package com.vg.run

import kotlin.concurrent.Volatile
import kotlin.time.TimeSource
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** The log tag of every line this file writes. */
private const val LOG_TAG = "MessageManager"

// ---------------------------------------------------------------------------
// MessageManager — relay client for sending and receiving encrypted messages.
//
// Talks to the capability-based relay (docs/RELAY_SPEC.md). Wire protocol:
//
//   POST   /inbox                              — mint a new inbox. Body is
//                                                ignored; requires X-PoW-*
//                                                headers. Returns
//                                                {inboxId, readCapability,
//                                                 writeCapability, expiresAt}.
//   POST   /inbox/{id}                         — append a blob.
//                                                Requires X-Write-Capability.
//   GET    /inbox/{id}?lease=1                 — drain unexpired blobs.
//                                                Requires X-Read-Capability.
//                                                Non-destructive — the inbox
//                                                survives across drains. LEASES
//                                                the blobs (+ ids + token);
//                                                nothing is deleted until
//   POST   /ack                                — retrieve-ack: delete the
//                                                processed ids, release the
//                                                rest (read caps in the body).
//                                                The bare GET (no query) still
//                                                deletes at fetch — never used.
//   GET    /inbox/{id}/peek                    — pending count, non-destructive.
//                                                Requires X-Read-Capability.
//   DELETE /inbox/{id}                         — explicit delete.
//                                                Requires X-Read-Capability.
//   PUT    /inbox/{id}/read-capability         — rotate read cap.
//                                                Auth: X-Read-Capability,
//                                                new value: X-New-Read-Capability.
//   PUT    /inbox/{id}/write-capability        — rotate write cap.
//                                                Auth: X-Read-Capability,
//                                                new value: X-New-Write-Capability.
//
// Rejection policy (relay): 404 with {"error":"request rejected"} for any
// auth failure — nonexistent inbox, wrong cap, or locked-out cap all look
// identical. 429 {"error":"rate limited"} when the relay is overloaded.
// Clients can NOT distinguish "I'm locked out" from "inbox is gone" from
// the wire — back off uniformly on any 404.
//
// PoW: only POST /inbox requires proof of work, via a two-request handshake
// (400 challenge → X-PoW-Token + X-PoW-Counter on retry). See PowSolver.kt
// and mintInbox below.
//
// The app-layer encryption lives on top of this transport: the Double Ratchet
// carries text; the static AES-256-GCM envelope (shared-secret-derived key +
// AEAD context, power-of-two padding, monotonic anti-replay counter + epoch) is
// the legacy / pre-ratchet fallback.
// ---------------------------------------------------------------------------

/**
 * Envelope for a received message with an optional sender timestamp.
 * Old messages sent before the timestamp feature will have timestamp = 0.
 *
 * Group fields (all null for a 1:1 message) ride INSIDE the AES-GCM envelope,
 * so the relay learns no group CONTENT — though the fan-out pattern itself is
 * still group-shaped to the relay (see GroupManager):
 *   [groupId]        — which group the message belongs to.
 *   [membershipHash] — the sender's view of (epoch + member set); a mismatch
 *                      with our own view means the sender has a different
 *                      member list (message-splitting / partition detection).
 *   [controlKind]/[controlBody] — group control messages (invite/join/
 *                      roster/leave); applied by GroupManager, never shown.
 */
data class ReceivedMessage(
    val text: String,
    val timestamp: Long,      // millis since epoch, 0 if absent
    val counter: Long = 0,    // sender's per-contact monotonic counter (anti-replay)
    // True when this message's counter skipped ahead of the last accepted
    // one, i.e. one or more earlier messages were dropped (by a hostile
    // relay or lost in transit). Surfaced so the UI can warn the user.
    val sequenceGap: Boolean = false,
    val groupId: String? = null,
    val membershipHash: String? = null,
    val controlKind: String? = null,
    val controlBody: String? = null,
    // The STABLE de-dupe id the conversation UIs key on. It is
    // channel-NAMESPACED at the source (see [receiveDedupeId]) so a ratchet receive id
    // (a local 1,2,3… counter) can't collide with a legacy sender-counter id (also
    // 1,2,3…) on the just-paired path — that collision silently dropped messages when
    // both UIs keyed on "rx-{counter}". Empty only for test / system-notice messages the
    // UI keys by other means.
    val dedupeId: String = "",
)

/**
 * Retrieve-ack (2026-11-03): what a conversation SCREEN's poll decrypted — NOT yet
 * persisted, NOT yet acked to the relay. See docs/vault-relay-internals.md
 * "Retrieve-ack".
 *
 * Contract for the screens:
 *  1. Poll on a background dispatcher (blocking I/O): `MessageManager.pollMessagesPending`,
 *     `GroupManager.pollDirectPending`, `GroupManager.pollGroupPending`.
 *  2. Append [messages] to the visible list.
 *  3. THEN call [commit] — off the main thread (it writes the vault: the ratchet
 *     state and the anti-replay baseline). It returns once the state is persisted;
 *     the relay ack it triggers is fire-and-forget and never awaited.
 *  4. Commit BEFORE the next poll of the same conversation starts. A newer poll that
 *     finds an older one still uncommitted treats it as abandoned (rolls it back and
 *     has the relay hand its blobs back), so a late commit costs a duplicate on
 *     screen — never a lost message.
 *  5. If the messages will NOT be shown (the screen went away while the poll was in
 *     flight), call [abandon] — or simply drop the object: an uncommitted drain is
 *     rolled back after 15 s and the relay re-delivers its blobs after its lease.
 * A teardown (lock, background, process death) between poll and commit therefore
 * persists nothing and acks nothing, and the messages come back on the next session.
 *
 * Both [commit] and [abandon] are idempotent, thread-safe, never throw, and the first
 * of the two to run wins. An empty drain has nothing to commit; calling either is
 * still fine.
 */
class PendingDrain<T : Any> internal constructor(
    val messages: List<T>,
    private val parts: List<MessageManager.PendingPart>,
    private val owner: MessageManager?,
    private val onCommitted: (() -> Unit)? = null,
) {
    private val lock = SyncLock()
    private var settled = false

    /** Nothing in this drain needs a commit (no message, no part). */
    val isEmpty: Boolean get() = messages.isEmpty() && parts.isEmpty()

    /** Persist what this drain decrypted, then (fire-and-forget) ack it. */
    fun commit() {
        if (!settle()) return
        try {
            owner?.commitPendingParts(parts)
            onCommitted?.invoke()
        } catch (e: Exception) {
            platformLogWarn(LOG_TAG, "retrieve-ack: commit threw: ${e::class.simpleName}")
        }
    }

    /** The messages will never be shown: persist nothing and hand the blobs back. */
    fun abandon() {
        if (!settle()) return
        try { owner?.abandonPendingParts(parts) } catch (e: Exception) {
            platformLogWarn(LOG_TAG, "retrieve-ack: abandon threw: ${e::class.simpleName}")
        }
    }

    private fun settle(): Boolean = lock.withLock { if (settled) false else { settled = true; true } }

    internal companion object {
        fun <T : Any> empty(): PendingDrain<T> = PendingDrain(emptyList(), emptyList(), null)
    }
}

/** Retrieve-ack: process-wide registry behind MessageManager.pendingLegacy. */
private object PendingLegacyRegistry {
    val lock = SyncLock()
    val map = mutableMapOf<String, MessageManager.PendingPart>()
}

/**
 * The channel-namespaced stable id both conversation UIs de-dupe on. Ratchet and
 * legacy receive counters are INDEPENDENT sequences that both start at 1, so they must
 * live in different id namespaces or the legacy↔ratchet transition drops messages.
 */
internal fun receiveDedupeId(ratchet: Boolean, counter: Long): String =
    if (ratchet) "dr-$counter" else "rx-$counter"

/**
 * Source of the `n` in a ratchet receive's UI id ("dr-{n}", [receiveDedupeId]).
 *
 * PROCESS-wide and RAM-only, deliberately:
 *  - not persisted — the per-contact `dr-rxc` count it replaces was an exact
 *    lifetime message volume readable from an opened vault, and no message is
 *    ever kept on disk for an id to collide with across processes;
 *  - not per [MessageManager] instance — a Tor restart rebuilds the manager while
 *    the conversation screens keep their lists, and a counter restarting at 1 would
 *    hand a NEW message an id already on screen, which the UIs drop as a duplicate.
 * Strictly increasing within the process, so no two ratchet receives ever share an id
 * (also across contacts — the group UIs prefix the sender anyway).
 */
internal object RatchetReceiveIds {
    private val lock = SyncLock()
    private var last = 0L
    fun next(): Long = lock.withLock { last += 1; last }
}

/**
 * Result of [MessageManager.mintInbox]. The reader-side `readCapability` MUST
 * stay private to this device; the `(inboxId, writeCapability)` pair is what
 * the peer needs and is exchanged via the IRL pairing QR.
 *
 * `expiresAt` is informational — the inbox lives indefinitely under sliding
 * TTL as long as at least one authenticated op happens before each idle
 * window elapses (default: 1 year of inactivity → reap).
 */
data class MintedInbox(
    val inboxId: String,
    val readCapability: String,
    val writeCapability: String,
    val expiresAt: Long,
) {
    override fun toString() = "MintedInbox(inboxId=[redacted])"
}

/**
 * The inboxes a pairing needs, minted together by [MessageManager.mintInboxPair]:
 * [main] carries 1:1 text messages, [ctl] carries v7 group-control traffic and
 * [grp] carries GROUP text.
 *
 * **[grp] is nullable, and the name [MintedInboxPair] is deliberately unchanged.**
 * Renaming would change the Objective-C selector both Swift call sites use, and a
 * non-null third field would make [decodeStoredAccept] reject every referral accept
 * record written before this shipped — destroying a LIVE handshake mid-flight. So:
 * `null` means "this pair predates the group inbox" (a rehydrated legacy record),
 * which routes group text down the [MessageManager.Chan.MAIN] fallback exactly as
 * before. [MessageManager.mintInboxPair] always returns a non-null [grp].
 */
data class MintedInboxPair(
    val main: MintedInbox,
    val ctl: MintedInbox,
    val grp: MintedInbox? = null,
)

/**
 * Outcome of ONE read-capability rotation / reconcile, for a single
 * (contact, direction) inbound inbox.
 *
 * The whole point of the four "did it land?" states is that a rotation crosses a
 * network we do not trust to answer: the PUT's response is a HINT, never the
 * decision. The decision is made by probing `/peek` with each candidate, and the
 * invariant it protects is **the union {record.cap, pending marker} always
 * contains whatever capability the relay currently holds** — so no outcome here
 * can ever leave the user without a usable capability for their own inbox.
 *
 *  - [ROTATED]       — the new cap answered 200; it is now the record's cap and
 *                      the pending marker is gone.
 *  - [NOT_APPLIED]   — the new cap 404'd AND the cap we still hold answered 200,
 *                      i.e. the rotation provably never landed. Marker dropped,
 *                      record untouched.
 *  - [UNKNOWN]       — could not prove either way (429 / transport failure /
 *                      both 404). BOTH caps are kept and nothing is changed; the
 *                      next poll cycle reconciles again.
 *  - [BUSY]          — an unresolved rotation is already pending for this inbox.
 *                      Rotations are never CHAINED (two live candidates would
 *                      break the union invariant).
 *  - [FAILED]        — refused locally, before any network I/O (no inbox row, a
 *                      malformed stored cap/id, or the durable marker could not
 *                      be written). Nothing was sent.
 *  - [NOTHING_TO_DO] — reconcile found no pending marker (the steady state).
 */
enum class CapRotationOutcome {
    ROTATED,
    NOT_APPLIED,
    UNKNOWN,
    BUSY,
    FAILED,
    NOTHING_TO_DO,
}

class MessageManager(
    private val databaseManager: VaultDatabase,
    // Captured at construction, RESOLVED at use ([relayBaseUrl] below): when it is
    // one of the relay's configured addresses (RelayAddressRace, 2026-10-23), every
    // request goes to the session's current winner instead. A URL that is not one
    // of them (every unit test) is used verbatim.
    relayBaseUrl: String = RelayConfig.BASE_URL,
    // NOT the field the class talks through — [httpClient] below wraps this one
    // so the update-nudge observer sees every relay response without a single
    // per-call-site edit. Nothing in this class may use `transport` directly.
    transport: RelayHttp,
    // This build's own version (Android `BuildConfig.VERSION_NAME`, iOS
    // `CFBundleShortVersionString`), INJECTED rather than generated: a generated
    // constant would change on every push and force a full commonMain + K/N
    // relink. Defaulted LAST and to "" so every existing construction site and
    // test double keeps compiling; "" never parses, so a caller that does not
    // supply it can never nudge. RunViewModel / IosAppController pass the real
    // value.
    private val localAppVersion: String = "",
    // The RAM-only ledger of transport-failed 1:1 sends this instance parks into
    // and re-drives out of. Defaults to the process-wide [TransportFailedSends.shared]
    // BECAUSE a MessageManager is rebuilt on every transport change and the sends
    // worth re-driving failed on the instance that just died; tests inject their
    // own. Defaulted LAST so every existing construction site keeps compiling.
    private val transportFailedSends: TransportFailedSends = TransportFailedSends.shared,
) {
    private val configuredRelayBaseUrl: String = relayBaseUrl

    /** The relay base URL for THIS request: the descriptor race's current winner
     *  when [configuredRelayBaseUrl] is one of the relay's addresses, else that URL. */
    private val relayBaseUrl: String
        get() = RelayEndpoints.resolve(configuredRelayBaseUrl)

    /** Convenience ctor for production code that still holds a PlatformHttpClient. */
    constructor(
        databaseManager: VaultDatabase,
        relayBaseUrl: String = RelayConfig.BASE_URL,
        httpClient: PlatformHttpClient,
        localAppVersion: String = "",
    ) : this(databaseManager, relayBaseUrl, httpClient.asRelayHttp(), localAppVersion)

    /**
     * The relay transport every call in this class goes through: the injected
     * one, wrapped in a PURE OBSERVER for the update-nudge version header.
     *
     * The wrapper forwards each call verbatim — same URL, body, headers and
     * timeout — and returns the delegate's [HttpResult] unchanged; a transport
     * exception propagates identically because the observer only runs on a
     * returned value. It is `private` so it never enters the ObjC/Swift export.
     *
     * The hook has to live HERE rather than on one endpoint: the health probe
     * `GET /`, the warm-circuit probe and the unread prime all race on the same
     * Tor transport with nothing ordering them, so "the first relay response of
     * the session" is endpoint-agnostic by construction.
     */
    private val httpClient: RelayHttp = object : RelayHttp {
        override fun post(url: String, body: ByteArray, contentType: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult =
            observeRelayResponse(transport.post(url, body, contentType, headers, timeoutSeconds))
        // The six-argument form MUST be forwarded explicitly. [RelayHttp]'s
        // default implementation delegates to the five-argument one, so without
        // this override the caller's `suppressLog` would be silently dropped by
        // this wrapper — and DebugLogUploader's own POST (the only caller) would
        // be logged again, re-arming the 1 Hz self-feeding loop the flag exists
        // to kill. Same pure-observer contract as the rest.
        override fun post(url: String, body: ByteArray, contentType: String, headers: Map<String, String>, timeoutSeconds: Int, suppressLog: Boolean): HttpResult =
            observeRelayResponse(transport.post(url, body, contentType, headers, timeoutSeconds, suppressLog))
        override fun put(url: String, body: ByteArray, contentType: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult =
            observeRelayResponse(transport.put(url, body, contentType, headers, timeoutSeconds))
        override fun get(url: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult =
            observeRelayResponse(transport.get(url, headers, timeoutSeconds))
        override fun delete(url: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult =
            observeRelayResponse(transport.delete(url, headers, timeoutSeconds))
        // NEWNYM ABORT forms, forwarded explicitly for the same reason as the
        // suppressLog post above: RelayHttp's defaults would drop the flag, and
        // the probe would silently lose its hard abort (only the epoch check
        // would remain).
        override fun get(url: String, headers: Map<String, String>, timeoutSeconds: Int, cancelOnNewCircuit: Boolean): HttpResult =
            observeRelayResponse(transport.get(url, headers, timeoutSeconds, cancelOnNewCircuit))
        // First-byte form — forwarded for the same reason (the default would
        // silently drop the budget).
        override fun get(url: String, headers: Map<String, String>, timeoutSeconds: Int, cancelOnNewCircuit: Boolean, firstByteTimeoutSeconds: Int): HttpResult =
            observeRelayResponse(transport.get(url, headers, timeoutSeconds, cancelOnNewCircuit, firstByteTimeoutSeconds))
        override fun post(url: String, body: ByteArray, contentType: String, headers: Map<String, String>, timeoutSeconds: Int, suppressLog: Boolean, cancelOnNewCircuit: Boolean): HttpResult =
            observeRelayResponse(transport.post(url, body, contentType, headers, timeoutSeconds, suppressLog, cancelOnNewCircuit))
        override fun cancelNewCircuitSensitive(): Int = transport.cancelNewCircuitSensitive()
        // SOCKS isolation (RendezvousHedge) — forwarded for the same reason: the
        // defaults would report "cannot isolate" and drop the hedge's credential.
        override val supportsSocksIsolation: Boolean get() = transport.supportsSocksIsolation
        override fun get(url: String, headers: Map<String, String>, timeoutSeconds: Int, cancelOnNewCircuit: Boolean, firstByteTimeoutSeconds: Int, socksIsolation: String): HttpResult =
            observeRelayResponse(transport.get(url, headers, timeoutSeconds, cancelOnNewCircuit, firstByteTimeoutSeconds, socksIsolation))
    }

    /**
     * The relay transport THIS instance is currently using (Tor-proxied in
     * production, direct HTTP only where the app already uses it in debug/
     * emulator) — i.e. the exact same [httpClient] every call in this class
     * goes through, update-nudge observer included. Exposed so
     * [BugReportSender] (commonMain, standalone — not message-protocol code)
     * can send an anonymous bug report over the SAME live transport the
     * message channel uses, without a second platform-side torProxy/direct
     * construction to keep in sync. Report-bug traffic is a normal relay
     * response for the update-nudge "first response of the session" latch —
     * harmless.
     */
    fun relayTransport(): RelayHttp = httpClient

    // Double Ratchet for the TEXT channel (forward secrecy + post-compromise).
    // Vault-backed per (contact, channel). SEND engages only for contacts whose
    // `dr-on/{id}` marker is set — pairings made under this build (marked
    // ratchet-capable via [markRatchetCapable]) whose first exchange has
    // completed; every existing/legacy contact keeps the static AES-GCM envelope
    // below, byte-for-byte unchanged. RECEIVE is self-describing (per-blob wire
    // magic), so it reads either format regardless of this flag. The control
    // channel is intentionally NOT ratcheted (group control, screenshot notices,
    // referral handshakes stay on the static envelope): it carries the
    // bootstrap-critical in-band inbox announce, which must flow before any
    // ratchet can exist. The ONE exception (2026-09-08) is that same
    // inbox announce AFTER the ratchet is live: it is then sealed by the text
    // ratchet (posted to the control inbox), and a legacy announce is dropped once
    // dr-rxlock is armed — so a one-time vault image cannot rewrite the peer's
    // routing forever. Sealed control (2026-10-21) extends the same rule to the integrity-
    // critical control kinds (referral handshake, group membership control), gated
    // both ways on the peer's advert — see [isRatchetSealedControlKind]. The chatty
    // control kinds (activity / screenshot notices) stay on the static envelope.
    private val ratchetManager = RatchetManager(
        VaultRatchetStore(databaseManager),
        onCorruptReinit = { contactId, channel ->
            // A corrupt local text-ratchet state is re-inited fresh
            // (rooted at hkdf(sharedSecret), DESYNCED from the peer's advanced root).
            // If we stayed engaged we'd emit fresh-root blobs the peer can't decrypt.
            // Clear the LOCAL ratchet engagement so we don't immediately re-arm:
            //   dr-rxlock  — stop dropping our own inbound legacy
            //   dr-on      — send legacy this exchange, not the desynced ratchet
            //   dr-rxseen  — so enableRatchetIfReady waits for a fresh inbound before
            //                re-enabling dr-on (prevents a re-arm loop)
            // Do NOT delete dr-intent. It is only ever set at pairing
            // (markRatchetCapable), so deleting it permanently reverted the contact to
            // the legacy static-key envelope (no forward secrecy) until a manual
            // re-pair. Keeping dr-intent lets the pair RE-BOOTSTRAP back into the
            // ratchet on the next exchange (dr-on re-enables once dr-rxseen is set by a
            // fresh inbound), instead of dropping to permanent legacy.
            // Known limitation: this heals the LOCAL side. If the PEER's dr-rxlock is
            // armed it still drops our legacy until the peer independently recovers.
            // Spontaneous local corruption only;
            // not attacker-triggerable (vault is SQLCipher-authenticated).
            // Also drop the two downgrade counters and the refusal latch.
            // This re-init is a LOCAL disk anomaly (the vault is authenticated, so it is
            // not attacker-triggerable) and it puts the pairing back at the bootstrap,
            // where dr-on is off and every send is legacy again — exactly the traffic a
            // stale latch would refuse, permanently, with no way back. The security
            // property is preserved and merely re-earned: if the roles really did
            // collide, the fresh ratchet resolves the SAME role again — from
            // [ratchetSelfIsBobOverride] (the persisted role-order bit + the secret parity,
            // role rule v2) or, without v2 evidence, the inbox-id order; nothing here
            // touches either input — and the counters climb back to the threshold
            // within 8 sends.
            // The keys, in order, with the WHY of each: [ratchetReinitResetKeys].
            if (channel == RATCHET_TEXT_CHANNEL) ratchetReinitResetKeys(contactId).forEach { deleteMetaBestEffort(it) }
        },
    )
    private fun ratchetSendOn(contactId: String) = databaseManager.getMeta(drOnKey(contactId)) == "1"

    /** A `_meta` write whose failure is swallowed — the exact semantics every call site
     *  had inline (`try { … } catch (_: Exception) {}`). A site that must REACT to a
     *  failed write (a counter persist, the grace record before a lock arm) keeps its
     *  own try. */
    private fun putMetaBestEffort(key: String, value: String) {
        try { databaseManager.putMeta(key, value) } catch (_: Exception) {}
    }

    /** @see putMetaBestEffort */
    private fun deleteMetaBestEffort(key: String) {
        try { databaseManager.deleteMeta(key) } catch (_: Exception) {}
    }

    // A delete issued only when the key is present (one read, then the delete), both
    // inside ONE swallowed try: a throwing read deletes nothing. Avoids a delete on
    // the steady-state path where the key is long gone.
    private fun deleteMetaIfPresentBestEffort(key: String) {
        try {
            if (databaseManager.getMeta(key) != null) databaseManager.deleteMeta(key)
        } catch (_: Exception) {}
    }

    // Per-contact lock serialising the anti-replay counter
    // read-modify-write. All six counters (inbound/outbound × text/ctl/grp) plus
    // inboundEpoch live in ONE ContactRecord row that both send and poll persist
    // via a whole-row upsert (insertContact). send() and the text/ctl poll loops
    // run on separate Dispatchers.IO coroutines, so without serialisation a
    // concurrent send+poll (or text-poll+ctl-poll) lost-updates last-writer-wins:
    //   (A) a poll writing a stale snapshot rolls another channel's inbound
    //       baseline BACKWARD → reopens the replay window (a hostile relay can
    //       re-serve drained blobs past the strict-monotonic check), and
    //   (B) two sends reusing the same outbound counter → the receiver drops the
    //       second as a replay → silent message loss.
    // The fix: hold this lock across the getContact→copy→insertContact sequence,
    // and RE-READ the record fresh INSIDE the lock so a counter is never written
    // back from a snapshot taken before a (up-to-60s) Tor round-trip. The lock is
    // held only for the two fast vault ops, never across network I/O. Per-contact
    // (not global) so unrelated contacts never serialise. Non-reentrant (iOS
    // NSLock): the critical sections do only DB reads/writes, no nested locking.
    //
    // The registry now lives in [ContactRowLocks] (commonMain) instead of a
    // private map here, because send+poll are NOT the only whole-row upserters —
    // the contact-edit paths (alias roll / mnemonic save, ContactEdits) do the same
    // read-modify-write from a user tap and cannot reach a private field of a
    // MessageManager instance. Same per-contact granularity, same contract; it is
    // simply reachable by every writer now. Bonus: two MessageManager instances over
    // one vault (the Tor-reconnect recreate) previously did not serialise with each
    // other either, and now do.
    private fun counterLock(contactId: String): SyncLock = ContactRowLocks.forContact(contactId)

    // counterLock makes outbound counters UNIQUE but not
    // ORDERED. Two concurrent sends to the same contact can take counters N and N+1,
    // release counterLock, then POST in the OPPOSITE order (the first stalling in
    // postWithTransientRetry on a Tor drop — the very case the retry exists for). The
    // receiver's strict-monotonic rule then drops the lower-counter blob as a replay =
    // permanent message loss. sendOrderLock serializes the WHOLE send (counter assign
    // through POST) per contact so arrival order == counter order. It is DISTINCT from
    // counterLock — the receiver holds counterLock but never sendOrderLock, so holding
    // this across Tor I/O blocks only other sends to the SAME contact, never the
    // receive path or other contacts. Lock order is always sendOrderLock → counterLock;
    // no path acquires them in the reverse order, so there is no deadlock.
    private val sendOrderLocksGuard = SyncLock()
    private val sendOrderLocks = mutableMapOf<String, SyncLock>()
    private fun sendOrderLock(contactId: String): SyncLock =
        sendOrderLocksGuard.withLock { sendOrderLocks.getOrPut(contactId) { SyncLock() } }

    /**
     * Existence probe for a contact row. [VaultDatabase.getContact] decodes a FRESH
     * copy of the pairing secret on every call on both actuals (Android: the cursor
     * blob; iOS: a base64 decode — the androidApp screens wipe theirs on the same
     * contract), so a probe that only needs "is it there?" wipes that copy at once
     * instead of leaving one more copy of the secret in the heap per peek / drain.
     */
    private fun contactExists(contactId: String): Boolean {
        val c = databaseManager.getContact(contactId) ?: return false
        c.sharedSecret.secureWipe()
        return true
    }

    /**
     * Sealed-control send gate, TRI-STATE: true = the peer advertised [CTL_RATCHET_CAP_FIELD];
     * false = the marker is genuinely ABSENT (or not "1"); null = the read THREW.
     * The null must never be collapsed into false for a sealed kind: a legacy send
     * above a watermark the peer already holds is DROPPED by the peer, while a failed
     * send is redriven (roster obligations, the `ref_*` accept/relay queues).
     */
    private fun peerCtlRatchetCapability(contactId: String): Boolean? = try {
        databaseManager.getMeta(drCtlCapKey(contactId)) == "1"
    } catch (_: Exception) { null }

    /** [peerCtlRatchetCapability] where an unreadable marker may safely read as "no". */
    private fun peerCtlRatchetCapable(contactId: String): Boolean = peerCtlRatchetCapability(contactId) == true

    /** Sealed-control receive evidence: the peer's lowest ratchet-proven control commitment,
     *  or null (unknown / unreadable / malformed ⇒ no lock — the fail-open side). */
    private fun peerCtlWatermark(contactId: String): Long? = try {
        parseCtlWatermark(databaseManager.getMeta(drCtlWatermarkKey(contactId)))
    } catch (_: Exception) { null }

    /** TEST SEAM ONLY: make this instance's envelopes look like a build that predates
     *  sealed control (no `cr`, no `crw`) — the vault-moved-onto-an-older-install case. Never set
     *  in production code. */
    internal var simulatePreSealedControlBuildForTest: Boolean = false

    // SEALED-CONTROL CATCH-UP WAKE (RAM-only, session-scoped like this instance).
    //
    // Sealed control kinds ride the ONE text ratchet chain but land on the CONTROL
    // inbox, which the background sweep drains every 60–90 s, while an open
    // conversation drains the text inboxes every 1–2 s. When a text drain decrypts a
    // LATER ratchet blob first, the sealed control blob's message key becomes a
    // SKIPPED key — and `DoubleRatchet.dhRatchet` flushes skipped keys two DH steps
    // back; two reply round trips inside one idle interval (a lively chat) would
    // make that roster/invite/join/referral blob undecryptable for good.
    //
    // So a TEXT drain whose decrypt left MORE skipped keys than it found, for a peer
    // that seals control, marks the contact; a later text drain that empties the
    // cache unmarks it (the ordinary GRP-DRAIN-1 interleave is net zero within one
    // conversation poll, so it never wakes anything). A pending mark ends the
    // platform control loop's IDLE wait at the next 1 s slice
    // ([controlPollIdleWaitShouldEnd]) — ONCE per new mark — so the ordinary
    // background sweep drains the control inbox before another DH step can happen.
    // Nothing runs in the UI-awaited conversation poll and nothing holds the sweep
    // admission. A contact with DEFERRED sealed control ([drCtlDeferredKey]) is marked
    // after every text drain too, which is what retries the deferral promptly.
    private val sealedControlCatchUpLock = SyncLock()
    private val sealedControlCatchUp = LinkedHashSet<String>()
    private var sealedControlWakeArmed = false
    // Contacts whose deferred sealed control the next sweep must drain despite an
    // empty control-inbox peek (set by a text drain), and the short-lived cache of
    // "texts waiting" peek answers. Both RAM-only, guarded by the lock above.
    private val deferredRetryRequested = LinkedHashSet<String>()
    private val undrainedPeekCache = LinkedHashMap<String, Pair<Long, Int>>()

    private fun noteSealedControlCatchUp(contactId: String) {
        sealedControlCatchUpLock.withLock {
            if (contactId !in sealedControlCatchUp) {
                if (sealedControlCatchUp.size >= MAX_SEALED_CONTROL_CATCH_UPS) {
                    sealedControlCatchUp.firstOrNull()?.let { sealedControlCatchUp.remove(it) }
                }
                sealedControlCatchUp.add(contactId)
                sealedControlWakeArmed = true
            }
        }
    }

    private fun clearSealedControlCatchUp(contactId: String) {
        sealedControlCatchUpLock.withLock { sealedControlCatchUp.remove(contactId) }
    }

    /** Test/diagnostic view: is any contact owed a catch-up? */
    internal fun hasPendingSealedControlCatchUp(): Boolean =
        sealedControlCatchUpLock.withLock { sealedControlCatchUp.isNotEmpty() }

    /** Consumes the one-shot wake (true at most once per newly marked batch). The
     *  marks are dropped with it: the sweep it triggers drains every control inbox. */
    private fun consumeSealedControlWake(): Boolean = sealedControlCatchUpLock.withLock {
        val fire = sealedControlWakeArmed && sealedControlCatchUp.isNotEmpty()
        sealedControlWakeArmed = false
        if (fire) sealedControlCatchUp.clear()
        fire
    }

    // -----------------------------------------------------------------------
    // 1:1 screenshot notices. Applied receive-side like the inbox announce
    // (never surfaced as a message) and parked here until the conversation layer
    // collects them — see [drainDirectScreenshotNotices] and
    // GroupManager.collectDirectScreenshotNotices.
    //
    // THIS BUFFER is still RAM-only and still dies with the session: no vault
    // write happens HERE, so there is nothing for [ratchetMetaKeysForContact] to
    // purge on the transport side. The DURABLE copy is written one layer up by
    // GroupManager, through ScreenshotNoticeStore's `ssn:` `_meta` namespace,
    // which the deleteContact/deleteGroup purges classify with
    // [isScreenshotNoticeResidueForContact] / [isScreenshotNoticeResidueForGroup]
    // (predicates, not an exact-key list — the keys carry a receivedAt suffix).
    //
    // Records the contactId, our LOCAL receive time and the sender's CLAIMED,
    // minute-rounded capture time from the envelope's "t" — never the peer's
    // alias and never any text. The claimed time is carried through UNVALIDATED
    // and is display-only; it is clamped in one place
    // (ScreenshotNoticeStore.clampTakenAt) and never touches ordering or expiry.
    // -----------------------------------------------------------------------
    private val screenshotNoticeLock = SyncLock()
    private val pendingScreenshotNotices = mutableListOf<DirectScreenshotNotice>()

    /**
     * Records one authenticated, replay-checked 1:1 screenshot notice. Bounded.
     * [claimedTakenAtMs] is the envelope's `"t"` verbatim (0 when the peer sent
     * none) — attacker-controlled, so it is passed on for DISPLAY only.
     */
    private fun noteScreenshotNotice(contactId: String, claimedTakenAtMs: Long) = screenshotNoticeLock.withLock {
        if (pendingScreenshotNotices.size >= MAX_PENDING_SCREENSHOT_NOTICES) {
            platformLogWarn(LOG_TAG, "screenshot-notice buffer full — dropping")
            return@withLock
        }
        pendingScreenshotNotices.add(
            DirectScreenshotNotice(contactId, currentTimeMillis(), claimedTakenAtMs)
        )
    }

    /**
     * Takes (and clears) the 1:1 screenshot notices received since the last call.
     * Destructive by design — these are ephemeral and are handed to the
     * conversation layer, which owns per-conversation buffering from there.
     */
    internal fun drainDirectScreenshotNotices(): List<DirectScreenshotNotice> =
        screenshotNoticeLock.withLock {
            if (pendingScreenshotNotices.isEmpty()) emptyList()
            else pendingScreenshotNotices.toList().also { pendingScreenshotNotices.clear() }
        }

    /**
     * Teardown hook forwarding to the ratchet manager
     * so lock/wipe can fence any in-flight ratchet op (it has persisted + released
     * its transient key material by the time this returns). Parity with
     * GroupManager/ReferralManager.scrubInMemory(); called from RunViewModel and
     * IosAppController lock/wipe paths before the manager reference is dropped.
     *
     * Also empties the ephemeral screenshot-notice list — an undrained notice is
     * social-graph state (a contactId + a time), and the platform teardown sites
     * only null the reference, which does not zero a still-resident collection.
     */
    fun scrubInMemory() {
        // Retrieve-ack FIRST: no ack may be launched or sent, and no pending commit
        // may write the vault, once teardown has begun (lock / wipe). Taking
        // [pendingLock] fences a commit already inside its legacy persist. Nothing
        // un-acked is lost: the relay re-delivers after its lease and the next
        // session's anti-replay drops what was already persisted. The uncommitted
        // ratchet advances are zeroed by [RatchetManager.scrubInMemory] below.
        acksClosed = true
        try { ackJob.cancel() } catch (_: Exception) {}
        pendingLock.withLock {
            for (part in pendingLegacy.values) { part.legacyDiscarded = true; part.settled = true }
            pendingLegacy.clear()
        }
        ackUnconfirmedLock.withLock { ackUnconfirmed.clear() }
        screenshotNoticeLock.withLock { pendingScreenshotNotices.clear() }
        // The catch-up marks are contact ids (social-graph state) — same rule.
        sealedControlCatchUpLock.withLock {
            sealedControlCatchUp.clear()
            deferredRetryRequested.clear()
            undrainedPeekCache.clear()
        }
        ratchetManager.scrubInMemory()
        // Parked plaintexts must not outlive the session either (they are the
        // only message content this layer ever holds). The ledger is shared across
        // instances, so this clears it for the process. NOT the only clear, and
        // not the load-bearing one: entries are recorded exactly when the platform
        // holds NO manager (the no-transport parking branch), so a lock / wipe
        // taken in that state never reaches this method — RunViewModel.lockSession
        // / performEmergencyWipe and IosAppController.lock() / emergencyWipe() call
        // `TransportFailedSends.shared.clear()` unconditionally for that case.
        transportFailedSends.clear()
    }

    // -----------------------------------------------------------------------
    // Transport-failed sends: known-down fail-fast + transport-back re-drive
    // (resilience:tor-death, 2026-10-15). A send whose POST attempts all died on
    // the transport (Tor process killed mid-send) used to burn the whole transient
    // budget against a dead SOCKS port and then sit in the failed state until the
    // user long-pressed Retry — the self-heal brought Tor back 40 s later and
    // nothing re-drove the message.
    // -----------------------------------------------------------------------

    /**
     * Set by the owner the moment it learns THIS instance's transport is gone
     * (Android: Tor `Failed`/`Idle` → `messageManager = null`; the same on the
     * self-heal restart). From then on [postWithTransientRetry] stops after the
     * attempt in flight instead of re-POSTing the same bytes at a dead port: the
     * send fails fast as [SendOutcome.TRANSPORT_FAILED] and the re-drive on the NEXT
     * transport owns recovery. Positive evidence only — never inferred from a probe
     * miss, so a merely slow circuit keeps today's four attempts.
     */
    @Volatile
    private var transportLost = false

    /** @see transportLost */
    fun noteTransportLost() {
        transportLost = true
    }

    /** @see transportLost */
    fun isTransportLost(): Boolean = transportLost

    /** The between-attempt backoff of [postWithTransientRetry]; injectable for tests. */
    internal var sendRetrySleep: (Long) -> Unit = { sleepMillis(it) }

    /**
     * [sendMessage] with the failure CLASS reported, and — when [redriveToken] is
     * given — a transport-class failure PARKED for [redriveTransportFailures].
     *
     * Classification is exactly [postWithTransientRetry]'s null: every POST attempt
     * threw or returned no HTTP status, or the transport was already known down.
     * A relay 4xx/5xx (including the 404 the group-inbox fallback reads), a local
     * refusal (no contact / no outbound row / bad cap / too large / ratchet refused /
     * move-frozen) and a crypto or counter failure are all [SendOutcome.FAILED] and
     * are never parked — re-sending cannot fix them.
     *
     * [redriveToken] is the caller's stable id for THIS message (the UI bubble id):
     * a second failure under the same token upserts the one ledger entry, and a
     * send that lands under it drops the entry. `null` = never parked, which is the
     * plain [sendMessage] contract, byte-for-byte unchanged. [onRedriven] fires once
     * if a later automatic re-drive lands this message (on the re-drive's thread).
     */
    fun sendMessageWithOutcome(
        contactId: String,
        plaintext: String,
        noPush: Boolean = false,
        redriveToken: String? = null,
        onRedriven: (() -> Unit)? = null,
    ): SendOutcome {
        // Captured BEFORE the send: a send that outlives its session (a lock while the
        // blocking POST is in flight) must not re-park its plaintext after the lock's
        // clear — [TransportFailedSends.record] refuses an epoch that has ended.
        val epoch = transportFailedSends.sessionEpoch
        val status = SendStatus()
        val sent = sendEnvelope(contactId, plaintext, extraFieldsJson = "", noPush = noPush, status = status)
        if (sent) {
            if (redriveToken != null) transportFailedSends.remove(redriveToken)
            return SendOutcome.SENT
        }
        if (!status.transportFailed) return SendOutcome.FAILED
        if (redriveToken != null) {
            transportFailedSends.record(redriveToken, contactId, plaintext, noPush, onRedriven, sessionEpoch = epoch)
        }
        return SendOutcome.TRANSPORT_FAILED
    }

    /**
     * Re-sends every parked 1:1 text whose transport-class failure is within
     * [TransportFailedSends.REDRIVE_WINDOW_MS], through EXACTLY the manual-Retry
     * path — a fresh [sendMessage]: a new sealed envelope with the next persisted
     * anti-replay counter, or the next ratchet message key, precisely what a
     * long-press Retry produces. Nothing is "held and released": the bytes that
     * failed are never re-POSTed, so the strict-monotonic rule and the ratchet
     * skipped-key bookkeeping see an ordinary send.
     *
     * Each entry is taken ONCE (at most one automatic re-drive per message per
     * transport-back event); a re-drive that fails again is NOT re-parked — the
     * bubble stays in the normal failed state and manual Retry still works. Safe to
     * call with nothing pending (returns 0, logs nothing) and from any instance.
     * Returns the number of messages re-driven (attempted), not delivered.
     *
     * Call once per transport-back transition, after the new transport's first
     * relay answer (so the re-drive rides a warm budget), off the main thread; the
     * blocking sends run on [Dispatchers.Default]. One count-only log line.
     */
    suspend fun redriveTransportFailures(): Int = withContext(Dispatchers.Default) {
        val due = transportFailedSends.takeEligible()
        if (due.isEmpty()) return@withContext 0
        platformLog(LOG_TAG, "transport back — re-driving ${due.size} transport-failed sends")
        var redriven = 0
        for (entry in due) {
            // Same code path as manual Retry (sendMessage ⇒ sendEnvelope); no token,
            // so a second transport failure here is NOT re-parked.
            val outcome = try {
                sendMessageWithOutcome(entry.contactId, entry.plaintext, entry.noPush, redriveToken = null)
            } catch (_: Exception) { SendOutcome.FAILED }
            redriven++
            if (outcome == SendOutcome.SENT) {
                try { entry.onRedriven?.invoke() } catch (_: Exception) { /* UI callback, best-effort */ }
            }
        }
        redriven
    }

    /**
     * ONE value for the FIVE things a pairing's channel decides together: the
     * outbound inbox row, the inbound inbox row, the AEAD-sealed `"ch"` tag, and
     * the outbound/inbound anti-replay counter spaces.
     *
     * It replaces the `control: Boolean` axis. That boolean already derived four
     * coupled values at four separate sites ([sendEnvelopeSerialized]'s row
     * selection, its counter, its `ch` tag, and [legacyDropReason]'s `expectedChannel`),
     * and a THIRD boolean parameter is precisely the shape that produces a
     * `ch`/counter mismatch — a blob sealed for one channel whose counter came from
     * another, which the peer drops forever as a replay. With one value type every
     * site reads the SAME thing and a fourth channel could not desynchronise them.
     *
     * [isText] is "this channel carries user TEXT" — true for [MAIN] and [GRP],
     * false for [CTL]. It gates the ratchet (both text channels ride the one
     * `dr/{contactId}/text` chain; control stays on the static envelope), the
     * receive lock, the `dr-rxseen` / `dr-on` promotion and the role-collision
     * downgrade detectors. Treating [GRP] as control there would silently pin a
     * group-text-only pairing on the no-forward-secrecy static envelope forever.
     */
    internal enum class Chan(val outDir: String, val inDir: String, val tag: String) {
        MAIN("outbound", "inbound", CHANNEL_TAG_MAIN),
        CTL(DIR_OUTBOUND_CTL, DIR_INBOUND_CTL, CHANNEL_TAG_CTL),
        GRP(DIR_OUTBOUND_GRP, DIR_INBOUND_GRP, CHANNEL_TAG_GRP);

        /** @see Chan */
        val isText: Boolean get() = this != CTL

        /** The inbox's name in log lines — a fixed word, never an identifier. */
        val logLabel: String get() = when (this) {
            MAIN -> "text"
            CTL  -> "control"
            GRP  -> "group"
        }

        /** This channel's OUTBOUND anti-replay counter on [c]. */
        fun outCounterOf(c: ContactRecord): Long = when (this) {
            MAIN -> c.outboundCounter
            CTL  -> c.outboundCtlCounter
            GRP  -> c.outboundGrpCounter
        }

        /** This channel's INBOUND anti-replay baseline on [c]. */
        fun inCounterOf(c: ContactRecord): Long = when (this) {
            MAIN -> c.inboundCounter
            CTL  -> c.inboundCtlCounter
            GRP  -> c.inboundGrpCounter
        }

        /** [c] with ONLY this channel's outbound counter replaced — every sibling
         *  counter keeps whatever the freshly-read row holds. */
        fun withOutCounter(c: ContactRecord, value: Long): ContactRecord = when (this) {
            MAIN -> c.copy(outboundCounter = value)
            CTL  -> c.copy(outboundCtlCounter = value)
            GRP  -> c.copy(outboundGrpCounter = value)
        }

        /** [c] with ONLY this channel's inbound baseline replaced — same rule. */
        fun withInCounter(c: ContactRecord, value: Long): ContactRecord = when (this) {
            MAIN -> c.copy(inboundCounter = value)
            CTL  -> c.copy(inboundCtlCounter = value)
            GRP  -> c.copy(inboundGrpCounter = value)
        }
    }

    // -----------------------------------------------------------------------
    // "Move to new device" FREEZE GATE (docs/device-move.md D2).
    //
    // WHY IT LIVES INSIDE THIS CLASS and not only in the session layer:
    // `createSessionManagers` gates the MessageManager PROVIDER it hands
    // GroupManager/ReferralManager, which covers every group/referral relay op —
    // but the 1:1 paths hold this object DIRECTLY (RunViewModel.sendMessage-
    // InBackground, AppState.sendMessage, the iOS unread sweep's peekInbox, the
    // push-wake peek), and [MoveSessionControl.quiesce] deliberately KEEPS this
    // object alive because the transfer inbox still needs Tor and the HTTP
    // client. So an open conversation screen could still send after `mig_frozen`
    // was written and advance the SENDING ratchet chain the new phone is about to
    // inherit — the exact fork hazard the freeze exists to prevent
    // (docs/device-move.md fact 5). Gating here is what no caller can bypass.
    //
    // WHAT IS DELIBERATELY NOT GATED: the move's own transfer-inbox primitives
    // ([mintInbox], [postMoveChunk], [peekMoveInbox], [drainMoveInbox],
    // [deleteInbox], [rotateOwnedInboxReadCap]) and the contact-free relay health
    // probe ([isRelayReachable]) — the export/import IS the reason the transport
    // is kept alive, and a transfer inbox belongs to no contact and touches no
    // ratchet. See each of those for the per-call reasoning.
    //
    // The DURABLE source of truth stays `mig_frozen` in the vault: a relaunch
    // builds a fresh MessageManager which reads it on first use, with no
    // MoveManager involvement at all.
    // -----------------------------------------------------------------------

    /**
     * Cached `mig_frozen`. `null` = never read (or the last read FAILED).
     *
     * Cached because the gate sits on the hot send/poll paths: one `_meta` read
     * per instance in the steady state, then a volatile field read. A read
     * FAILURE is deliberately NOT cached: [isMoveFrozen] fails toward FROZEN,
     * which is the right answer for one call (a paused cycle self-heals) and the
     * wrong one as a latch — a single transient vault error would otherwise wedge
     * the whole session into "frozen" with nothing left to re-read it. So a failed
     * read refuses THAT call and leaves the cache null for the next one to retry.
     */
    @Volatile
    private var moveFrozenCache: Boolean? = null

    private val frozenGateLogLock = SyncLock()
    private var lastFrozenGateLogMs: Long = 0L

    /**
     * Flips the cached freeze state. Called by [MoveManager] the moment
     * `mig_frozen` is written (BEFORE the session quiesce) and again once a
     * successful cancel has cleared it, so the live instance stops — and resumes —
     * immediately instead of waiting for its next vault read.
     *
     * `internal` on purpose: it never reaches the ObjC/Swift export, so no UI can
     * turn a freeze off, and the vault row remains the durable authority.
     */
    internal fun setMoveFrozen(frozen: Boolean) {
        moveFrozenCache = frozen
    }

    /**
     * Re-reads `mig_frozen` from the vault and refreshes the cache. Returns the
     * value the gate would now use (a failed read answers `true` — fail toward
     * frozen — without latching).
     */
    internal fun refreshMoveFrozen(): Boolean {
        val read = readMoveFrozen()
        moveFrozenCache = read
        return read ?: true
    }

    /** Tri-state read of `mig_frozen`: true / false, or null when the read THREW. */
    private fun readMoveFrozen(): Boolean? = try {
        databaseManager.getMeta(MoveMetaKeys.FROZEN) == "1"
    } catch (e: Throwable) {
        platformLogWarn(LOG_TAG, "move-freeze probe failed — refusing this call: ${e::class.simpleName}")
        null
    }

    /**
     * True when this device is the OLD phone of a move and [op] must not touch the
     * relay. Fails toward FROZEN on an unreadable vault, the same direction and for
     * the same reason as [isMoveFrozen]: a false "not frozen" resumes traffic on a
     * device whose identity may already be live on another phone (the ratchet
     * fork), while a false "frozen" costs one refused operation that self-heals.
     */
    private fun moveFrozen(op: String): Boolean {
        val frozen = moveFrozenCache ?: run {
            val read = readMoveFrozen()
            if (read != null) moveFrozenCache = read
            read ?: true
        }
        if (frozen) noteFrozenGate(op)
        return frozen
    }

    /** At most one log line per [FROZEN_GATE_LOG_INTERVAL_MS]; never names a contact. */
    private fun noteFrozenGate(op: String) {
        val now = currentTimeMillis()
        val shouldLog = frozenGateLogLock.withLock {
            if (now - lastFrozenGateLogMs < FROZEN_GATE_LOG_INTERVAL_MS) {
                false
            } else {
                lastFrozenGateLogMs = now
                true
            }
        }
        if (shouldLog) {
            platformLogWarn(
                LOG_TAG,
                "move freeze: refused $op — this device is the old phone of a move",
            )
        }
    }

    /**
     * Latched true the first time a relay request on THIS transport got a real
     * HTTP response — i.e. a `.onion` round-trip actually completed end to end
     * (descriptor fetch + rendezvous + relay answer), not merely "Tor says it
     * bootstrapped".
     *
     * Tor reports `Bootstrapped 100%` once it has reached the directory system
     * and built *a* circuit; that proves nothing about reaching a specific
     * hidden service. Both UIs used to call themselves connected off that
     * signal, which is why a cold start could claim connectivity while every
     * request was still failing. [hasCompletedRelayRoundTrip] is the honest
     * signal, and unlike [isRelayReachable] it is a monotonic latch for the
     * lifetime of this transport, so it does not flap with the hysteresis.
     *
     * Set by every cheap call that proves a round trip: the health loop below,
     * [waitForRelayWarm] (the pre-mint warm-circuit gate), and the control / batch
     * peeks ([peekControlPending], [peekControlRef], [peekInboxesBatch]).
     */
    @Volatile
    private var relayRoundTripCompleted = false

    /** @see relayRoundTripCompleted */
    fun hasCompletedRelayRoundTrip(): Boolean = relayRoundTripCompleted

    /** The ONE writer of [relayRoundTripCompleted] (a monotonic latch: only ever set). */
    private fun markRelayRoundTripCompleted() {
        relayRoundTripCompleted = true
    }

    /**
     * Length of the CURRENT run of consecutive full-budget health-probe
     * timeouts on this transport (see [isFullBudgetProbeTimeout]). Reset by any
     * other probe outcome — a success, a fast failure, an exception — and by
     * [noteEarlyNewnymFired], so the cold rung's second fire needs two FRESH
     * timeouts after the first one, never the ones that caused it.
     *
     * A re-wired transport (Tor restart, resume) starts a new MessageManager and
     * therefore a new run, which is honest: those timeouts belonged to circuits
     * that no longer exist.
     */
    @Volatile
    private var consecutiveFullBudgetTimeouts = 0

    /** @see consecutiveFullBudgetTimeouts */
    fun consecutiveFullBudgetProbeTimeouts(): Int = consecutiveFullBudgetTimeouts

    /**
     * The cold-transport NEWNYM rung's decision for THIS transport — the single
     * seam both platform ladders call, so Android and iOS decide identically.
     * Pure decision in [shouldFireEarlyNewnym]; this only supplies the two
     * transport-owned inputs.
     *
     * @param msSinceConnectAnchor ms since the platform's connect anchor (never
     *   moved by this rung — see [shouldFireEarlyNewnym]).
     * @param newnymsFiredThisSession session-scoped counter owned by the
     *   platform, because it must survive a transport re-wire.
     */
    fun earlyNewnymDue(msSinceConnectAnchor: Long, newnymsFiredThisSession: Int): Boolean =
        earlyNewnymDue(msSinceConnectAnchor, newnymsFiredThisSession, newnymsFiredThisSession)

    /** [earlyNewnymDue] with the cold rung's OWN fire count for the floor
     *  (floor fix, 2026-10-09) — see [shouldFireEarlyNewnym]'s
     *  `coldRungFiresThisSession`. Both platforms call this one. */
    fun earlyNewnymDue(msSinceConnectAnchor: Long, newnymsFiredThisSession: Int, coldRungFiresThisSession: Int): Boolean =
        shouldFireEarlyNewnym(
            coldTransport = !relayRoundTripCompleted,
            consecutiveFullBudgetTimeouts = consecutiveFullBudgetTimeouts,
            msSinceConnectAnchor = msSinceConnectAnchor,
            newnymsFiredThisSession = newnymsFiredThisSession,
            coldRungFiresThisSession = coldRungFiresThisSession,
        )

    /** Called by the platform ladder right after it actually fired the cold
     *  rung's `SIGNAL NEWNYM`. @see consecutiveFullBudgetTimeouts */
    fun noteEarlyNewnymFired() {
        consecutiveFullBudgetTimeouts = 0
    }

    /**
     * Start ([warmRungNowMs], monotonic) of the first FULL-BUDGET timed-out
     * attempt of the current DARK RUN on this transport, null while the relay is
     * answering. Unlike [consecutiveFullBudgetTimeouts] it is NOT cleared by a fire
     * or by a fast failure — only by the next probe that gets an HTTP answer — so
     * it measures how long the relay has been dark, and it is also the key that
     * tells a [WarmNewnymLedger] a new run began (fresh per-run budget).
     */
    @Volatile
    private var darkRunStartedAtMs: Long? = null

    /** Health-probe bookkeeping, one call per attempt — the ONLY writers of
     *  [consecutiveFullBudgetTimeouts] / [darkRunStartedAtMs] on the probe path.
     *  Internal so WarmNewnymRungTest can drive the evidence without a 10 s
     *  transport. */
    internal fun noteProbeAnswered() {
        consecutiveFullBudgetTimeouts = 0
        darkRunStartedAtMs = null
    }

    /** @see noteProbeAnswered — a failure that consumed (almost) its whole
     *  budget ([isFullBudgetProbeTimeout]); [attemptStartedAtMs] on the
     *  [warmRungNowMs] clock. */
    internal fun noteProbeTimedOut(attemptStartedAtMs: Long) {
        consecutiveFullBudgetTimeouts++
        if (darkRunStartedAtMs == null) darkRunStartedAtMs = attemptStartedAtMs
    }

    /** @see noteProbeAnswered — a FAST failure or an exception: breaks the
     *  timeout run (NEWNYM cannot fix a broken transport), but the relay is
     *  still dark, so the dark run keeps its start. */
    internal fun noteProbeFailedFast() {
        consecutiveFullBudgetTimeouts = 0
    }

    /**
     * The WARM-transport NEWNYM rung's decision for THIS transport — the single
     * seam both platform ladders call (Android `RunViewModel.maybeFireWarmNewnym`,
     * iOS via `IosAppController.warmNewnymDue`). Pure decision in
     * [shouldFireWarmNewnym]; this supplies the transport-owned evidence and the
     * platform-owned [ledger] (session-scoped, it outlives a transport re-wire).
     */
    fun warmNewnymDue(ledger: WarmNewnymLedger): Boolean =
        warmNewnymDueAt(ledger, warmRungNowMs())

    /** [warmNewnymDue] at an explicit [nowMs] on the [warmRungNowMs] clock — tests. */
    internal fun warmNewnymDueAt(ledger: WarmNewnymLedger, nowMs: Long): Boolean {
        val darkStart = darkRunStartedAtMs ?: return false
        ledger.syncRun(darkStart)
        return shouldFireWarmNewnym(
            warmTransport = relayRoundTripCompleted,
            consecutiveFullBudgetTimeouts = consecutiveFullBudgetTimeouts,
            darkForMs = nowMs - darkStart,
            msSinceLastFireThisRun = ledger.msSinceLastFireThisRun(nowMs),
            firesThisRun = ledger.firesThisRun,
            firesInWindow = ledger.firesInWindow(nowMs),
        )
    }

    /** Called by the platform ladder right after it actually fired the warm
     *  rung's `SIGNAL NEWNYM`: spends the budgets and clears the timeout run, so a
     *  repeat needs FRESH timeouts (also what keeps iOS's concurrent probe loops
     *  from double-firing on the same evidence). */
    fun noteWarmNewnymFired(ledger: WarmNewnymLedger) {
        noteWarmNewnymFiredAt(ledger, warmRungNowMs())
    }

    /** [noteWarmNewnymFired] at an explicit [nowMs] — tests. */
    internal fun noteWarmNewnymFiredAt(ledger: WarmNewnymLedger, nowMs: Long) {
        ledger.noteFired(nowMs)
        consecutiveFullBudgetTimeouts = 0
    }

    /**
     * Bumped by [noteNewCircuitRequested] every time an app-fired `SIGNAL NEWNYM`
     * was accepted by Tor. A probe attempt that started under an older epoch and
     * did not get an answer was abandoned by that NEWNYM
     * ([classifyProbeAttempt]); see "NEWNYM ABORTS THE IN-FLIGHT PROBE" in the
     * companion.
     */
    @Volatile
    private var circuitResetEpoch = 0L

    /**
     * The epoch the last BOOKED probe attempt (answered, timed out or failed
     * fast — never an abandoned one) started under. Behind [circuitResetEpoch] =
     * the fresh circuits have not been probed yet, which is what makes
     * [relayHealthDelayMs] hand out one fast (1–2 s) cycle after a NEWNYM even on
     * a warm transport.
     */
    @Volatile
    private var lastProbedEpoch = 0L

    /**
     * The platform's hook, called right after an app-fired `SIGNAL NEWNYM` was
     * ACCEPTED by Tor (Android `TorManager.requestNewCircuit` got its `250`; iOS
     * the NEWNYM reply observer saw `250`) — whichever rung fired it: warm-up
     * rotation, cold rung, warm rung, stall watch. Both platforms wire it once,
     * in their TorManager, so no NEWNYM path can forget it.
     *
     * Aborts the in-flight requests that opted in (`cancelOnNewCircuit`: the
     * health probe `GET /` and the unread prime's batch `POST /peek`) and bumps
     * the epoch so their callers re-run at once instead of sitting out a 20 s
     * budget on a retired circuit. Never aborted, by design: sends, mints, cap
     * rotations, push (un)registration — not idempotent from the user's point of
     * view (a push-toggle registration that fails is REVERTED in the UI), or
     * already self-retrying on fresh streams. Thread-safe, non-blocking.
     */
    fun noteNewCircuitRequested() {
        // The NEWNYM rungs own recovery from here: no rendezvous hedge on this
        // transport any more (an in-flight one opted into the abort below).
        rendHedgeNewnymSeen = true
        abortCircuitSensitiveRequests("NEWNYM accepted — aborted in-flight relay probe/peek, re-probing")
    }

    /** Shared tail of [noteNewCircuitRequested] / [noteRelayAddressSwitched]: bump
     *  [circuitResetEpoch], abort every opted-in request, and log [phrase] — a fixed
     *  phrase, no count, no identifier — iff anything was in flight. */
    private fun abortCircuitSensitiveRequests(phrase: String) {
        circuitResetEpoch++
        val aborted = try { httpClient.cancelNewCircuitSensitive() } catch (_: Exception) { 0 }
        if (aborted > 0) platformLog(LOG_TAG, phrase)
    }

    /**
     * Bumped by [noteRelayAddressSwitched] — only to pick the panel phrase of the
     * abandoned attempt; the abort itself rides [circuitResetEpoch].
     */
    @Volatile
    private var relayAddressEpoch = 0L

    /**
     * SEVERAL ONION ADDRESSES (2026-10-23): the descriptor race ([RelayAddressRace])
     * just made a DIFFERENT address the session's relay base URL. A probe / batch
     * peek in flight is very likely queued on the LOSING address's descriptor fetch
     * — the stalled HSDir set the race exists to dodge — so abort it exactly like
     * after a NEWNYM ([noteNewCircuitRequested]: same opted-in requests, same
     * epoch, same unbooked re-run) and re-probe at once on the winner, whose
     * descriptor Tor already holds. Bound by the race itself: at most one switch
     * per race, and a race only starts with a Tor process or an accepted NEWNYM.
     * Thread-safe, non-blocking (called on the Tor event thread).
     */
    fun noteRelayAddressSwitched() {
        relayAddressEpoch++
        abortCircuitSensitiveRequests("relay address switched — aborted in-flight relay probe/peek, re-probing")
    }

    // -----------------------------------------------------------------------
    // RENDEZVOUS HEDGE (2026-10-25) — see RendezvousHedge.kt for the why, the
    // isolation-class evidence and the bounds. This transport's side: ONE
    // watcher, alive only while a cold probe attempt is in flight, and at most
    // ONE hedge GET per instance. Everything below is guarded by [rendHedgeLock].
    // -----------------------------------------------------------------------

    private enum class RendHedgeState { IDLE, WATCHING, FIRED, DONE }

    private val rendHedgeLock = SyncLock()
    private var rendHedgeState = RendHedgeState.IDLE
    /** First cold probe attempt of this transport ([DescriptorHedge.nowMs] clock). */
    private var rendHedgeColdStartMs: Long? = null
    private var rendHedgeAttemptInFlight = false
    /** A won hedge's HTTP code, waiting for the in-flight attempt to consume it. */
    private var rendHedgeAnswer: Int? = null

    @Volatile
    private var rendHedgeNewnymSeen = false

    /** Test seams: the descriptor reference time and the clock the decision reads. */
    internal var rendHedgeDescriptorAtMs: () -> Long? = { RelayEndpoints.descriptorReceivedAtMs() }
    internal var rendHedgeNowMs: () -> Long = { DescriptorHedge.nowMs() }

    /** Where the watcher and the hedge GET run (both block on nothing but the
     *  transport; never the probe's own thread). */
    // ioDispatcher, not Default: the hedge GET blocks for up to HEALTH_HTTP_TIMEOUT_SECONDS
    // and must not pin a CPU-pool thread during the connect.
    private val rendHedgeScope = CoroutineScope(SupervisorJob() + ioDispatcher)

    private fun rendHedgeStepLocked(): RendezvousHedge.Step = RendezvousHedge.decide(
        nowMs = rendHedgeNowMs(),
        attemptInFlight = rendHedgeAttemptInFlight,
        coldProbeStartedAtMs = rendHedgeColdStartMs,
        descriptorReceivedAtMs = rendHedgeDescriptorAtMs(),
        transportWarm = relayRoundTripCompleted,
        newnymSeen = rendHedgeNewnymSeen,
        spent = rendHedgeState == RendHedgeState.FIRED || rendHedgeState == RendHedgeState.DONE,
        isolationSupported = httpClient.supportsSocksIsolation,
    )

    /** A cold probe attempt is about to block on the relay: remember the first
     *  one's start and arm the watcher if none is running. Cheap when the hedge
     *  cannot apply (warm, spent, NEWNYM, non-isolating transport). */
    private fun noteColdProbeAttemptStarted() {
        val start = rendHedgeLock.withLock {
            rendHedgeAttemptInFlight = true
            if (rendHedgeColdStartMs == null) rendHedgeColdStartMs = rendHedgeNowMs()
            if (rendHedgeState != RendHedgeState.IDLE) return@withLock false
            if (rendHedgeStepLocked().action == RendezvousHedge.Action.NEVER) {
                rendHedgeState = RendHedgeState.DONE
                return@withLock false
            }
            rendHedgeState = RendHedgeState.WATCHING
            true
        }
        if (start) launchRendHedgeWatcher()
    }

    private fun noteProbeAttemptEnded() {
        rendHedgeLock.withLock { rendHedgeAttemptInFlight = false }
    }

    /** The won hedge's answer for the attempt that just returned, or null. */
    private fun takeRendezvousHedgeAnswer(): Int? = rendHedgeLock.withLock {
        val a = rendHedgeAnswer
        rendHedgeAnswer = null
        a
    }

    private fun launchRendHedgeWatcher() {
        rendHedgeScope.launch {
            while (true) {
                var fire = false
                var control = false
                var waitMs = 0L
                val keepGoing = rendHedgeLock.withLock {
                    if (rendHedgeState != RendHedgeState.WATCHING) return@withLock false
                    val step = rendHedgeStepLocked()
                    when (step.action) {
                        RendezvousHedge.Action.FIRE -> {
                            // The ONE hedge of this transport is spent here, whether
                            // it is sent or (control arm) only logged.
                            if (RendezvousHedge.isHedgeEnabled()) {
                                rendHedgeState = RendHedgeState.FIRED
                                fire = true
                            } else {
                                rendHedgeState = RendHedgeState.DONE
                                control = true
                            }
                            false
                        }
                        RendezvousHedge.Action.WAIT -> { waitMs = step.recheckInMs; true }
                        // The next cold attempt re-arms (state back to IDLE).
                        RendezvousHedge.Action.PAUSE -> { rendHedgeState = RendHedgeState.IDLE; false }
                        RendezvousHedge.Action.NEVER -> { rendHedgeState = RendHedgeState.DONE; false }
                    }
                }
                if (control) RendezvousHedge.line(RendezvousHedge.CONTROL_PHRASE)
                if (fire) sendRendezvousHedge()
                if (!keepGoing) return@launch
                delay(waitMs.coerceIn(1L, RendezvousHedge.POLL_MS))
            }
        }
    }

    /**
     * The hedge itself: the health probe's bare `GET /` under a FRESH isolation
     * credential, cold budget, opted into the NEWNYM abort. First answer wins.
     * Runs on [rendHedgeScope]; blocks only that coroutine.
     */
    private fun sendRendezvousHedge() {
        val credential = SocksIsolation.newCredential()
        val generation = SocksIsolation.generation()
        val epochAtStart = circuitResetEpoch
        val startedAtMs = currentTimeMillis()
        RendezvousHedge.line(RendezvousHedge.FIRED_PHRASE)
        val result = try {
            httpClient.get(relayBaseUrl, emptyMap(), HEALTH_HTTP_TIMEOUT_SECONDS, true, 0, credential)
        } catch (e: Exception) {
            HttpResult(-1, null, false)
        }
        val elapsedMs = currentTimeMillis() - startedAtMs
        rendHedgeLock.withLock { rendHedgeState = RendHedgeState.DONE }
        when {
            result.code > 0 && relayRoundTripCompleted -> RendezvousHedge.line(RendezvousHedge.LOST_PHRASE)
            result.code > 0 -> {
                if (!SocksIsolation.adopt(credential, generation)) {
                    RendezvousHedge.line(RendezvousHedge.STALE_PHRASE)
                    return
                }
                RendezvousHedge.line(RendezvousHedge.wonPhrase(elapsedMs))
                // Hand the answer to the attempt blocked right now (if any), then
                // abort what is parked on the slow default-class rendezvous — that
                // probe and an unread-prime POST /peek — through the NEWNYM-abort
                // path: same opted-in requests, same epoch, same unbooked re-run, so
                // the peek re-sends at once under the adopted class.
                rendHedgeLock.withLock { if (rendHedgeAttemptInFlight) rendHedgeAnswer = result.code }
                circuitResetEpoch++
                try { httpClient.cancelNewCircuitSensitive() } catch (_: Exception) {}
            }
            circuitResetEpoch != epochAtStart -> RendezvousHedge.line(RendezvousHedge.ABANDONED_PHRASE)
            else -> RendezvousHedge.line(RendezvousHedge.noAnswerPhrase(elapsedMs))
        }
    }

    /** What one health-probe attempt counts as ([classifyProbeAttempt]). */
    internal enum class ProbeAttemptOutcome { ANSWERED, ABANDONED_BY_NEWNYM, TIMEOUT, FAILED_FAST }

    /** Whole seconds the relay has been dark on this transport (0 if it is
     *  answering) — for the LogBuffer line only; never on the wire. */
    fun warmDarkForSeconds(): Long =
        darkRunStartedAtMs?.let { ((warmRungNowMs() - it) / 1000).coerceAtLeast(0) } ?: 0

    // -----------------------------------------------------------------------
    // Health-probe scheduling + mutual exclusion.
    // -----------------------------------------------------------------------

    /**
     * Consecutive FAST (cold) health-loop retries already handed out — bounded by
     * [RELAY_HEALTH_FAST_RETRY_MAX]. Owned by the platform health loop, which is a
     * single sequential coroutine/Task per transport on both platforms; a genuine
     * (re)connect builds a new MessageManager, which re-arms it at 0.
     */
    private var relayHealthFastRetries = 0

    /**
     * Monotonic per-transport health-probe counter and the last schedule mode
     * reported, both for the live connection-log panel (ConnectionLog.kt). A
     * fresh MessageManager re-arms them at 0/null, which is exactly right: the
     * panel's "probe #1" means "first probe on THIS transport".
     */
    private var healthProbeSeq = 0
    private var lastLoggedFastSchedule: Boolean? = null

    /**
     * How long the platform health loop should wait before its NEXT reachability
     * cycle. Shared so Android and iOS schedule identically (same shape as
     * [controlPollDelayMs]).
     *
     * Jittered 8–12 s in steady state; 1–2 s while this transport has never
     * completed an onion round-trip, so a cold start rotates onto fresh Tor
     * streams instead of sleeping between them — see [RELAY_HEALTH_FAST_RETRY_MAX]
     * for the bound and its rationale.
     *
     * Call it ONCE per cycle: it consumes one fast-retry credit when it hands out
     * a fast delay.
     */
    fun relayHealthDelayMs(): Long {
        val warm = relayRoundTripCompleted
        // A NEWNYM was accepted since the last booked probe attempt started: the
        // fresh circuits are unprobed, so the next cycle runs on the fast (1-2 s)
        // schedule — warm or cold — WITHOUT spending a cold fast-retry credit.
        // Once a probe attempt starts under the new epoch, this reads false.
        val newnymUnprobed = lastProbedEpoch != circuitResetEpoch
        val fast = newnymUnprobed || useFastRelayHealthRetry(warm, relayHealthFastRetries)
        // Connection-log panel: report the SCHEDULE, and only when it changes —
        // one line per transition, not one per cycle (the panel holds 300 lines).
        if (lastLoggedFastSchedule != fast) {
            lastLoggedFastSchedule = fast
            ConnectionLog.append(
                ConnectionLog.Kind.HEALTH,
                if (fast) "health schedule: fast retry (1-2 s)"
                else "health schedule: heartbeat (8-12 s)",
            )
        }
        if (fast && !newnymUnprobed) relayHealthFastRetries++ else if (!fast && warm) relayHealthFastRetries = 0
        val jitter = secureRandomInt(
            if (fast) RELAY_HEALTH_FAST_RETRY_JITTER_MS else RELAY_HEALTH_JITTER_MS
        )
        return relayHealthDelayMsFor(fast, jitter)
    }

    /**
     * At most ONE reachability GET may be in flight per transport.
     *
     * Two probes would be pointless — Tor attaches both to the same rendezvous
     * work, so the second learns nothing the first will not report a moment later —
     * and with the cold cadence now ~1–2 s they would stack: the manual Reconnect
     * (iOS `reconnectRelay`) and the health loop's own tick can both call in while
     * a 20 s cold attempt is still blocked, and the OLD job's in-flight probe
     * outlives the cancel that replaced it (a blocking transport call is not
     * cancellable on either platform).
     *
     * A caller that loses the race gets [lastHealthProbeResult] — the last thing a
     * completed probe actually observed — instead of making a second request. That
     * is honest ("nothing new to report yet") and it is the SAME direction the
     * hysteresis already handles: a stale miss costs at most one counted tick, and
     * both platforms floor those ticks on wall time, so it cannot accelerate the
     * grey-out or the stall escalation. It never fabricates a success: the value is
     * only ever written by a probe that ran.
     *
     * Deliberately NOT extended to [waitForRelayWarm]'s pre-mint GET: that gate is
     * a one-shot in front of a PoW grind, it already short-circuits on
     * [hasCompletedRelayRoundTrip], and blocking it behind a health probe would put
     * an unrelated 20 s wait in front of a mint.
     */
    private val healthProbeLock = SyncLock()
    private var healthProbeInFlight = false

    /** @see healthProbeLock */
    @Volatile
    private var lastHealthProbeResult = false

    // -----------------------------------------------------------------------
    // Update nudge — the relay's advertised "latest published version".
    // -----------------------------------------------------------------------

    /**
     * Latched true once the update check has been EVALUATED, i.e. the first
     * relay response with `code > 0` reached [observeRelayResponse]. Monotonic
     * per instance: the check is never re-run, so a relay cannot change its
     * mind mid-session by serving a different header on a later reply.
     */
    @Volatile
    private var updateCheckDone = false

    /**
     * The relay's advertised version when it is strictly newer than
     * [localAppVersion], else null. Re-RENDERED from the parsed integer triple
     * ([AppVersion.render]) — never the raw header — and never logged.
     */
    @Volatile
    private var newerRelayVersion: String? = null

    /**
     * The version string the update nudge may offer, or null (the normal case:
     * no header, an unparseable/hostile header, an equal or lower advertised
     * version, or an unparseable local version — see [isNewerVersion], which
     * fails closed on every ambiguity).
     *
     * Semantics, all deliberate:
     *  - decided by the FIRST `code > 0` response on ANY endpoint (the health
     *    probe `GET /`, the warm-circuit probe, `/peek`, a send — whichever
     *    lands first; they race on one Tor transport and nothing orders them);
     *  - MONOTONIC per MessageManager instance and NEVER re-evaluated. A new
     *    instance (Tor self-heal, re-foreground) re-arms the evaluation, which
     *    is harmless — the per-day vault throttle is the real cap;
     *  - the value is re-rendered from the parsed triple, so at most a bounded
     *    number of relay-chosen ASCII digits can travel onward, and it is never
     *    written to any log.
     *
     * Zero-arg function, not a `StateFlow`, on purpose: no coroutines type is
     * exported to Swift, and both platforms already poll this class from their
     * 8–12 s health loops (exact same shape as [hasCompletedRelayRoundTrip]).
     */
    fun newerRelayVersion(): String? = newerRelayVersion

    /**
     * The update-nudge observer wrapped around every relay response by the
     * [httpClient] delegate. Returns [result] UNCHANGED — it is a pure
     * observer, and the compute is additionally try/caught so it can never turn
     * a successful relay call into a failure.
     *
     * The check-and-set is not atomic; two responses landing concurrently on
     * the very first round-trip can both evaluate. That race is benign — both
     * are equally "the first response", and the outcome is one of the two
     * headers, never a merge.
     */
    private fun observeRelayResponse(result: HttpResult): HttpResult {
        if (!updateCheckDone && result.code > 0) {
            updateCheckDone = true
            newerRelayVersion = try {
                isNewerVersion(result.headers[UPDATE_NUDGE_HEADER_KEY], localAppVersion)?.render()
            } catch (_: Exception) {
                null
            }
        }
        return result
    }

    /**
     * Checks whether the relay server is reachable.
     * Any real HTTP response (even 404) means the server is up.
     * Only network-level failures return false.
     *
     * Deliberately NOT subject to the "move to new device" freeze gate: it is a bare
     * `GET /` carrying no capability and naming no inbox, and the old phone's QR /
     * waiting screen needs the same connectivity signal every other screen does.
     */
    fun isRelayReachable(): Boolean {
        // One health GET at a time per transport (see healthProbeLock): a loser
        // reports what the last completed probe saw rather than opening a second
        // stream onto the same rendezvous.
        val claimed = healthProbeLock.withLock {
            if (healthProbeInFlight) false else { healthProbeInFlight = true; true }
        }
        if (!claimed) return lastHealthProbeResult
        try {
            return probeRelayReachable()
        } finally {
            healthProbeLock.withLock { healthProbeInFlight = false }
        }
    }

    /** The probe itself; callers go through [isRelayReachable]'s in-flight gate. */
    private fun probeRelayReachable(): Boolean {
        // Each call opens a FRESH Tor onion stream (Connection: close); a single
        // stream can miss the v3 rendezvous under concurrent multi-device load even
        // when the relay is up (Android's Tor and the desktop's reach it fine at the
        // same time). Retry once on a fresh stream before reporting unreachable, so
        // one unlucky stream doesn't flip the reachability signal — the caller
        // additionally applies consecutive-miss hysteresis, so a genuine outage
        // still surfaces. Any real HTTP response (even 404) means the relay is up.
        // `attempt` counts BOOKED attempts only: one a NEWNYM abandoned is re-run
        // at once without consuming a slot (bounded by PROBE_NEWNYM_REPROBE_MAX).
        var attempt = 0
        var newnymReprobes = 0
        while (attempt < RELAY_HEALTH_ATTEMPTS) {
            // Connection-log panel: number every attempt so a user reading the
            // panel can see the probe cadence. Identifier-free by construction —
            // fixed phrases, the HTTP code, and elapsed seconds. NEVER the URL,
            // the host or `result.body` (see the CODE ONLY note below).
            val probeNo = ++healthProbeSeq
            val startedAtMs = currentTimeMillis()
            val startedAtMonoMs = warmRungNowMs()
            val epochAtStart = circuitResetEpoch
            val addressEpochAtStart = relayAddressEpoch
            try {
                // EXPLICIT budget (never the 60 s message-traffic default), and
                // COLD-AWARE: the first probes of a session get room to finish the
                // one-off descriptor fetch + rendezvous, then the latch drops us to
                // the tight steady-state budget. See relayProbeTimeoutSeconds.
                val timeout = relayProbeTimeoutSeconds(relayRoundTripCompleted)
                // cancelOnNewCircuit: an app-fired NEWNYM aborts this stream at
                // once (noteNewCircuitRequested) instead of letting it sit out
                // the budget on a retired circuit.
                val firstByte = probeFirstByteTimeoutSeconds(relayRoundTripCompleted)
                // RENDEZVOUS HEDGE: a cold attempt arms the one watcher; a hedge
                // that answers while this GET is blocked cancels it and hands its
                // answer back here (consumed below, under the hedge lock).
                if (!relayRoundTripCompleted) noteColdProbeAttemptStarted()
                val result = try {
                    httpClient.get(relayBaseUrl, emptyMap(), timeout, cancelOnNewCircuit = true, firstByteTimeoutSeconds = firstByte)
                } finally {
                    noteProbeAttemptEnded()
                }
                val hedgeCode = takeRendezvousHedgeAnswer()
                val elapsedMs = currentTimeMillis() - startedAtMs
                if (hedgeCode != null && result.code <= 0) {
                    // The hedge's own (real) relay answer ends this attempt: booked
                    // exactly as an answered probe — same PROBE_OK code, same latches.
                    return bookProbeAnswered(probeNo, hedgeCode, elapsedMs, viaHedge = true)
                }
                val firstByteTimedOut = firstByte > 0 && result.code <= 0 && result.firstByteTimeout
                val outcome = classifyProbeAttempt(
                    answered = result.code > 0,
                    newnymDuringAttempt = circuitResetEpoch != epochAtStart,
                    elapsedMs = elapsedMs,
                    timeoutSeconds = timeout,
                    firstByteTimedOut = firstByteTimedOut,
                )
                if (outcome == ProbeAttemptOutcome.ABANDONED_BY_NEWNYM) {
                    // Neither a timeout nor a success: NO bookkeeping at all — the
                    // NEWNYM rungs' run, the dark-run start, the in-flight result
                    // and lastProbedEpoch are left exactly as they were — and the
                    // attempt is re-run NOW on the fresh circuits. Fixed phrase +
                    // numbers, no code (uncoded lines never reach telemetry).
                    logAbandonedProbe(probeNo, elapsedMs, addressEpochAtStart)
                    if (newnymReprobes < PROBE_NEWNYM_REPROBE_MAX) newnymReprobes++ else attempt++
                    continue
                }
                lastProbedEpoch = epochAtStart
                attempt++
                if (outcome == ProbeAttemptOutcome.ANSWERED) {
                    return bookProbeAnswered(probeNo, result.code, elapsedMs, viaHedge = false)
                }
                // A transport failure that consumed (almost) the whole budget is a
                // timeout; anything quicker is a refused/broken stream. Both are
                // numbers-only lines.
                val isTimeout = outcome == ProbeAttemptOutcome.TIMEOUT
                // Feeds the cold-transport NEWNYM rung (shouldFireEarlyNewnym):
                // only a run of FULL-BUDGET timeouts is evidence of a wedged
                // introduction point; a fast failure is a broken transport and
                // breaks the run.
                // The warm rung (shouldFireWarmNewnym) reads the same run plus
                // the dark-run start recorded here.
                if (isTimeout) noteProbeTimedOut(startedAtMonoMs) else noteProbeFailedFast()
                ConnectionLog.append(
                    ConnectionLog.Kind.HEALTH,
                    if (isTimeout && firstByteTimedOut && !isFullBudgetProbeTimeout(elapsedMs, timeout))
                        // Fixed phrase + numbers. Same PROBE_TIMEOUT code — it
                        // is the same evidence, and the code set is relay-allowlisted.
                        "probe #$probeNo: no answer $firstByte s after the stream connected"
                    else if (isTimeout)
                        "probe #$probeNo: timeout after $timeout s"
                    else
                        "probe #$probeNo: no response in ${formatSeconds(elapsedMs)} s",
                    // The FAST failure used to carry NO code at all, so a
                    // connect made of broken streams reached the relay as a
                    // timeline with a hole in it — indistinguishable from a
                    // connect where the probe loop was simply not running. The
                    // two outcomes stay SEPARATE codes because they mean
                    // different things (and are acted on differently): a
                    // full-budget timeout is a wedged rendezvous and feeds the
                    // cold NEWNYM rung, a fast failure is a broken transport and
                    // breaks that run. PROBE_FAILED is sheddable by family,
                    // PROBE_TIMEOUT deliberately is not — see
                    // ConnectTelemetry.isSheddableProbeCode.
                    if (isTimeout) ConnectionLog.Code.PROBE_TIMEOUT else ConnectionLog.Code.PROBE_FAILED,
                )
                // The probe failed WITHOUT throwing — which is the only way it
                // ever fails in production: both actuals map a transport error
                // to HttpResult(code = -1, …) instead of propagating
                // (PlatformHttpClient.android.kt's catch-all; the iOS actual
                // returns the bridge's code verbatim). So the catch below never
                // fired and every relay/Tor health failure went UNRECORDED at
                // this layer — the failure path is logged here instead.
                //
                // CODE ONLY, deliberately: on Android `body` on this path is the
                // raw OkHttp exception message, and several of those embed the
                // request host ("unexpected end of stream on http://<onion>/…",
                // UnknownHostException) — writing that into the in-app log
                // buffer would partially deanonymize the relay, which the
                // never-reveal-the-relay rule forbids (the same reason the transport logs a host-free path).
                // The code alone distinguishes the outcomes that matter: -1 =
                // transport/Tor failure, 0 = no response at all.
                platformLogWarn(
                    LOG_TAG,
                    "relay probe failed (attempt $attempt/$RELAY_HEALTH_ATTEMPTS, budget=${timeout}s): code=${result.code}"
                )
            } catch (e: Exception) {
                // A hedge answer handed to an attempt that THREW is not booked
                // here; the hedge's class is adopted, so the re-run answers fast.
                takeRendezvousHedgeAnswer()
                // An exception thrown on an attempt a NEWNYM abandoned is booked
                // like any other abandon: not at all, and re-run now.
                if (circuitResetEpoch != epochAtStart) {
                    logAbandonedProbe(probeNo, currentTimeMillis() - startedAtMs, addressEpochAtStart)
                    if (newnymReprobes < PROBE_NEWNYM_REPROBE_MAX) newnymReprobes++ else attempt++
                    continue
                }
                lastProbedEpoch = epochAtStart
                attempt++
                // Retained for defense in depth: nothing throws here today, but
                // a bridge-holder misregistration on iOS raises IllegalState
                // from PlatformHttpClient.get. Class name only — an arbitrary
                // exception's message is not vetted for relay identifiers.
                platformLogWarn(
                    LOG_TAG,
                    "relay probe threw (attempt $attempt/$RELAY_HEALTH_ATTEMPTS): ${e::class.simpleName}"
                )
                // Not a full-budget timeout (and not vetted as one) — breaks the
                // cold rung's run, same as a fast failure above.
                noteProbeFailedFast()
                // Class name only, same rule as the log line above: an arbitrary
                // exception's MESSAGE is not vetted for relay identifiers.
                ConnectionLog.append(
                    ConnectionLog.Kind.HEALTH,
                    "probe #$probeNo: error ${e::class.simpleName}",
                    ConnectionLog.Code.PROBE_ERROR,
                )
            }
        }
        lastHealthProbeResult = false
        return false
    }

    /**
     * Books an ANSWERED probe attempt (a real relay answer, the probe's own or the
     * rendezvous hedge's) and returns true for the caller to return: the PROBE_OK
     * panel line (relay-allowlisted — the phrase is byte-identical on both paths
     * apart from the hedge suffix), the round-trip latch, the in-flight result, and
     * [lastProbedEpoch] moved to the CURRENT epoch — the relay is reachable, so
     * there is nothing left for a post-NEWNYM fast cycle to find out, whichever
     * circuit carried the answer.
     */
    private fun bookProbeAnswered(probeNo: Int, code: Int, elapsedMs: Long, viaHedge: Boolean): Boolean {
        ConnectionLog.append(
            ConnectionLog.Kind.HEALTH,
            "probe #$probeNo: $code in ${formatSeconds(elapsedMs)} s${if (viaHedge) " (rendezvous hedge)" else ""}",
            ConnectionLog.Code.PROBE_OK,
        )
        markRelayRoundTripCompleted()
        lastHealthProbeResult = true
        lastProbedEpoch = circuitResetEpoch
        noteProbeAnswered()
        return true
    }

    /** The uncoded panel line for an attempt a NEWNYM / address switch abandoned. The
     *  caller does the (deliberately absent) bookkeeping: re-run without a slot. */
    private fun logAbandonedProbe(probeNo: Int, elapsedMs: Long, addressEpochAtStart: Long) {
        ConnectionLog.append(
            ConnectionLog.Kind.HEALTH,
            abandonedProbePhrase(probeNo, elapsedMs, addressSwitched = relayAddressEpoch != addressEpochAtStart),
        )
    }

    /**
     * Builds a relay inbox URL, optionally with the blob-retention query
     * parameter the relay's `POST /inbox/{id}` accepts (`?ttl=<seconds>`,
     * server-side `coerceIn(1, maxTtlSeconds)`; absent ⇒ the relay's 24 h
     * default).
     *
     * [ttlSeconds] is CLAMPED to `1..RELAY_MAX_TTL_SECONDS` and rendered as bare
     * digits, so nothing a caller passes can inject structure into the URL. It is
     * a URL parameter ONLY — never part of the sealed envelope — so the wire
     * format, the AEAD-bound `ch`/`di` fields and the counter+epoch anti-replay
     * rules are completely untouched by it. `null` (a TEXT append) emits a
     * byte-identical URL to what has always been sent.
     *
     * What that paragraph misses, and why the value is
     * now UNIFORM: the ttl is METADATA. It rides the request line in the clear, so
     * a per-kind ttl is a per-kind label the padding buckets were meant to deny the
     * relay. `?ttl=604800` + `X-No-Push: 1` used to mean "group ROSTER or LEAVE,
     * nothing else". Every control append now passes
     * [CONTROL_APPEND_TTL_SECONDS]; do not add a second ttl value to the control
     * path without re-reading this note.
     */
    private fun validatedInboxUrl(
        inboxId: String,
        suffix: String = "",
        ttlSeconds: Long? = null,
    ): String {
        require(isValidInboxId(inboxId)) { "Invalid inbox ID format" }
        val base = "$relayBaseUrl/inbox/$inboxId$suffix"
        if (ttlSeconds == null) return base
        return base + "?ttl=" + ttlSeconds.coerceIn(1L, RELAY_MAX_TTL_SECONDS)
    }

    // -----------------------------------------------------------------------
    // Inbox creation — IRL pairing only
    // -----------------------------------------------------------------------

    /** A transient mint failure (a dropped Tor round-trip) — retried by [mintInbox]. */
    /** [reason] is a fixed phrase plus a class name / HTTP code — what the retry log prints. */
    private class MintTransientFailure(val reason: String, val rateLimited: Boolean = false) : Exception(reason)

    /** Remaining PoW-grind budget (ms), shared across one [mintInbox]'s solves. */
    private class PowBudget(var remainingMs: Long)

    /**
     * Mints a fresh inbox on the relay. CPU-bound for ~1-5 seconds while
     * solving the PoW; MUST be called from a background dispatcher. Returns null
     * (does NOT throw) if [abort] is signalled before a solution — the solver's
     * [PowSolveAborted] is caught internally and mapped to a null result.
     *
     * [abort] is honoured OUTSIDE the grind too: at the top of every transient
     * retry and inside the inter-retry backoff (see [sleepAbortable]). It is NOT
     * checked mid-flight of an individual HTTP leg — those are already bounded by
     * [MINT_HTTP_TIMEOUT_SECONDS] — so the worst-case overrun past a signalled
     * abort is one in-flight POST, not the whole retry ladder.
     *
     * Returns null on transport/protocol failure (logged); caller handles
     * UX retry. On success, the caller is responsible for:
     *   1. Persisting the inbox via [VaultDatabase.insertInboxId] with the
     *      appropriate direction and cap field populated. The readCap goes
     *      on the inbound record (we hold it). The writeCap is what we
     *      hand the peer in the IRL pairing QR.
     *   2. Discarding the writeCap from local memory once handed off, if
     *      you want to minimize on-device exposure (the peer is the only
     *      party that needs it).
     *
     * No contactId here — minting is independent of pairing. The bundle is
     * bound to a contact at vault-insert time after the QR exchange.
     *
     * Deliberately NOT subject to the "move to new device" freeze gate — this is
     * what mints the move's own TRANSFER inbox ([RelayMoveTransport.mintTransferInbox]),
     * which happens after `mig_frozen` is written by construction. The PAIRING mint
     * on top of it, [mintInboxPair], IS gated; there is no other caller.
     */
    fun mintInbox(
        abort: PowAbort = PowAbort { false },
        // How many mint grinds run concurrently, so the PoW solver splits
        // the core budget and doesn't oversubscribe. mintInboxPair runs its two
        // mints sequentially, so today every caller uses the default 1.
        concurrentGrinds: Int = 1,
    ): MintedInbox? {
        // Retry the whole handshake after a TRANSIENT failure — a dropped Tor
        // round-trip (the POST threw or returned code <= 0) OR a 429 rate-limit
        // (the relay saying "slow down"). Re-grinds across retries stay bounded
        // by [MINT_TOTAL_POW_BUDGET_MS], so retrying 429 can't be abused into
        // unbounded PoW. Genuinely terminal (return null, NOT retried): PoW
        // timeout, 507 inbox-limit, hostile difficulty, caller abort.
        //
        // One PoW-grind budget shared across every solve this mint runs (across
        // both the transient retries here and the re-solve loop in
        // mintInboxOnce), so a hostile relay can't multiply the per-solve cap.
        val powBudget = PowBudget(MINT_TOTAL_POW_BUDGET_MS)
        repeat(MAX_MINT_TRANSIENT_ATTEMPTS) { attempt ->
            // The caller's abort is polled by the PoW grind but was NOT
            // consulted by this loop or by the HTTP legs, so a mint that kept hitting
            // transient failures ran to its own exhaustion — 12 attempts × (up to two
            // 25 s POSTs + a 1.5-12 s backoff) — long past the deadline/cancel the
            // caller had already signalled (ReferralManager's ACCEPT_MINT_DEADLINE_MS,
            // AddContactScreen's user-cancel flag). Check it at the TOP of every
            // iteration so an abort raised during an attempt or a backoff stops the
            // next one, and use the SAME semantics the grind's own abort has here:
            // a quiet null, never a throw (see mintInboxOnce's PowSolveAborted arm).
            if (abort.shouldAbort()) {
                platformLog(LOG_TAG, "mintInbox: aborted before attempt ${attempt + 1}")
                return null
            }
            try {
                return mintInboxOnce(abort, powBudget, concurrentGrinds)
            } catch (e: MintTransientFailure) {
                // This message is OUR text (a fixed phrase + exception class / HTTP code,
                // built in mintInboxOnce), never transport or relay text.
                platformLogWarn(
                    LOG_TAG,
                    "mintInbox: transient (${e.reason}) — retry ${attempt + 1}/$MAX_MINT_TRANSIENT_ATTEMPTS",
                )
                if (attempt < MAX_MINT_TRANSIENT_ATTEMPTS - 1) {
                    // Backoff before the next attempt. A 429 means the relay is
                    // rate-limiting inbox creation, so back off LONGER (6-12s) to
                    // let its (short, ~10-15s) window clear without hammering it;
                    // a plain Tor-drop just needs the circuit to rotate (1.5-5s).
                    // Network/backoff time is NOT counted against the PoW budget,
                    // which independently caps grind — so this rides out a rate
                    // limit without enabling a hostile 429 CPU-DoS.
                    //
                    // ABORT-AWARE: a blocking sleep of up to 12 s per retry is the
                    // single biggest place a cancelled mint used to overrun, so it is
                    // slept in short chunks and cut short the moment the abort fires.
                    if (!sleepAbortable(
                            if (e.rateLimited) jitterMs(MINT_BACKOFF_RATE_LIMITED_BASE_MS, MINT_BACKOFF_RATE_LIMITED_SPREAD_MS)
                            else jitterMs(MINT_BACKOFF_TRANSIENT_BASE_MS, MINT_BACKOFF_TRANSIENT_SPREAD_MS),
                            abort,
                        )
                    ) {
                        platformLog(LOG_TAG, "mintInbox: aborted during backoff")
                        return null
                    }
                }
            }
        }
        platformLogWarn(LOG_TAG, "mintInbox: exhausted $MAX_MINT_TRANSIENT_ATTEMPTS transient retries")
        return null
    }

    /**
     * [sleepMillis] in [ABORT_SLEEP_CHUNK_MS] slices, polling [abort] between them.
     * Returns true if the whole delay elapsed, false if it was cut short because the
     * caller aborted — so the caller can bail immediately instead of finishing a
     * backoff nobody is waiting for any more.
     *
     * Chunked rather than interruptible because [sleepMillis] is a plain blocking
     * sleep on both platforms (no cancellation token to plumb), and the mint runs on
     * a blocking dispatcher. The chunk size bounds how long an abort can be ignored;
     * it is deliberately coarse enough that a 12 s backoff costs at most a dozen
     * cheap predicate calls.
     */
    private fun sleepAbortable(totalMs: Long, abort: PowAbort): Boolean {
        var remaining = totalMs
        while (remaining > 0) {
            if (abort.shouldAbort()) return false
            val chunk = if (remaining < ABORT_SLEEP_CHUNK_MS) remaining else ABORT_SLEEP_CHUNK_MS
            sleepMillis(chunk)
            remaining -= chunk
        }
        return true
    }

    /** What one leg of the mint handshake answered — see [classifyMintResponse]. */
    private sealed class MintStep {
        /** 201: the inbox (null = the body did not parse — terminal, as before). */
        class Minted(val inbox: MintedInbox?) : MintStep()
        /** 400 with a body: a (fresh) PoW challenge. */
        class Challenge(val body: String) : MintStep()
        /** Any other real status (507 inbox limit, …): terminal, no retry. Logged. */
        object Terminal : MintStep()
    }

    /**
     * The ONE response ladder both mint legs share ([leg] = "challenge fetch" or
     * "submit", so every phrase is the one each leg logged before). A transport drop
     * (code ≤ 0) and a 429 THROW [MintTransientFailure] — transient, retried with
     * backoff by [mintInbox] (the re-grind bounded by the shared PoW budget). CODE
     * ONLY in the log, like the relay probe: the body is never logged.
     */
    private fun classifyMintResponse(r: HttpResult, leg: String): MintStep = when {
        r.code == 201 && r.body != null -> MintStep.Minted(parseMintResponse(r.body))
        r.code == 400 && r.body != null -> MintStep.Challenge(r.body)
        r.code <= 0 -> throw MintTransientFailure("$leg transport drop (code=${r.code})")
        r.code == 429 -> throw MintTransientFailure("$leg rate-limited (429)", rateLimited = true)
        else -> {
            platformLogWarn(LOG_TAG, "mintInbox: $leg code=${r.code}")
            MintStep.Terminal
        }
    }

    private fun mintInboxOnce(
        abort: PowAbort,
        powBudget: PowBudget,
        concurrentGrinds: Int = 1,
    ): MintedInbox? {
        // Phase 1: ask for a challenge. No PoW headers, empty body. Under the
        // capability protocol the relay always answers 400 with the challenge
        // body — that 400 IS the control step, not an error.
        val challengeResult = try {
            httpClient.post(
                url = "$relayBaseUrl/inbox",
                body = ByteArray(0),
                contentType = CONTENT_TYPE,
                timeoutSeconds = MINT_HTTP_TIMEOUT_SECONDS,
            )
        } catch (e: Exception) {
            // A thrown POST is a Tor transport drop — transient, worth a retry.
            throw MintTransientFailure("challenge fetch threw: ${e::class.simpleName}")
        }
        var challengeBody: String = when (val step = classifyMintResponse(challengeResult, "challenge fetch")) {
            // Defensive: a relay with PoW disabled could 201 immediately.
            is MintStep.Minted -> return step.inbox
            is MintStep.Challenge -> step.body
            MintStep.Terminal -> return null
        }

        // Phase 2: solve the current challenge and submit. The relay may reject
        // a fresh solution (expired/spent/skew) with ANOTHER 400-challenge —
        // identical on the wire to the first. Re-solve the fresh challenge,
        // bounded by MAX_MINT_SOLVE_ATTEMPTS so a hostile relay can't spin us.
        repeat(MAX_MINT_SOLVE_ATTEMPTS) { attempt ->
            val challenge = parseChallenge(challengeBody) ?: return null

            // Each solve gets the smaller of the per-solve cap and what's left
            // of this mint's aggregate budget; the actual grind time is deducted
            // in `finally` (so a timeout/abort still counts) so re-solves and
            // transient retries can't multiply the per-solve cap. Once the budget
            // is spent, solveCap is 0 and solvePow times out at once → terminal.
            val solveCap = powBudget.remainingMs.coerceIn(0L, POW_MAX_SOLVE_MILLIS)
            val solveStart = TimeSource.Monotonic.markNow()
            val counter = try {
                solvePow(nonce = challenge.nonce, difficulty = challenge.difficulty, abort = abort, maxDurationMs = solveCap, concurrentGrinds = concurrentGrinds)
            } catch (e: PowDifficultyTooHigh) {
                // Hostile/over-budget difficulty — refuse rather than burn CPU.
                platformLogWarn(LOG_TAG, "mintInbox: refusing difficulty ${e.difficulty} (> $MAX_POW_DIFFICULTY_BITS)")
                return null
            } catch (e: PowSolveAborted) {
                platformLog(LOG_TAG, "mintInbox: PoW solve aborted")
                return null
            } catch (e: PowTimedOut) {
                // The grind hit its wall-clock cap — abandon this mint cleanly.
                platformLogWarn(LOG_TAG, "mintInbox: PoW exceeded ${e.budgetMs}ms budget, giving up")
                return null
            } catch (e: Exception) {
                platformLogError(LOG_TAG, "mintInbox: PoW failed: ${e::class.simpleName}")
                return null
            } finally {
                powBudget.remainingMs -= solveStart.elapsedNow().inWholeMilliseconds
            }

            val result = try {
                httpClient.post(
                    url = "$relayBaseUrl/inbox",
                    body = ByteArray(0),
                    contentType = CONTENT_TYPE,
                    headers = mapOf(
                        POW_TOKEN_HEADER   to challenge.token,
                        POW_COUNTER_HEADER to counter.toString(),
                    ),
                    timeoutSeconds = MINT_HTTP_TIMEOUT_SECONDS,
                )
            } catch (e: Exception) {
                // Submit threw — a Tor transport drop. Transient. If the relay
                // actually created the inbox before the response was lost, the
                // retry re-solves a fresh challenge and mints a new one; the
                // orphan simply expires unused — acceptable vs failing pairing.
                throw MintTransientFailure("submit threw: ${e::class.simpleName}")
            }

            when (val step = classifyMintResponse(result, "submit")) {
                is MintStep.Minted -> return step.inbox
                // Fresh challenge handed back — re-solve on the next iteration.
                is MintStep.Challenge -> {
                    platformLog(LOG_TAG, "mintInbox: solution rejected (attempt ${attempt + 1}), re-solving")
                    challengeBody = step.body
                }
                MintStep.Terminal -> return null
            }
        }

        platformLogWarn(LOG_TAG, "mintInbox: exhausted $MAX_MINT_SOLVE_ATTEMPTS solve attempts")
        return null
    }

    /**
     * Mints the inboxes a pairing needs — the text inbox, the control inbox (v7)
     * and the GROUP-text inbox — SEQUENTIALLY. Each is an independent two-request
     * PoW handshake ([mintInbox]); text first, then control, then group.
     *
     * Null ONLY when the text or the control inbox could not be minted. A failed
     * GROUP mint returns the pair with `grp = null` — see the branch below for why
     * that asymmetry is deliberate.
     *
     * The mints run one after the other ON PURPOSE rather than in parallel.
     * Each [mintInbox] grind already fans across every CPU core, so two
     * simultaneous grinds oversubscribe the cores — on a low-core or busy
     * device each grind then makes roughly half-speed progress, doubling its
     * wall-clock and pushing it toward the per-solve timeout
     * ([POW_MAX_SOLVE_MILLIS]). Serial minting keeps a single full-speed grind
     * on the cores at a time. It also short-circuits: if the text inbox can't be
     * minted there is no point grinding the control inbox.
     *
     * This is the SINGLE entry point both platforms call, so Android and iOS
     * mint identically.
     *
     * Suspends until both finish; the blocking grind/HTTP work runs on
     * [Dispatchers.Default], so a caller on the main thread is never blocked.
     * [abort] cancels the in-flight grind.
     */
    suspend fun mintInboxPair(
        abort: PowAbort = PowAbort { false },
    ): MintedInboxPair? = withContext(Dispatchers.Default) {
        // "Move to new device" FREEZE GATE. A PAIRING mint (this is the only caller
        // shape: add-contact + the referral accept) would create inbox rows the
        // exported bundle no longer contains, i.e. a contact that exists on the old
        // phone and nowhere else. `null` is what both callers already render as
        // "could not reach the relay". Note the single-inbox [mintInbox] is
        // deliberately NOT gated — it is what mints the move's own transfer inbox.
        if (moveFrozen("pairing mint")) return@withContext null
        // Don't spend PoW + fire mint POSTs into a cold circuit — wait (cheaply)
        // for the relay to answer first, so all three inboxes mint on a warm circuit.
        // Best-effort: returns even if never warm (then we mint anyway, as before),
        // but bails immediately if the caller's deadline (abort) has already passed.
        if (abort.shouldAbort()) return@withContext null
        waitForRelayWarm(abort)
        // Mint the three inboxes SEQUENTIALLY with a short-circuit. Concurrent
        // minting (tried in 6a0c138) fires both mints' POST sequences at once;
        // on Tor's single constrained circuit that is observably UNRELIABLE — on
        // a physical device the cheap warm-gate GET reached the relay (404) but
        // the concurrent mint POSTs failed "could not reach the relay" for
        // minutes. Sequential is slower but far more reliable over Tor, and it
        // also removes both regressions the concurrent change introduced: a
        // terminal FIRST-inbox failure mints no control inbox (no orphan),
        // and only one PoW grind runs at a time (no core oversubscription).
        val main = mintInbox(abort) ?: return@withContext null
        // Honour the caller's deadline/cancel BETWEEN the two mints. The
        // first mint can legitimately consume the whole budget, and without this the
        // pair still paid a SECOND full mint (a PoW grind plus up to
        // MAX_MINT_TRANSIENT_ATTEMPTS handshakes) after the deadline had already
        // passed — the ~888 s worst case against ReferralManager's 480 s. Falls into
        // the same abandonment branch as a failed ctl mint, so the just-minted (and
        // still unshared) main inbox is destroyed rather than left parked.
        val ctl = if (abort.shouldAbort()) {
            platformLog(LOG_TAG, "mintInboxPair: aborted after the main mint — not minting ctl")
            null
        } else {
            mintInbox(abort)
        }
        if (ctl == null) {
            // The main inbox WAS minted but the pair is being abandoned. That
            // inbox is unpersisted and unshared — nobody but this call frame has ever
            // held its caps — so destroying it is unambiguous (nothing can be lost)
            // and it stops a failed pairing attempt from leaving a live, drainable
            // inbox parked on the relay for its idle-TTL year. Best-effort: a failed
            // DELETE just leaves the orphan we already had.
            deleteInbox(main.inboxId, main.readCapability)
            return@withContext null
        }
        // Abort check again before the THIRD grind — same check, same reason, and it
        // matters MORE here: the pairing PoW cost is now three 20-bit grinds, so a
        // caller whose deadline expired during the first two must not pay a third
        // (ReferralManager's 480 s accept budget is the tight one).
        val grp = if (abort.shouldAbort()) {
            platformLog(LOG_TAG, "mintInboxPair: aborted after the ctl mint — not minting grp")
            null
        } else {
            mintInbox(abort)
        }
        // A FAILED THIRD MINT IS NOT A FAILED PAIRING, and that asymmetry with the
        // ctl mint above is deliberate. The main+ctl pair is everything a pairing
        // NEEDS: the group inbox is an optimisation whose absence is a supported,
        // fully-handled state at every layer — [MintedInboxPair.grp] is nullable,
        // `PairingVault` writes no `*-grp` row, `PairingPayload.buildFull` emits no
        // `gib`/`gwcap`, and `sendGroupText` falls back to [Chan.MAIN]. The backfill
        // then converges it on a later control sweep. Throwing away two good
        // inboxes plus two completed 20-bit grinds — and failing the user's IRL
        // pairing — because a third optional grind timed out would be strictly
        // worse than shipping the pairing in exactly the state every EXISTING
        // pairing is already in.
        if (grp == null) {
            platformLogWarn(
                LOG_TAG,
                "mintInboxPair: the group inbox could not be minted — pairing anyway; the backfill will converge it",
            )
        }
        MintedInboxPair(main, ctl, grp)
    }

    /**
     * Blocks (on the calling background dispatcher) until a cheap relay probe
     * succeeds — i.e. there's a live Tor circuit to the relay — or until either
     * [WARM_PROBE_MAX_WAIT_MS] elapses or [abort] fires. See [WARM_PROBE_TIMEOUT_
     * SECONDS] for the rationale: this front-loads the cheap "is the circuit up?"
     * check so the expensive mint runs on a warm circuit. Returns true once warm,
     * false on timeout/abort (the caller still proceeds to mint — best effort).
     */
    private fun waitForRelayWarm(abort: PowAbort): Boolean {
        // Already proven warm on this transport (the latch is monotonic for its
        // lifetime) — skip the redundant probe round-trip this gate would otherwise
        // pay before EVERY pair mint, even on a session whose health loop / earlier
        // mint already completed the one-off descriptor fetch + rendezvous.
        if (hasCompletedRelayRoundTrip()) return true
        val started = TimeSource.Monotonic.markNow()
        fun withinWarmBudget() = started.elapsedNow().inWholeMilliseconds < WARM_PROBE_MAX_WAIT_MS
        var probe = 0
        while (withinWarmBudget() && !abort.shouldAbort()) {
            val warm = try {
                httpClient.get(relayBaseUrl, timeoutSeconds = WARM_PROBE_TIMEOUT_SECONDS).code > 0
            } catch (_: Exception) {
                false
            }
            if (warm) {
                // Same evidence the health probe latches on: a completed .onion
                // round-trip (see hasCompletedRelayRoundTrip). It is also the same
                // request, so it refreshes the verdict a concurrent health probe
                // would hand a loser (see healthProbeLock) — the mint gate and the
                // health loop must never disagree about the relay being lit.
                markRelayRoundTripCompleted()
                lastHealthProbeResult = true
                if (probe > 0) platformLog(LOG_TAG, "mint warm-gate: circuit up after ${probe + 1} probe(s)")
                return true
            }
            probe++
            // Brief jittered backoff between probes so a flaky guard has time to
            // rotate; cheap GETs, so this isn't a CPU/PoW cost. Bail early if the
            // remaining budget is short rather than oversleeping past the cap.
            if (withinWarmBudget() && !abort.shouldAbort()) {
                sleepMillis(jitterMs(WARM_GATE_POLL_BASE_MS, WARM_GATE_POLL_SPREAD_MS))
            }
        }
        platformLogWarn(LOG_TAG, "mint warm-gate: relay not warm after $probe probe(s) — minting anyway")
        return false
    }

    /** A relay-issued PoW challenge, parsed from the 400 body of POST /inbox. */
    internal class PowChallenge(val nonce: String, val token: String, val difficulty: Int)

    /**
     * Parses the relay's 400 PoW-challenge body. Pragmatic regex, matching the
     * rest of this file. Expected shape (extra fields ignored):
     *
     *   {"error":"…","nonce":"<b64url>","token":"<opaque>","difficulty":N,
     *    "ttlSeconds":N,"algorithm":"sha256","preimage":"nonce:counter"}
     *
     * We need exactly three fields: [nonce] (preimage input, used verbatim),
     * [token] (echoed back unmodified), and [difficulty] (grind target).
     * Returns null on any structural mismatch.
     */
    internal fun parseChallenge(body: String): PowChallenge? = try {
        // Parse via the non-regex depth-1 scanner (parseTopLevelJson),
        // like every envelope/control parser. This is the PRE-AUTH mint handshake on
        // a relay-controlled body, and Kotlin/Native's regex engine is the exact
        // crash-prone path the codebase moved all other parsers off. Same fields,
        // same validation.
        // Via the guarded entry point — this is the PRE-AUTH handshake, so a
        // body that is over the parse bounds (or that kills the scanner) must fail
        // the mint exactly like a malformed one, never the process. null ⇒ every
        // field below reads as absent ⇒ the "malformed or unsafe" branch.
        val m = parseRelayJsonOrNull(body)
        val nonce = m?.get("nonce")?.takeIf { it.isString }?.text
        val token = m?.get("token")?.takeIf { it.isString }?.text
        val diff  = m?.get("difficulty")?.text?.toIntOrNull()
        // Reject control chars (CR/LF/etc.) in relay-controlled fields: the token
        // is echoed verbatim into the X-PoW-Token HTTP header, so a hostile relay
        // embedding CRLF could inject headers/requests on the iOS raw-HTTP
        // transport (OkHttp rejects such values on Android).
        // Bound the LENGTH too — these relay-controlled fields are echoed
        // verbatim into HTTP headers, so an unbounded token/nonce is a parse /
        // header-amplification vector (caps are already length-capped; PoW fields
        // weren't). 256 is far above any legitimate value.
        fun fieldSafe(s: String) = s.length <= MAX_POW_FIELD_LEN && s.none { it.code < 0x20 || it.code == 0x7F }
        if (nonce != null && token != null && diff != null &&
            fieldSafe(token) && fieldSafe(nonce)) {
            PowChallenge(nonce = nonce, token = token, difficulty = diff)
        } else {
            platformLogWarn(LOG_TAG, "mintInbox: malformed or unsafe challenge body")
            null
        }
    } catch (e: Exception) {
        platformLogError(LOG_TAG, "mintInbox: challenge parse failed: ${e::class.simpleName}")
        null
    }

    /**
     * Parses the relay's 201 POST /inbox response. Uses the non-regex depth-1
     * scanner (parseTopLevelJson), like every other parser; this
     * is a pre-auth relay-controlled body. The expected shape is:
     *
     *   {"inboxId":"…","readCapability":"…","writeCapability":"…","expiresAt":N}
     *
     * Both capabilities are shape-checked ([isValidCapability]) so a malformed
     * or truncated relay response can't seed an unusable contact (the
     * old parser accepted any non-empty cap). Returns null on any structural
     * mismatch — caller logs and bails.
     */
    private fun parseMintResponse(body: String): MintedInbox? = try {
        // Guarded entry point, same reason as [parseChallenge] — pre-auth,
        // relay-controlled, and a refusal must read as "malformed response body".
        val m   = parseRelayJsonOrNull(body)
        val id  = m?.get("inboxId")?.takeIf { it.isString }?.text
        val rc  = m?.get("readCapability")?.takeIf { it.isString }?.text
        val wc  = m?.get("writeCapability")?.takeIf { it.isString }?.text
        val ex  = m?.get("expiresAt")?.text?.toLongOrNull()
        if (id != null && rc != null && wc != null && ex != null &&
            isValidInboxId(id) && isValidCapability(rc) && isValidCapability(wc)
        ) {
            MintedInbox(inboxId = id, readCapability = rc, writeCapability = wc, expiresAt = ex)
        } else {
            platformLogWarn(LOG_TAG, "mintInbox: malformed response body")
            null
        }
    } catch (e: Exception) {
        platformLogError(LOG_TAG, "mintInbox: parse failed: ${e::class.simpleName}")
        null
    }

    // -----------------------------------------------------------------------
    // Send — into the peer's inbox using their writeCap
    // -----------------------------------------------------------------------

    /**
     * Sends a message to the contact's outbound inbox (the inbox THEY
     * minted on their device and gave us via QR). Requires the peer's
     * writeCap on the outbound [InboxIdRecord].
     *
     * [noPush] is the sender's opt-in-push-suppression choice (docs/RELAY_SPEC.md,
     * `X-No-Push`): when true, the outbound append carries `X-No-Push: 1` so the relay
     * skips the contentless wake-push it would otherwise enqueue for a
     * registered destination inbox. Default false = the relay's normal push
     * (unaffected by whether the recipient has push registered at all).
     */
    fun sendMessage(contactId: String, plaintext: String, noPush: Boolean = false): Boolean =
        sendEnvelope(contactId, plaintext, extraFieldsJson = "", noPush = noPush)

    /**
     * Sends a group TEXT message to one member over the normal pairwise
     * channel. Identical crypto/counter/padding pipeline to [sendMessage]; the
     * group routing fields live inside the GCM envelope. Note the group fields
     * add 78 bytes, so a copy can land in a HIGHER padding bucket than a 1:1
     * message of the same plaintext — one copy is not byte-identical to a 1:1
     * send. Fan-out across members (with jitter) is
     * GroupManager's job, not this layer's, and the fan-out pattern itself is
     * group-shaped on the wire — see GroupManager's header.
     */
    internal fun sendGroupText(
        contactId: String,
        groupId: String,
        membershipHash: String,
        plaintext: String,
        noPush: Boolean = false,
    ): Boolean = sendGroupTextRouted(contactId, groupId, membershipHash, plaintext, noPush) != GroupTextRoute.FAILED

    /**
     * Which of the pairing's two TEXT channels a group-text copy ACTUALLY went out
     * on. The caller needs the fact, not the intent: the 404 fallback can put a
     * copy on the text inbox even when the group row is present, and the receiver's
     * `KIND_ACTIVITY` notice carries `{"gi":"1"}` **iff the copy really rode the
     * group inbox** — a notice that lies about the inbox would subtract a phantom
     * from the sender's 1:1 badge or leave a real group text
     * unattributed.
     */
    internal enum class GroupTextRoute { GRP, MAIN, FAILED }

    /** @see GroupTextRoute — [sendGroupText] with the route reported. */
    internal fun sendGroupTextRouted(
        contactId: String,
        groupId: String,
        membershipHash: String,
        plaintext: String,
        noPush: Boolean = false,
    ): GroupTextRoute {
        val extraFieldsJson = ""","g":${jsonEscape(groupId)},"h":${jsonEscape(membershipHash)}"""
        // THE capability signal: the peer's group inbox row. Present ⇒ the group
        // text lands on a DIFFERENT relay inbox than a 1:1 text, which is what makes
        // the receiver's contact dot correct by construction. Absent ⇒ a legacy /
        // not-yet-backfilled peer, and this is byte-for-byte today's behaviour.
        // [sendEnvelopeSerialized] re-resolves the same row and falls back on its
        // own, so a row deleted between these two reads is still handled.
        val hasGrp = try {
            databaseManager.getInboxIdForContact(contactId, DIR_OUTBOUND_GRP) != null
        } catch (_: Exception) { false }
        if (!hasGrp) {
            return if (sendEnvelope(contactId, plaintext, extraFieldsJson, noPush = noPush)) {
                GroupTextRoute.MAIN
            } else GroupTextRoute.FAILED
        }
        val status = SendStatus()
        if (sendEnvelope(contactId, plaintext, extraFieldsJson, chan = Chan.GRP, noPush = noPush, status = status)) {
            return GroupTextRoute.GRP
        }
        // 404 on the PEER's group inbox (gone, cap rotated out, or the relay lying).
        // Retry this ONE send on the text inbox and MUTATE NOTHING: we do not delete a
        // row on a relay answer we do not trust, and the peer's own inbound self-heal
        // re-announces a fresh id. Degraded (their contact dot may light for this one
        // message) but never lost. Not a retry-LOOP: postWithTransientRetry treats any
        // real HTTP response as terminal, so this is one explicit second attempt.
        if (!status.inboxGone) return GroupTextRoute.FAILED
        platformLogWarn(
            LOG_TAG,
            "group text: the peer's group inbox answered 404 — retrying this one send on the text inbox",
        )
        return if (sendEnvelope(contactId, plaintext, extraFieldsJson, noPush = noPush)) {
            GroupTextRoute.MAIN
        } else GroupTextRoute.FAILED
    }

    /**
     * Announces OUR inbound inboxes to the peer, in-band:
     * `{"ib":…,"wc":…[,"cib":…,"cwc":…][,"gib":…,"gwc":…],"rv":"2"}` inside the
     * AEAD envelope with control kind "inbox" (no group id).
     *
     * This is what makes the instant-QR pairing flow close: the first QR a
     * device shows carries only its secret half (so it renders with no mint
     * wait), and the device that scanned the peer's FULL code delivers its
     * own (inboxId, writeCap) through the peer's inbox afterwards. The
     * announce is authenticated by the pairwise AEAD and replay-protected by
     * the normal counters, so a peer can only ever (re)direct THEIR OWN
     * channel — it also doubles as an inbox-rotation mechanism.
     *
     * [peerWriteCap] is the write capability the PEER will use on our inbox
     * (from our own mint result — held in memory at pairing time; it is not
     * persisted in the vault). That non-persistence is exactly why EVERY pair
     * here is optional and only "at least one complete pair" is required: a later
     * announce (a group-inbox backfill, a 404 re-mint) physically cannot re-state
     * `wc`, but it CAN state `gwc`, which comes straight out of the mint it just
     * performed. A group-only announce therefore carries `{"gib","gwc","rv"}` and
     * nothing else.
     *
     * PUSH IS ALWAYS SUPPRESSED here — there is no `noPush` parameter to
     * override it (removed: the one shipped Swift caller no longer passes
     * one — see the send below, and the per-kind noPush table in
     * PushRegistration.kt).
     */
    fun sendInboxAnnounce(
        contactId: String,
        // OPTIONAL since the group inbox (see below): a LATER announce physically
        // cannot re-state the text pair, because our own inbound WRITE cap is never
        // persisted — it is held in RAM at pairing only. Both-or-neither.
        myInboxId: String?,
        peerWriteCap: String?,
        // Our CONTROL inbox pair (v7) — optional so pre-v7 callers/tests
        // still work; both-or-neither, like everywhere else.
        myCtlInboxId: String? = null,
        peerCtlWriteCap: String? = null,
        // Our GROUP inbox pair — same shape, same both-or-neither rule. Unlike the
        // text pair this CAN be re-announced later: a re-mint produces a fresh write
        // cap we legitimately hold, which is what makes the group inbox the one inbox
        // in the vault that can be replaced in-band (the 404 self-heal).
        myGrpInboxId: String? = null,
        peerGrpWriteCap: String? = null,
    ): Boolean {
        fun pairOk(id: String?, cap: String?, what: String): Boolean {
            if ((id == null) != (cap == null)) {
                platformLogWarn(LOG_TAG, "inbox announce refused: half-present $what pair")
                return false
            }
            if (id != null && cap != null && (!isValidInboxId(id) || !isValidCapability(cap))) {
                platformLogWarn(LOG_TAG, "inbox announce refused: malformed $what inbox/cap")
                return false
            }
            return true
        }
        if (!pairOk(myInboxId, peerWriteCap, "text")) return false
        if (!pairOk(myCtlInboxId, peerCtlWriteCap, "ctl")) return false
        if (!pairOk(myGrpInboxId, peerGrpWriteCap, "grp")) return false
        val textPart = if (myInboxId != null && peerWriteCap != null) {
            """"ib":${jsonEscape(myInboxId)},"wc":${jsonEscape(peerWriteCap)}"""
        } else ""
        val ctlPart = if (myCtlInboxId != null && peerCtlWriteCap != null) {
            """"cib":${jsonEscape(myCtlInboxId)},"cwc":${jsonEscape(peerCtlWriteCap)}"""
        } else ""
        val grpPart = if (myGrpInboxId != null && peerGrpWriteCap != null) {
            """"gib":${jsonEscape(myGrpInboxId)},"gwc":${jsonEscape(peerGrpWriteCap)}"""
        } else ""
        val pairs = listOf(textPart, ctlPart, grpPart).filter { it.isNotEmpty() }
        if (pairs.isEmpty()) {
            // An announce that declares nothing is not a message; the receiver would
            // drop it anyway (see [applyInboxAnnounce]'s "at least one pair" rule).
            platformLogWarn(LOG_TAG, "inbox announce refused: no complete pair to announce")
            return false
        }
        // The optional role-rule marker. Unconditional (this build always
        // runs rule v2) and LAST, so the existing fields are byte-identical for any
        // reader; every older parser reads bodies field-by-field through
        // [firstStringFieldAnywhere] and simply never asks for it. Costs 10 bytes inside a
        // padded envelope, i.e. nothing on the wire. `gib`/`gwc` sit AFTER the ctl
        // pair and BEFORE `rv` for the same reason.
        val body = "{" + pairs.joinToString(",") +
            ""","$ROLE_RULE_FIELD":${jsonEscape(ROLE_RULE_V2)}}"""
        return sendEnvelope(
            contactId, "",
            extraFieldsJson = ""","k":${jsonEscape(CONTROL_KIND_INBOX)},"b":${jsonEscape(body)}""",
            chan = Chan.CTL,
            // An announce rewrites the PEER's routing, so
            // once the text ratchet is live it MUST ride the ratchet (still posted
            // to the control inbox) — the static sharedSecret key has no
            // post-compromise security, and a vault image would otherwise let an
            // attacker redirect the peer forever. See sendEnvelopeSerialized.
            announce = true,
            // UNCONDITIONALLY suppressed, not merely defaulted: inbound CONTROL
            // inboxes are now part of the push surface ([allPushableInboxes]), and
            // an announce is silent pairing maintenance — both users are already
            // in-app finishing a QR exchange, so a wake buys nothing and an APNs
            // wake is an ALERT push (visible banner + sound), not a silent one.
            // Forced here rather than left to the caller because the one shipped
            // Swift caller passes `noPush: false` explicitly.
            noPush = true,
            // Every control append carries the SAME ttl, so the retention hint
            // stops being a plaintext kind classifier. An announce is rare and small;
            // the extra retention buys the relay nothing it does not already hold.
            ttlSeconds = CONTROL_APPEND_TTL_SECONDS,
        )
    }

    /**
     * Sends a group CONTROL message (invite/join/roster/leave). [bodyJson]
     * is carried as an escaped JSON string in the "b" field so the pragmatic
     * regex envelope parser never has to handle nested JSON structure.
     */
    internal fun sendGroupControl(
        contactId: String,
        groupId: String,
        kind: String,
        bodyJson: String,
        membershipHash: String,
        noPush: Boolean = false,
        // Relay retention override (`?ttl=`), same
        // affordance as [sendDirectControl]. Membership-change kinds pass 7 days
        // so a member who does not open the app for a day still receives the
        // roster/leave that removes someone from their fan-out. null = the
        // relay's 24 h default (activity notices, screenshot notices).
        ttlSeconds: Long? = null,
    ): Boolean = sendEnvelope(
        contactId, "",
        extraFieldsJson = ""","g":${jsonEscape(groupId)},"h":${jsonEscape(membershipHash)},"k":${jsonEscape(kind)},"b":${jsonEscape(bodyJson)}""",
        chan = Chan.CTL,
        noPush = noPush,
        ttlSeconds = ttlSeconds,
        // Invite/join/roster/leave ride the text ratchet once the peer
        // advertised it accepts them; `act`/`screenshot` stay on the static envelope.
        sealedControl = isRatchetSealedControlKind(kind, groupScoped = true),
    )

    /**
     * Sends a DIRECT (non-group) control message — used by ReferralManager for
     * the relayed referral handshake (referral.md). Same envelope shape as the
     * inbox announce (`"k"`/`"b"`, no group id), on the control channel.
     *
     * [noPush] defaults to `false` (= the relay may fire its contentless wake for
     * a push-registered destination inbox). That default is now LOAD-BEARING
     * rather than incidental: since inbound CONTROL inboxes joined the push
     * surface ([allPushableInboxes]), a control kind's wake behaviour is a
     * per-kind product decision made at the CALL SITE — the referral offer/accept
     * legs deliberately wake (they are the half of an introduction the user is
     * waiting on), while the screenshot notice deliberately does not. Every
     * caller states its choice explicitly; see the per-kind table in
     * PushRegistration.kt.
     *
     * [ttlSeconds] asks the relay to retain this blob for that long instead of
     * its 24 h default (`?ttl=`, clamped in [validatedInboxUrl]). `null` = today's
     * behaviour. Referral passes 7 days so the blob cannot expire while the
     * handshake record that consumes it is still alive.
     */
    fun sendDirectControl(
        contactId: String,
        kind: String,
        bodyJson: String,
        noPush: Boolean = false,
        ttlSeconds: Long? = null,
    ): Boolean = sendEnvelope(
        contactId, "",
        extraFieldsJson = ""","k":${jsonEscape(kind)},"b":${jsonEscape(bodyJson)}""",
        chan = Chan.CTL,
        noPush = noPush,
        ttlSeconds = ttlSeconds,
        // The referral handshake (offer, accept and the introducer's relayed
        // accept) rides the text ratchet once the peer advertised it accepts it; the
        // screenshot notice stays on the static envelope.
        sealedControl = isRatchetSealedControlKind(kind, groupScoped = false),
    )

    /**
     * Tells [contactId] that we just took a screenshot of their 1:1 conversation
     * ([CONTROL_KIND_SCREENSHOT]). Body-less: the pairwise channel is the
     * attribution, and the receiver stamps its own local time.
     *
     * BEST-EFFORT, FIRE-AND-FORGET. It rides the ordinary control-envelope
     * pipeline — same AEAD, same counter+epoch anti-replay, same `ch`/`di`
     * binding, same padding buckets, same transient-retry — and returns whether
     * the relay accepted the append purely so tests/logs can see it. A caller
     * must NEVER surface a `false` as a conversation error: a lost notice costs
     * only the notice. Blocking (network) — call from a background dispatcher,
     * like every other send.
     *
     * Non-throwing: any failure below (no contact, no inbox, transport) is already
     * a `false` from [sendEnvelope]; the catch is belt-and-braces so a notice can
     * never take down the caller's send flow.
     *
     * Push is SUPPRESSED (`noPush`): a screenshot notice must not wake the peer's
     * device or produce a "new message" banner for something that is not a
     * message. Moot on a v7
     * pairing (push tokens are registered on inbound TEXT inboxes only, so the
     * relay pushes nothing for a control append) — it matters on the pre-v7
     * fallback, where control traffic rides the main text inbox.
     */
    fun sendScreenshotNotice(contactId: String): Boolean = try {
        // Uniform control ttl (see [CONTROL_APPEND_TTL_SECONDS]). A notice the
        // peer drains days late is still a true statement and is expiry-anchored on
        // THEIR receive clock (ScreenshotNoticeStore), so retention cannot resurrect
        // a notice that already aged out on the receiver.
        sendDirectControl(contactId, CONTROL_KIND_SCREENSHOT, "{}", noPush = true, ttlSeconds = CONTROL_APPEND_TTL_SECONDS)
    } catch (e: Exception) {
        platformLogWarn(LOG_TAG, "screenshot notice send failed: ${e::class.simpleName}")
        false
    }

    /**
     * One send's out-of-band status, for the caller that needs more than a
     * Boolean. Today exactly one does: [sendGroupText]'s 404 fallback has
     * to tell "the peer's group inbox is GONE" from "the relay was unreachable",
     * because only the first justifies re-sending on the text inbox.
     *
     * An out-parameter rather than a richer return type on purpose: every one of
     * [sendEnvelopeSerialized]'s dozen refusal paths already returns `false`, and
     * re-shaping all of them would be a large hunk across the single most
     * security-critical function here for one caller's benefit.
     */
    private class SendStatus {
        /** The relay answered 404 for the destination inbox (gone / wrong cap /
         *  locked — the relay collapses all three). Never set by a transport
         *  failure, a local refusal or any other status. */
        var inboxGone: Boolean = false
        /** [postWithTransientRetry] returned null: every attempt died on the
         *  transport (threw / no HTTP status) or the transport was known down.
         *  Never set by a relay response of any status or by a local refusal. */
        var transportFailed: Boolean = false
    }

    private fun sendEnvelope(
        contactId: String,
        plaintext: String,
        // Extra envelope fields as a PRE-ESCAPED JSON fragment, spliced verbatim
        // between the fixed fields and "m": either "" or a fragment that STARTS WITH a
        // comma (`,"g":…,"h":…`, `,"k":…,"b":…`). Group fields, control kind/body —
        // and, on the ratchet branch, the cap adverts prepended to it.
        extraFieldsJson: String,
        // Which of the pairing's three channels this envelope belongs to. A
        // non-MAIN channel falls back to MAIN when the peer has no such outbound
        // row — a peer paired before the control channel existed, or one that has
        // not announced a group inbox — and the row, the counter space and the
        // sealed `ch` tag then ALL come from the channel actually used.
        chan: Chan = Chan.MAIN,
        // docs/RELAY_SPEC.md `X-No-Push`: sender-side push suppression for this one append.
        noPush: Boolean = false,
        // Relay blob-retention override (`?ttl=`), URL-only — see
        // [validatedInboxUrl]. null = the relay's default.
        ttlSeconds: Long? = null,
        // This envelope is an inbox announce — the one control kind that is
        // allowed (and, once dr-on, required) to take the ratchet branch.
        announce: Boolean = false,
        // @see SendStatus
        status: SendStatus? = null,
        // An integrity-critical control kind ([isRatchetSealedControlKind]) —
        // takes the ratchet branch when the peer advertised it accepts that.
        sealedControl: Boolean = false,
    ): Boolean {
        // "Move to new device" FREEZE GATE. THE single choke point for every
        // contact-facing send — [sendMessage], [sendGroupText], [sendInboxAnnounce],
        // [sendGroupControl] (group control + the membership redrive),
        // [sendDirectControl] (referral handshake) and [sendScreenshotNotice] all
        // funnel through here — so one check covers all of them and none of them can
        // advance the sending ratchet chain after `mig_frozen` is written.
        //
        // Placed BEFORE the send lock and before any vault read, so a frozen send
        // costs nothing and can neither bump the outbound counter nor step the
        // ratchet. `false` is exactly what every caller already handles as "the relay
        // refused it" (the UI shows "not sent"); nothing here throws.
        if (moveFrozen("send")) return false
        // Serialize all sends to this contact (1:1 / group /
        // control all funnel through here) so POST order == counter order. See
        // sendOrderLock for why this is safe against the receive path + deadlock.
        return sendOrderLock(contactId).withLock {
            sendEnvelopeSerialized(contactId, plaintext, extraFieldsJson, chan, noPush, ttlSeconds, announce, status, sealedControl)
        }
    }

    private fun sendEnvelopeSerialized(
        contactId: String,
        plaintext: String,
        extraFieldsJson: String,
        chan: Chan,
        noPush: Boolean = false,
        ttlSeconds: Long? = null,
        announce: Boolean = false,
        status: SendStatus? = null,
        sealedControl: Boolean = false,
    ): Boolean {
        // Freeze gate again, one layer in. [sendEnvelope] is the only caller today,
        // so this is redundant BY DESIGN: it is what keeps a future direct caller of
        // the serialized path (a new send kind, a refactor that skips the lock
        // wrapper) from re-opening the fork hazard silently. One volatile read.
        if (moveFrozen("send")) return false
        // Do NOT log the plaintext length — the padding scheme hides message
        // length from observers; logging the exact char count would defeat it
        // for that record.
        platformLog(LOG_TAG, "sendMessage (${chan.logLabel})")
        val contact = databaseManager.getContact(contactId)
        if (contact == null) { platformLogWarn(LOG_TAG, "send: no contact"); return false }
        // [contact] is a FRESH decode (both actuals) carrying the pairing secret; it is
        // used only inside this send (the static key below, the ratchet branch), so its
        // copy is wiped on every exit instead of waiting for GC.
        try {
            // Channel selection, ONE decision for all five derived values (see [Chan]):
            // a non-MAIN channel wants its own outbound row; absent (a pre-v7 peer, or
            // one that has not announced a group inbox) it falls back to MAIN, and the
            // counter space and the sealed `ch` tag below then come from the channel
            // ACTUALLY used, never from the one the caller asked for.
            val wantedRecord =
                if (chan == Chan.MAIN) null else databaseManager.getInboxIdForContact(contactId, chan.outDir)
            val useChan = if (wantedRecord != null) chan else Chan.MAIN
            val inboxRecord = wantedRecord ?: databaseManager.getInboxIdForContact(contactId, "outbound")
            if (inboxRecord == null) { platformLogWarn(LOG_TAG, "send: no outbound inbox"); return false }
            val writeCap = inboxRecord.cap
            if (writeCap.isNullOrEmpty()) {
                platformLogWarn(LOG_TAG, "outbound inbox has no writeCap — re-pair required")
                return false
            }
            // Defense-in-depth: validate the STORED cap (not just rotated ones)
            // before it goes into the X-Write-Capability header, so a corrupt/legacy
            // row with control chars can never reach raw HTTP/1.1 header
            // construction (CRLF/header injection).
            if (!capValidForHeader(writeCap)) {
                platformLogWarn(LOG_TAG, "outbound writeCap fails header validation — refused")
                return false
            }
            // Validate the inbox ID up-front. validatedInboxUrl() throws on
            // a legacy/corrupt ID and is called only AFTER the anti-replay counter
            // is bumped+persisted below — so without this guard every failed send
            // to such a contact would permanently inflate the counter.
            if (!isValidInboxId(inboxRecord.inboxId)) {
                platformLogWarn(LOG_TAG, "outbound inbox ID not valid — re-pair required")
                return false
            }
            // Reject an over-ceiling message BEFORE any crypto
            // or counter bump — but check the SERIALIZED envelope, not the raw plaintext.
            // A single source byte can escape to \uXXXX (6×) via jsonEscape, so a raw size
            // that passed the old `raw + 128 <= cap` check could still overflow padMessage
            // AFTER escaping — failing the send while an already-persisted anti-replay
            // counter stays bumped (spurious loss + wasted counter on pathological input).
            // epoch/channelTag are hoisted so this probe mirrors the real envelope built
            // below; Long.MAX_VALUE placeholders for the not-yet-known counter/timestamp
            // make it a strict upper bound (real digits are never wider).
            val epoch = messageEpoch(contact.sharedSecret)
            val channelTag = useChan.tag
            // The capability advert every envelope carries (see
            // [CTL_RATCHET_CAP_FIELD]). In the size probe too, so the probe stays a strict
            // upper bound on the legacy envelope; the ratchet envelope (which may add the
            // ≤ 27-byte watermark) drops e/c/ch/di, so it is always smaller than this.
            val capAdvert = if (simulatePreSealedControlBuildForTest) "" else ""","$CTL_RATCHET_CAP_FIELD":"1""""
            val sizeProbeEnvelope =
                """{"e":${jsonEscape(epoch)},"c":${Long.MAX_VALUE},"t":${Long.MAX_VALUE},"ch":"$channelTag","di":${jsonEscape(inboxRecord.inboxId)}$capAdvert$extraFieldsJson,"m":${jsonEscape(plaintext)}}"""
            if (sizeProbeEnvelope.encodeToByteArray().size > MAX_PADDED_PAYLOAD_BYTES) {
                platformLogWarn(LOG_TAG, "message too large to send")
                return false
            }

            // Double Ratchet text path (forward secrecy). Control traffic stays on
            // the static envelope below — see [ratchetManager] note — with TWO
            // exceptions: the integrity-critical control kinds (below, advert-gated)
            // and the inbox ANNOUNCE. It is sealed by
            // the TEXT ratchet (post-compromise security) but POSTed to the control
            // inbox, so the peer's background control sweep applies it promptly and
            // no phantom unread dot appears on the text inbox. A stolen sharedSecret
            // can then no longer forge a routing rewrite once the peer's receive
            // lock is armed (the receiver drops legacy announces after dr-rxlock).
            // The ratchet supplies ordering + replay protection (header N/PN +
            // one-shot keys), so the epoch/counter machinery is skipped here. A null
            // result means the ratchet is not yet ready to send (responder before its
            // first ratchet receive) — fall through to a legacy envelope, which the
            // peer auto-detects by wire format (the accepted bootstrap window).
            // [ttlSeconds] IS threaded through here. It used to be dropped on the
            // ratchet branch on the grounds that "control never takes it" — no longer
            // true since the inbox ANNOUNCE was routed over the text ratchet, and the
            // announce now carries the uniform control ttl. Text sends still pass null,
            // so a 1:1/group TEXT append is byte-identical to before.
            //
            // Read the refusal latch ONCE, BEFORE the ratchet attempt, and
            // apply it AFTER. Reading it first is what makes the send that CROSSES a
            // threshold still go out (it is the evidence, not yet the verdict) while the
            // next one fails; applying it after is what keeps a SUCCESSFUL ratchet send
            // unconditionally unblocked — a refusal stops the DOWNGRADE, never the secure
            // path. One `_meta` read on the steady-state send path.
            // NOTE both of these read the REQUESTED [chan], not the resolved [useChan]:
            // a CONTROL send that fell back to the main inbox (a pre-v7 peer) must stay
            // un-gated by the refusal latch and must stay OFF the ratchet branch, exactly
            // as it was before this channel became a value. Only the tag and the counter
            // follow the inbox actually used.
            val refusedBeforeThisSend = chan.isText && refusalLatched(contactId)
            // An integrity-critical control kind joins the announce on the ratchet
            // branch — but ONLY once this peer has advertised that its control inbox
            // accepts them. An older peer drops every non-announce ratchet blob on its
            // control inbox, so without the advert this stays exactly the older legacy
            // send. Like the announce, gated on the REQUESTED channel.
            val capability = peerCtlRatchetCapability(contactId)
            if (sealedControl && chan == Chan.CTL && capability == null) {
                // Unreadable marker: we cannot tell whether the peer already holds a
                // watermark from us, and a legacy copy above it would be DROPPED there.
                // Fail the send instead — every sealed kind has a retry path (the roster/
                // leave obligations, the `ref_*` accept / relay / offer redrives).
                platformLogWarn(LOG_TAG, "sealed control send deferred: capability marker unreadable")
                return false
            }
            val peerSealsControl = capability == true
            val sealThisControl = sealedControl && chan == Chan.CTL && peerSealsControl
            if ((chan.isText || announce || sealThisControl) && ratchetSendOn(contactId)) {
                // Non-MAIN → post to the resolved row while the TEXT ratchet seals it:
                // the announce onto the control inbox and a group text onto the
                // group inbox both do this. The ratchet instance/role is ALWAYS keyed on
                // the text inbox pair, so there is exactly one chain per contact.
                val postTo = if (chan == Chan.MAIN) null else inboxRecord
                // Every ratchet envelope advertises the capability and — once we
                // hold the peer's — commits to sealing from our CURRENT outbound control
                // counter on. The value must never UNDER-state a counter we already used
                // for a legacy control send (the peer would then drop that genuine blob),
                // so it is the max of the snapshot and a fresh read; over-stating it only
                // loosens the peer's lock, never bricks anything.
                val ratchetAdvert = if (peerSealsControl && !simulatePreSealedControlBuildForTest) {
                    val fresh = try {
                        databaseManager.getContact(contactId)?.let { r -> r.sharedSecret.secureWipe(); r.outboundCtlCounter }
                    } catch (_: Exception) { null }
                    val committedFrom = maxOf(contact.outboundCtlCounter, fresh ?: 0L).coerceAtLeast(0L)
                    capAdvert + ""","$CTL_RATCHET_WATERMARK_FIELD":"$committedFrom""""
                } else capAdvert
                when (sendOverTextRatchet(contactId, contact, ratchetEnvelopeJson(plaintext, ratchetAdvert + extraFieldsJson), noPush, postTo, ttlSeconds, status)) {
                    // A landed ratchet send proves forward secrecy is engaged — clear
                    // the fallback counter (the "consecutive" in its definition).
                    true -> {
                        noteRatchetSendLanded(contactId)
                        // Same convergence arming the legacy path below gives a successful
                        // control send: a ratchet-sealed roster/invite/join must not
                        // drop the poll loop to the 60–90 s idle cadence mid-handshake.
                        if (chan == Chan.CTL) armControlConvergence(progress = true)
                        return true
                    }
                    false -> return false
                    // The ratchet has no sending chain (responder pre-bootstrap, or a
                    // relay dropping the peer's ratchet blobs to keep it that way). We fall
                    // through to legacy — refusing a TRANSIENT drop would let the relay
                    // silence the conversation — and count it, up to the threshold, past
                    // which the role-collision gate below turns the same evidence into a refusal.
                    // A sealed CONTROL kind falls through the same way but is NOT
                    // counted: the counter's threshold arms the TEXT refusal, and a burst of
                    // membership control must not move a text verdict. (The peer holds no
                    // watermark from us yet — that needs a ratchet blob from us, i.e. a
                    // sending chain, which is exactly what is missing here — except after
                    // the onCorruptReinit local-corruption path, the same known
                    // limitation as the sticky text lock.)
                    null -> if (chan.isText || announce) noteRatchetFallbackToLegacy(contactId)
                }
            }

            // A REFUSED contact never falls through to the static envelope.
            // Reached only by a TEXT send (1:1 or group) that did not leave on the ratchet
            // — either the ratchet had no sending chain (the both-Bob collision this
            // refusal exists for) or `dr-on` is not set (e.g. cleared by onCorruptReinit
            // after the refusal armed). CONTROL traffic is deliberately NOT gated: its
            // static-envelope path is the designed fallback for every contact (the
            // sealed kinds included, while the peer has not advertised or we hold no
            // sending chain), so there is no downgrade to refuse, and blocking it would
            // break group-membership convergence, the
            // referral handshake and the inbox announce that a re-pair needs.
            //
            // The failure shape is the existing one — `false`, exactly what a relay refusal
            // produces — because a thrown exception crossing the non-`@Throws` Swift bridge
            // SIGABRTs iOS. [ratchetRefused] is what tells the UI why. Counts only in the
            // log line, never an identifier.
            if (refusedBeforeThisSend) {
                platformLogWarn(
                    LOG_TAG,
                    "send refused: the secure channel never established for this contact " +
                        "(ratchet role collision) — re-pair required",
                )
                return false
            }

            // Anti-replay: stamp a per-contact monotonic counter and
            // the shared-secret epoch inside the GCM envelope. Persist the
            // bumped counter to the vault BEFORE sending so a crash can only
            // skip a counter (receiver tolerates gaps), never reuse one (which
            // the receiver would reject as a replay).
            // Fail CLOSED if the bumped counter can't be persisted. iOS now THROWS
            // on a vault write failure (execChecked); returning false here means
            // we neither send nor advance the counter, rather than crashing the app
            // (uncaught Kotlin->Swift exception = SIGABRT) or sending with an
            // unpersisted counter a later crash could reuse (replay). Mirrors the
            // inbound counter-persist guard.
            // Derive+persist the counter under the per-contact lock, re-reading
            // the row fresh INSIDE the lock. The `contact` snapshot above was read
            // before this critical section, so a concurrent send/poll could have
            // advanced a counter since; using the stale value would reuse an outbound
            // counter (receiver drops as replay) or clobber a sibling counter.
            val counter: Long?
            try {
                counter = counterLock(contactId).withLock {
                    // Re-read under the lock; if the contact was DELETED
                    // between the snapshot at the top of this send and here, ABORT rather than
                    // fall back to the stale snapshot and RESURRECT it (re-persisting its key
                    // material). Small window on send (no network in between), but the same
                    // resurrection class as the poll path — fixed on both for sibling parity.
                    val fresh = databaseManager.getContact(contactId) ?: return@withLock null
                    try {
                        val next = useChan.outCounterOf(fresh) + 1
                        databaseManager.insertContact(useChan.withOutCounter(fresh, next))
                        next
                    } finally {
                        // The insert has bound the bytes; this decoded copy is dead.
                        fresh.sharedSecret.secureWipe()
                    }
                }
            } catch (e: Exception) {
                platformLogError(LOG_TAG, "outbound counter persist failed — not sending: ${e::class.simpleName}")
                return false
            }
            if (counter == null) {
                platformLogWarn(LOG_TAG, "contact gone mid-send — not sending (not resurrecting)")
                return false
            }

            // Derived only AFTER the counter-persist exits above, so every early `return false`
            // leaves no live copy of the static key/AAD in RAM: from here on the only exit is
            // the encrypt below, whose `finally` wipes both.
            val encryptionKey = sha256(contact.sharedSecret)
            val aeadContext = sha256WithLabel(encryptionKey, "message-aead".encodeToByteArray())

            // Format: {"e":"<epoch>","c":<counter>,"t":<millis>,"ch":"<m|c|g>","di":"<inbox>"[,group fields][,"cr"/"crw" adverts],"m":"<text>"}
            // "ch" binds the blob to the inbox-channel it was sealed for; "di"
            // binds it to the DESTINATION inbox id so the relay can't cross-splice/reflect it
            // between this pairing's inboxes. Both are sealed inside the AEAD.
            // (epoch + channelTag hoisted above for the size probe.)
            // `capAdvert` ("cr") rides every legacy envelope too — it is how a peer
            // that has not engaged the ratchet yet still learns we accept sealed control.
            // The watermark never rides a legacy envelope: a static-key forger could mint
            // one, so the receiver honours it only off a ratchet blob.
            val envelope =
                """{"e":${jsonEscape(epoch)},"c":$counter,"t":${roundTimestampToMinute(currentTimeMillis())},"ch":"$channelTag","di":${jsonEscape(inboxRecord.inboxId)}$capAdvert$extraFieldsJson,"m":${jsonEscape(plaintext)}}"""

            val encryptedBlob = try {
                aesGcmEncrypt(
                    plaintext = padMessage(envelope.encodeToByteArray()),
                    key = encryptionKey,
                    associatedData = aeadContext
                )
            } catch (e: Exception) {
                platformLogError(LOG_TAG, "encrypt failed: ${e::class.simpleName}")
                return false
            } finally {
                // Wipe the derived legacy key + AAD once consumed,
                // matching DoubleRatchet's key hygiene (the ratchet wipes every key in
                // finally; the static-key path left them live in RAM on every send).
                encryptionKey.secureWipe()
                aeadContext.secureWipe()
            }

            val inboxId = inboxRecord.inboxId
            val url = validatedInboxUrl(inboxId, ttlSeconds = ttlSeconds)
            platformLog(LOG_TAG, "sending ${encryptedBlob.size}b to the ${useChan.logLabel} inbox")

            // Idempotent transient retry via the shared helper — the SAME discipline
            // the ratchet text path uses, so no send path can silently drop. The
            // monotonic counter was sealed + persisted above, so re-POSTing the same
            // blob is replay-safe.
            val result = postWithTransientRetry(url, encryptedBlob, sendHeaders(writeCap, noPush), useChan.logLabel)
            // Transport-class failure (no HTTP status at all) — the re-drive's input.
            if (result == null) status?.transportFailed = true
            // The relay ACCEPTED an append to this outbound inbox — positive proof it
            // still holds it, so the row's informational lease may be re-stamped. Only on
            // a real 2xx; a 404 (inbox reaped) must keep falling through to the re-pair
            // signal instead.
            if (result?.isSuccess == true) noteInboxProvenLive(inboxRecord)
            // Report a 404 for THIS destination inbox to the caller that asked.
            // Only a real 404 — a transport drop leaves it false, because "unreachable"
            // is not evidence that an inbox is gone.
            if (result?.code == 404) status?.inboxGone = true
            // A successful control send opens a convergence window: we now expect a
            // reply (roster/join ack), so the poll loop follows up FAST instead of
            // idling (see [controlPollDelayMs]). OUR OWN send, so it counts as
            // PROGRESS — the episode bound exists to stop a hostile PEER from
            // pinning the fast cadence, never to throttle work this device initiated.
            if (chan == Chan.CTL && result?.isSuccess == true) armControlConvergence(progress = true)
            return result?.isSuccess == true
        } finally {
            contact.sharedSecret.secureWipe()
        }
    }

    /**
     * Builds the outbound POST /inbox headers: the write cap plus, when
     * [noPush] is set, `X-No-Push: 1` (docs/RELAY_SPEC.md) so the relay
     * skips the contentless wake-push it would otherwise enqueue for a
     * registered destination inbox. Omitted (not "0") when false so a relay
     * that only checks header presence sees identical bytes to pre-Phase-3
     * clients.
     */
    private fun sendHeaders(writeCap: String, noPush: Boolean): Map<String, String> =
        if (noPush) mapOf(WRITE_CAP_HEADER to writeCap, NO_PUSH_HEADER to "1")
        else mapOf(WRITE_CAP_HEADER to writeCap)

    /**
     * POST [body] to [url] with idempotent transient-retry (Tor-resilience). A
     * dropped POST — an exception or code <= 0 — would otherwise SILENTLY LOSE
     * the copy (the group fan-out never re-sends a failed member copy; a ratchet
     * text has already advanced its chain, so the plaintext is unrecoverable).
     * Re-POSTing the SAME bytes up to [SEND_TRANSIENT_ATTEMPTS] is safe ONLY
     * because every caller passes a REPLAY-SAFE body: the static envelope seals a
     * persisted monotonic counter, and a ratchet wire carries a header the
     * receiver drops on replay — so a duplicate that two arrivals produce is
     * dropped receive-side. Only a transport drop retries; a real HTTP response
     * (2xx/4xx/5xx) is terminal. Returns that final [HttpResult], or null once
     * transient retries are exhausted.
     */
    private fun postWithTransientRetry(
        url: String, body: ByteArray, headers: Map<String, String>,
        // A fixed word naming the destination ("text" / "control" / "group" / "move")
        // — never an inbox id.
        logLabel: String,
    ): HttpResult? {
        // Bound the WALL CLOCK, not just the attempt
        // count. This whole loop runs inside sendOrderLock(contactId) — held to keep
        // POST order == counter order — so on a cold/dead circuit four attempts at
        // the 60 s HTTP timeout plus backoff could hold that per-contact lock for
        // ~4 minutes, stalling every other send to the same contact (including each
        // group fan-out copy) behind one wedged circuit. Attempts still stop early
        // on their own; this only caps how long a caller can be made to wait.
        val deadline = currentTimeMillis() + SEND_TRANSIENT_BUDGET_MS
        repeat(SEND_TRANSIENT_ATTEMPTS) { attempt ->
            if (attempt > 0 && currentTimeMillis() >= deadline) {
                platformLogWarn(
                    LOG_TAG,
                    "send budget spent after ${attempt} attempt(s) ($logLabel) — releasing the send lock",
                )
                return null
            }
            // COLD-AWARE per-attempt budget, evaluated PER ATTEMPT rather than once
            // per call: the latch is flipped by whichever cheap GET completes the
            // first rendezvous (the health loop, the mint warm-gate, a control
            // peek), any of which can land WHILE this loop is retrying — and the
            // very next attempt should then get the full steady-state budget. See
            // [SEND_COLD_TIMEOUT_SECONDS].
            val timeout =
                if (hasCompletedRelayRoundTrip()) DEFAULT_RELAY_HTTP_TIMEOUT_SECONDS
                else SEND_COLD_TIMEOUT_SECONDS
            val result = try {
                httpClient.post(url, body, CONTENT_TYPE, headers, timeout)
            } catch (e: Exception) {
                // Class name only: a transport exception's MESSAGE can embed the relay
                // host (see the CODE ONLY note in the relay probe).
                platformLogWarn(LOG_TAG, "send threw ($logLabel, attempt ${attempt + 1}/$SEND_TRANSIENT_ATTEMPTS, budget=${timeout}s): ${e::class.simpleName}")
                null
            }
            if (result != null && result.code > 0) {
                platformLog(
                    LOG_TAG,
                    // CODE ONLY, like the relay probe: the body is never logged.
                    "send → code=${result.code} ($logLabel)",
                )
                return result
            }
            // KNOWN-DOWN fail-fast (resilience:tor-death): the owner has told this
            // instance its transport is gone, so the remaining attempts would only
            // hit a dead SOCKS port and spend the budget the user waits on. Stop
            // after the attempt that just failed — the transport-back re-drive owns
            // recovery. Checked AFTER an attempt, never before the first one, so a
            // stale flag still costs exactly one cheap attempt rather than a
            // silent refusal. Fixed phrase + a count; no identifier.
            if (transportLost) {
                platformLogWarn(
                    LOG_TAG,
                    "send stopped after ${attempt + 1} attempt(s) — transport is known down, leaving it to the transport-back re-drive",
                )
                return null
            }
            // Transport drop (threw or code <= 0) → brief backoff, re-POST same bytes.
            if (attempt < SEND_TRANSIENT_ATTEMPTS - 1) sendRetrySleep(jitterMs(SEND_RETRY_BACKOFF_BASE_MS, SEND_RETRY_BACKOFF_SPREAD_MS))
        }
        platformLogWarn(LOG_TAG, "send exhausted $SEND_TRANSIENT_ATTEMPTS transient retries ($logLabel)")
        return null
    }

    // -----------------------------------------------------------------------
    // Poll — out of our own inbox using our readCap
    // -----------------------------------------------------------------------

    /**
     * Polls our inbound inbox for new messages.
     *
     * The relay's GET /inbox/{id} drains the queue but does NOT destroy the
     * inbox; the inbox lives on across drains and the peer's writeCap stays
     * valid indefinitely. (This is the persistent-channel behaviour: one IRL
     * pairing enables ongoing messaging.)
     *
     * On 404 we back off silently. The new server collapses NOT_FOUND,
     * UNAUTHORIZED, and LOCKED into one identical 404 response, so we can
     * neither distinguish nor self-heal. A persistent 404 means the inbox is
     * really gone (expired or deleted) or our cap was rotated out from under
     * us by an attacker — either way the only fix is re-pair IRL.
     *
     * On 429 we back off silently too (rate-limited or transient lock-out).
     */
    fun pollMessages(contactId: String): List<ReceivedMessage> = pollChannel(contactId, Chan.MAIN)

    /**
     * Drains the CONTROL inbox for [contactId] (group control + announces).
     * Safe to call any time — control traffic has no relay-retention
     * requirement, unlike texts. No ctl inbox (pre-v7 pairing) → no-op.
     */
    fun pollControlMessages(contactId: String): List<ReceivedMessage> = pollChannel(contactId, Chan.CTL)

    /**
     * Drains the GROUP-text inbox for [contactId].
     *
     * Same leased drain, same anti-replay rules and the same ratchet chain as
     * [pollMessages] — only the inbox and the counter space differ. A pairing with
     * no `inbound-grp` row (legacy, or not yet backfilled) is a NETWORKLESS no-op,
     * exactly as [pollControlMessages] is for a pre-v7 pairing, so such a contact
     * can never record a group-channel 404 or a streak.
     *
     * Its caller is the conversation-poll layer (GRP-DRAIN-1: a poll drains BOTH of
     * a contact's text inboxes together, which is what keeps skipped ratchet keys at
     * today's level). Blocking (vault + network) — background dispatcher only.
     */
    fun pollGroupInbox(contactId: String): List<ReceivedMessage> = pollChannel(contactId, Chan.GRP)

    // Wall-clock (ms) of the last control-channel ARM — a successful control send
    // (sendEnvelopeSerialized) or a QUALIFYING received control message
    // ([noteControlActivity], called by GroupManager.ingest). Drives the fast/idle
    // poll cadence decision. Injectable clock seam, same pattern and same reason as
    // [relayLostClockMs]: the episode bound is a 10-minute property and a unit
    // test must drive it without real waits.
    private var lastControlActivityAtMs: Long = 0L

    // When the CURRENT fast episode began. An episode starts on the first arm
    // after the window lapsed, and is re-anchored by an arm that carried PROGRESS.
    private var fastEpisodeStartedAtMs: Long = 0L

    internal var controlConvergenceClockMs: () -> Long = { currentTimeMillis() }

    /**
     * Delay (ms) the platform control-poll loop should wait before its NEXT
     * cycle. FAST (jittered, a few seconds — [CONTROL_POLL_FAST_BASE_MS]) while a
     * convergence round-trip is active, IDLE (jittered 60–90 s, the anti-traffic-
     * analysis default) once quiet. [convergingNow] is the caller's per-cycle
     * signal that a join→roster→resolve chain is in flight — it should be true
     * when THIS cycle received control traffic OR the device still has unresolved
     * group members ([GroupManager.hasUnresolvedMembers]); a recent control SEND
     * (marked in sendEnvelope) also keeps the window open to catch the reply.
     * Gating on pending resolution — not just our own sends — is what makes
     * member↔member convergence RELIABLE: iosMember keeps polling fast until the
     * admin's roster actually lands, instead of idling out mid-round-trip and
     * stalling past the 6-min budget. Shared so Android and iOS poll identically.
     *
     * **(2026-09-16) [convergingNow] no longer RE-ARMS the persistent
     * window — it decides THIS cycle only.** Both platforms pass
     * `received || hasUnresolvedMembers()`, and `received` is true for ANY drained
     * blob, including a group control whose kind is unknown and discarded. Arming a
     * 60 s global window off that let one paired contact hold the device in 2.5–5 s
     * sweeps forever with one POST a minute — and, worse, hold
     * [isControlConverging] true, which disables the peek-before-drain for EVERY
     * contact and turns every sweep into an unconditional drain. The
     * half that is legitimate is preserved exactly: a cycle that reports
     * `convergingNow` still gets ONE fast follow-up (that is all
     * `hasUnresolvedMembers()` — itself bounded — ever needed), while the
     * persistent window is armed only by [noteControlActivity] / a control send.
     *
     * **2026-10-01: both platforms now pass
     * `received || hasUnresolvedMembers() || isGroupConversationForeground()`** —
     * the fourth arming condition (`GroupManager.setGroupConversationForeground`),
     * per cycle only, by the same rule: it never reaches [armControlConvergence].
     */
    fun controlPollDelayMs(convergingNow: Boolean): Long {
        val converging = convergingNow || isControlConverging()
        return if (converging)
            jitterMs(CONTROL_POLL_FAST_BASE_MS, CONTROL_POLL_FAST_JITTER_MS)
        else
            jitterMs(CONTROL_POLL_IDLE_BASE_MS, CONTROL_POLL_IDLE_JITTER_MS)
    }

    /**
     * True while the control channel is inside its CONVERGENCE window — the state
     * [controlPollDelayMs] uses to pick the FAST cadence (a control send, or a
     * QUALIFYING received control message, within [CONTROL_CONVERGENCE_WINDOW_MS])
     * AND inside the [CONTROL_FAST_EPISODE_MAX_MS] episode bound.
     *
     * READ-ONLY, and that is the point: the only writers are [armControlConvergence]'s
     * three callers (a control send, [noteControlActivity], [notePairingAwaitingPeer]),
     * so this can be used as a predicate. The control sweep asks it to
     * decide whether a `/peek` before the drain is worth an extra round-trip: while
     * converging, a join→roster→resolve chain is in flight and traffic is EXPECTED,
     * so the probe would only add an RTT per hop to the exchange the fast window
     * exists to accelerate. See [GroupManager.pollAllControls].
     *
     * The SECOND term is the absolute episode bound
     * ([GroupManager.UNRESOLVED_MEMBER_FAST_WINDOW_MS] has the identical shape and
     * rationale). Without it, an arm every 50 s keeps the 60 s window permanently
     * open — "bounded by a window that any arm re-opens" is not a bound. An episode
     * therefore expires [CONTROL_FAST_EPISODE_MAX_MS] after it started **regardless
     * of re-arms**, and only two things restart it: the window genuinely lapsing
     * (no arm for [CONTROL_CONVERGENCE_WINDOW_MS]) or an arm that carried PROGRESS
     * — this device's own control send, or a received control message that actually
     * mutated group state. Peer noise produces neither.
     */
    internal fun isControlConverging(): Boolean {
        val now = controlConvergenceClockMs()
        // Fail toward FAST on a backward clock step (the pre-episode-cap behaviour): a
        // cadence must never be frozen idle by an NTP correction, and the bound
        // exists to stop a remote pin, not to police the clock.
        if (now < lastControlActivityAtMs || now < fastEpisodeStartedAtMs) return true
        if (now - lastControlActivityAtMs >= CONTROL_CONVERGENCE_WINDOW_MS) return false
        return now - fastEpisodeStartedAtMs < CONTROL_FAST_EPISODE_MAX_MS
    }

    /**
     * Reports control-channel ACTIVITY without asking for a delay — the write half of
     * the window [isControlConverging] reads.
     *
     * It exists because neither existing entry point fits a caller that only wants to
     * SAY "control traffic just landed": [controlPollDelayMs] decides a cadence (so a
     * caller would have to discard a delay it never wanted), and [isControlConverging]
     * is deliberately read-only.
     *
     * **Who may call it: only a QUALIFYING arrival.** `GroupManager.ingest`
     * arms it for a group-membership control kind (roster / leave / invite / join)
     * from a contact that is a member of at least one group this device knows, OR
     * while this device still has a window-bounded unresolved member, OR while an
     * invite from that contact is parked awaiting consent — the only traffic a fast
     * follow-up can actually help converge. Everything else (an activity notice, a
     * screenshot notice, an unknown kind, a 1:1 text misrouted onto the control inbox)
     * must NOT arm it: that was the pin. The two extra admissions (2026-09-17) exist
     * because "is a RESOLVED member" is false for exactly the peer whose slot is still
     * unresolved and for a first invite, i.e. the two cases that need the fast window
     * most; both are themselves bounded (the 10 min fast window / the user's consent
     * + the forced-join invite caps), so a chatty stranger still arms nothing.
     *
     * [progress] says the arrival MOVED group state (the epoch, the member set or
     * the resolved-member count changed, or this is our own send). Progress
     * re-anchors the episode bound in [isControlConverging]; a bare arm does not.
     */
    internal fun noteControlActivity(progress: Boolean = false) = armControlConvergence(progress)

    // When the Add-contact scan-back screen last ticked [notePairingAwaitingPeer];
    // a gap of [CONTROL_CONVERGENCE_WINDOW_MS] or more separates two VISITS.
    private var lastPairingWaitTickMs: Long = 0L
    // The contact that screen is waiting on (its [notePairingAwaitingPeer] argument);
    // read by the control sweep to peek that contact first — see [pairingAwaitingContactId].
    private var pairingAwaitingContactId: String? = null

    /**
     * The Add-contact "Almost there" (scan-back) screen ticks this — once a second,
     * only while that state is showing — on both platforms (iOS `AddContactView`'s
     * 1 Hz timer, Android `AddContactScreen`'s announce-watch loop).
     *
     * **Why (2026-09-27, `pairing-two-scan.multi.spec.ts`, measured 69 s on a
     * hermetic relay):** in the two-scan flow the pairing completes OFF-SCREEN —
     * the peer scans our full code and their inbox reaches us as an in-band
     * [CONTROL_KIND_INBOX] announce applied by the background control sweep. The
     * announce lands on the relay within a second, but nothing on the waiting side
     * armed the fast cadence, so the user sat on that screen for a whole idle
     * interval (60–90 s) plus a Tor round-trip. This arm opens the fast window;
     * [controlPollIdleWaitShouldEnd] lets a loop already asleep in its idle wait
     * act on it at once.
     *
     * **Bound:** only the FIRST tick of a visit is PROGRESS — it is a local,
     * user-attended event, the same standing as our own control send — and every
     * later tick inside the same visit is a bare arm. One visit therefore gets the
     * fast cadence for at most [CONTROL_FAST_EPISODE_MAX_MS] and then falls back to
     * the idle loop, exactly the ceiling peer noise gets; a user who leaves the
     * screen up for an hour is not a permanent 2.5–5 s Tor beacon. A visit begins
     * when the previous tick is at least [CONTROL_CONVERGENCE_WINDOW_MS] old (the
     * screen was left and the window lapsed), so pairing a second contact later is
     * a fresh episode. Costs nothing on the wire by itself.
     */
    fun notePairingAwaitingPeer() = notePairingAwaitingPeer(null)

    /**
     * [contactId] (2026-10-26): the half-paired contact the screen is waiting on,
     * so the control sweep can peek THAT inbox first instead of wherever the
     * shuffle put it — measured on a production pairing: the announce sat on the
     * relay 8 s into a 21 s sweep over 13 contacts. Null keeps the old behaviour.
     */
    fun notePairingAwaitingPeer(contactId: String?) {
        val now = controlConvergenceClockMs()
        val newVisit = now < lastPairingWaitTickMs ||
            now - lastPairingWaitTickMs >= CONTROL_CONVERGENCE_WINDOW_MS
        lastPairingWaitTickMs = now
        pairingAwaitingContactId = contactId
        armControlConvergence(progress = newVisit)
    }

    /**
     * The contact the Add-contact scan-back screen is waiting on, or null when
     * that screen is not showing (no tick within [CONTROL_CONVERGENCE_WINDOW_MS])
     * or it never named one. Read by `GroupManager.pollAllControls` to order the
     * sweep; a RAM hint only, never persisted.
     */
    internal fun pairingAwaitingContactId(): String? {
        val id = pairingAwaitingContactId ?: return null
        val now = controlConvergenceClockMs()
        return if (now >= lastPairingWaitTickMs && now - lastPairingWaitTickMs < CONTROL_CONVERGENCE_WINDOW_MS) id else null
    }

    /**
     * Asked by the platform control loops ONCE A SECOND while they sleep out a
     * delay [controlPollDelayMs] handed them: true means "end the wait now and run
     * the next sweep". It is true only for an IDLE wait (one at or above
     * [CONTROL_POLL_IDLE_BASE_MS]) during which the convergence window opened —
     * [notePairingAwaitingPeer], or our own control send from the UI mid-sleep. A
     * FAST wait is never cut: [isControlConverging] is true for its whole duration
     * by construction, so cutting it would collapse the 2.5–5 s cadence into a 1 s
     * busy loop. A quiet idle wait runs its full jittered course, so the idle
     * cadence a traffic observer sees is unchanged.
     *
     * [fastWantedNow] is the caller's per-slice view of the PER-CYCLE fast
     * conditions that live outside this class — today only the fourth arming
     * condition, `GroupManager.isGroupConversationForeground()` (2026-10-01): a
     * device asleep in a 60–90 s idle wait must sweep within a slice of the user
     * opening a group conversation. It is read, never stored: it arms nothing, so
     * [isControlConverging] and the peek-before-drain are untouched, and the same
     * IDLE-only rule applies (the FAST wait the next cycle then picks is never cut).
     * Kotlin default arguments do not cross the Swift bridge, so iOS passes it
     * explicitly.
     */
    // Also true ONCE per newly marked sealed-control catch-up (see
    // [sealedControlCatchUp]) — same IDLE-only rule, so a FAST wait is never cut.
    fun controlPollIdleWaitShouldEnd(chosenDelayMs: Long, fastWantedNow: Boolean = false): Boolean =
        chosenDelayMs >= CONTROL_POLL_IDLE_BASE_MS &&
            // A sealed-control catch-up wake is consumed LAST and only when
            // nothing else already ends the wait, so it fires at most once per mark.
            (fastWantedNow || isControlConverging() || consumeSealedControlWake())

    private fun armControlConvergence(progress: Boolean) {
        val now = controlConvergenceClockMs()
        val lapsed = now < lastControlActivityAtMs || now - lastControlActivityAtMs >= CONTROL_CONVERGENCE_WINDOW_MS
        if (progress || lapsed) fastEpisodeStartedAtMs = now
        lastControlActivityAtMs = now
    }

    /**
     * Non-destructively asks the relay how many blobs are queued in
     * [contactId]'s INBOUND TEXT inbox, via `GET /inbox/{id}/peek`. Returns
     * the count, or null on any failure (no inbox, stale cap, 404/429, parse
     * error) — null means "unknown", never treat it as zero-with-confidence.
     *
     * Unlike [pollMessages], peek does NOT drain: unread texts deliberately
     * survive on the relay until their conversation is opened (an app exit
     * must not destroy them), and peek preserves that — it is purely an
     * "is there something waiting?" probe for the contact-list unread badge.
     * This method never peeks the control inbox (control is not user-visible
     * "unread"); the control sweep's peek-before-drain is [peekControlPending].
     */
    fun peekInbox(contactId: String): Int? {
        // Freeze gate: `null` is the documented "unknown" answer every caller already
        // handles by showing no badge. A peek does not drain and does not step the
        // ratchet, but it is a capability-authenticated call on a CONTACT inbox the
        // new phone is about to own, and the iOS unread sweep makes it on this object
        // directly (AppState.swift), bypassing the session-layer provider gate.
        if (moveFrozen("unread peek")) return null
        if (!contactExists(contactId)) return null
        val inboxRecord = databaseManager.getInboxIdForContact(contactId, "inbound") ?: return null
        val readCap = inboxRecord.cap ?: return null
        val outcome = peekOnce(inboxRecord.inboxId, readCap)
        if (!outcome.live) return null
        // A 2xx peek proves this inbound TEXT inbox is alive. It matters that peek
        // is a refresh point at all: a contact whose conversation is never opened is
        // only ever peeked (the text inbox is deliberately not drained), so without
        // this its lease would be the one nothing renews.
        noteInboxProvenLive(inboxRecord)
        return outcome.pending
    }

    /**
     * The PURE-HTTP `/peek` against an ALREADY-RESOLVED inbox ref: byte-for-byte the
     * same request [peekInbox] makes (same `/peek` path, same `X-Read-Capability`
     * header, same cap/inbox-id validation before either enters a header, same
     * depth-1 body parse) — both delegate to [peekOnce], so the two can never drift
     * — with every vault-touching side effect removed:
     *
     *  - **NO vault read.** The `(inboxId, readCap)` pair comes from the caller's
     *    up-front snapshot ([inboundTextPeekTargets]). That is what makes several of
     *    these safe to run CONCURRENTLY: `VaultDatabase` thread-safety under
     *    genuinely concurrent access is unproven on both platforms, and the parallel
     *    prime must not become its first concurrent caller.
     *  - **NO vault write.** The lease re-stamp ([noteInboxProvenLive]) is
     *    deliberately skipped — it is roughly once-a-year hygiene which the
     *    steady-state [peekInbox] sweep still performs on these very same inboxes.
     *  - **NO relay-loss bookkeeping, NO re-pair flagging, NO retries.** An in-flight
     *    read-capability rotation makes a peek 404 TRANSIENTLY (the union
     *    {record cap, pending marker} holds the live cap, and the reconcile settles
     *    it on the next poll). That is harmless here only because this records no
     *    404 streak ([noteRelay404]) and its caller emits nothing on a null — do not
     *    "improve" it with retries or streak marking; those two absences ARE the
     *    safety property.
     *
     * Returns the pending-blob count, or null on ANY failure (404 / 429 / transport
     * timeout / malformed body). Blocking — call from a dispatcher that tolerates
     * blocking I/O. See [GroupManager.primeUnreadCounts], the only caller.
     */
    internal fun peekInboxRef(inboxId: String, readCap: String): Int? {
        // Freeze gate on the connect-time unread prime's PURE-HTTP peek. Its caller
        // ([GroupManager.primeUnreadCounts]) already sits behind the session-layer
        // provider gate, but this method takes a pre-resolved (inboxId, readCap) pair
        // and therefore needs no vault at all — exactly the shape that outlives a
        // teardown. `null` = "unknown", which the prime emits nothing for.
        if (moveFrozen("unread prime peek")) return null
        return peekOnce(inboxId, readCap).pending
    }

    /**
     * One `/peek` outcome. [live] is true iff the relay answered 2xx WITH a body —
     * the proof-of-life that justifies the lease re-stamp; [pending] is the
     * parsed count, null when the body carried no readable `pending` field.
     */
    private class PeekOutcome(val live: Boolean, val pending: Int?)

    /**
     * The single request shape behind [peekInbox] and [peekInboxRef]. Validates the
     * stored cap + inbox id before either reaches an HTTP header / [validatedInboxUrl]
     * (the CRLF-injection + uncaught-throw guard every relay call site applies), then
     * `GET /inbox/{id}/peek` and reads `pending` off the body.
     *
     * NEVER a bare `GET /inbox/{id}` — that DRAINS the inbox, which would silently
     * destroy exactly the queued messages this probe exists to count. Touches no
     * vault state at all, so it is safe from several coroutines at once.
     */
    private fun peekOnce(inboxId: String, readCap: String): PeekOutcome {
        if (readCap.isEmpty() || !capValidForHeader(readCap)) return PeekOutcome(false, null)
        if (!isValidInboxId(inboxId)) return PeekOutcome(false, null)
        val url = validatedInboxUrl(inboxId, "/peek")
        val result = try {
            httpClient.get(url, headers = mapOf(READ_CAP_HEADER to readCap))
        } catch (e: Exception) {
            platformLog(LOG_TAG, "peek failed: ${e::class.simpleName}")
            return PeekOutcome(false, null)
        }
        // 404 (gone/wrong cap/locked) and 429 (rate limited) are both "unknown".
        if (!result.isSuccess || result.body == null) return PeekOutcome(false, null)
        // Non-regex parse — this is a raw MALICIOUS-RELAY response on
        // every background poll, exactly the surface the codebase keeps off
        // Kotlin/Native's recursive regex engine. parseTopLevelJson is depth-1 and
        // stack-safe.
        // …and bounded, via the guarded entry point. A refused or failed parse
        // is a RELAY ERROR — the same PeekOutcome(false, null) a non-2xx yields, so
        // it is never read as "empty", never re-stamps the lease, and can never
        // be an OutOfMemoryError that escapes the poll path's Exception catches.
        val fields = parseRelayJsonOrNull(result.body) ?: return PeekOutcome(false, null)
        return PeekOutcome(true, fields["pending"]?.text?.toIntOrNull())
    }

    // -----------------------------------------------------------------------
    // BATCH peek — one round trip for the whole connect-time unread prime
    // (2026-09-20). See
    // [GroupManager.primeUnreadCounts], the only caller.
    // -----------------------------------------------------------------------

    /**
     * ONE inbox for [peekInboxesBatch]: the id plus the read capability, both
     * RESOLVED BY THE CALLER on one thread before any request exists — the same
     * snapshot-then-request rule [inboundTextPeekTargets] and
     * [inboundControlPeekTargets] already follow, and for the same reason
     * (`DatabaseManager` / `IosVaultDatabase` thread-safety under concurrent
     * access is unproven, so nothing downstream of the snapshot may touch the
     * vault).
     *
     * [controlContactId] is set ONLY for a CONTROL inbox, and it is what makes the
     * batch carry exactly the side effects the two single peeks carry and no
     * others: a control ref that positively answers gets [noteRelayHealthy] (what
     * [peekControlRef] does — a 2xx on this inbox under the cap we hold clears the
     * control channel's 404 streak), while a TEXT ref passes `null` and gets none
     * (the deliberate ABSENCE that is [peekInboxRef]'s safety property). Neither
     * ever records a 404 of its own.
     */
    internal class PeekRef(
        val inboxId: String,
        val readCap: String,
        val controlContactId: String? = null,
    ) {
        // The read cap is the inbox OWNER capability — same redaction rule as
        // [PeekTarget] / [InboundInboxRef].
        override fun toString() =
            "PeekRef(inboxId=[redacted], readCap=[redacted], control=${controlContactId != null})"
    }

    /**
     * What one [peekInboxesBatch] pass learned. The three cases are deliberately
     * distinct, because "the route is missing" and "the request failed" need
     * OPPOSITE handling and neither may ever be read as "the inboxes are empty".
     */
    internal sealed class BatchPeekOutcome {
        /**
         * The relay answered one of [BATCH_PEEK_UNSUPPORTED_CODES] — it does not
         * implement the batch route. The caller runs the per-inbox path it has
         * always run, and [isBatchPeekUnsupported] is latched for this transport so
         * no later pass pays for the discovery again.
         */
        object Unsupported : BatchPeekOutcome()

        /**
         * Transport error, timeout, non-2xx, unreadable body, or a frozen (move)
         * device. UNKNOWN for every ref — never "assume 0". The caller falls back
         * to the per-inbox path, which re-asks.
         */
        object Failed : BatchPeekOutcome()

        /**
         * The relay answered. [byInboxId] maps an inbox id to its queued-blob count,
         * or to **null = UNKNOWN** for an item the relay answered with a `status`
         * (404 unknown/bad cap, 429 rate-limited) — exactly what a null from
         * [peekInboxRef] / [peekControlPending] means. An inbox MISSING from the map
         * is equally unknown: a caller must treat `null` and absent identically
         * (`byInboxId[id] ?: <unknown>`), and must never treat either as zero.
         */
        class Counts(val byInboxId: Map<String, Int?>) : BatchPeekOutcome()
    }

    /**
     * Per-TRANSPORT latch: this relay answered the batch route with one of
     * [BATCH_PEEK_UNSUPPORTED_CODES], so nothing on this transport should ask
     * again. It is an instance field on purpose — a `MessageManager` is rebuilt
     * whenever the transport is (Tor self-heal, a new SOCKS port, a fresh session),
     * which is precisely when a relay could have been upgraded under us, so the
     * latch clears exactly then and never needs an explicit reset.
     */
    @Volatile
    private var batchPeekUnsupported = false

    /** @see batchPeekUnsupported */
    internal fun isBatchPeekUnsupported(): Boolean = batchPeekUnsupported

    /**
     * Asks the relay for the queued-blob count of MANY inboxes in ONE round trip:
     * `POST {relay}/peek`, `{"v":1,"items":[{"id":…,"rc":…},…]}`, answered
     * `{"v":1,"results":[{"id":…,"pending":N} | {"id":…,"status":C},…]}`.
     *
     * It is the connect-time unread prime's whole network phase: the prime used to
     * spend one sequential control round trip per group member plus a 3-wide `/peek`
     * fan-out over every contact, all on the coldest circuit of the session, which
     * is what the user waits through before the contact list appears.
     *
     * **Exactly the single peek's side effects, and no others.** Pure HTTP plus:
     *  - [noteRelayHealthy] for each CONTROL ref that positively answered (see
     *    [PeekRef.controlContactId]) — never for a text ref;
     *  - the [hasCompletedRelayRoundTrip] latch on any 2xx, because a `/peek` that
     *    answered IS a completed `.onion` round trip, the same evidence
     *    [peekControlRef] latches on.
     * **NEVER a vault write, never a vault READ** — every id/cap comes from the
     * caller's snapshot — and never any 404 bookkeeping ([noteRelay404]), for the
     * same reason the two single peeks skip it: an unknown answer DRAINS, and that
     * drain owns the streak.
     *
     * **The relay is UNTRUSTED and nothing destructive rides on its answer.** A
     * relay that lies `pending: 0` withholds one unread dot / delays one control
     * drain by a sweep — exactly what it can already do by simply not returning the
     * blobs, and exactly the cost the single `/peek` already carries. Results are
     * matched **by index** (the relay answers one per item, in request order) with
     * the echoed id as a cross-check, so a reordered or forged echo yields UNKNOWN
     * rather than a count attributed to the wrong inbox; an over-long results array
     * fails the whole batch closed.
     *
     * **Only refs the caller would have single-peeked anyway.** A wrong read cap
     * inside a batch feeds the same per-inbox read-strike lockout on the relay as a
     * wrong cap on `GET /inbox/{id}/peek`, so this must never be handed a
     * speculative capability. Its caller's snapshots are the same ones the single
     * peeks use, including the read-cap rotation reconcile
     * ([inboundControlPeekTargets]).
     *
     * **Body shape.** The ids and caps are validated ([isValidInboxId] /
     * [capValidForHeader]) BEFORE they enter the JSON, and an invalid ref is
     * dropped rather than sent — the same gate [peekOnce] applies before either
     * value reaches a header. The body is NOT padded: request bodies are padded
     * only where the payload is CIPHERTEXT ([padMessage] pads the plaintext inside
     * the envelope), and this body's one length-bearing fact — how many inboxes
     * this device holds — is the very thing the relay is being told, so padding
     * would buy nothing from the party that reads it.
     *
     * Chunked at [BATCH_PEEK_MAX_ITEMS]; an [Unsupported] or [Failed] chunk ends
     * the whole call with that outcome (a partial map would make the caller's
     * fallback ambiguous, and a peek is non-destructive, so re-asking costs
     * nothing). Same per-request timeout as the single peek (the transport
     * default). Blocking — call from a dispatcher that tolerates blocking I/O.
     */
    internal fun peekInboxesBatch(refs: List<PeekRef>): BatchPeekOutcome {
        // Freeze gate, same as [peekInboxRef] / [inboundTextPeekTargets]: a frozen
        // phone must reach the relay zero times. FAILED, never UNSUPPORTED — the
        // relay said nothing, so nothing may be latched about it.
        if (moveFrozen("unread prime batch peek")) return BatchPeekOutcome.Failed
        if (batchPeekUnsupported) return BatchPeekOutcome.Unsupported
        // Validate + de-duplicate, order-preserving. A malformed ref is simply not
        // asked about (absent = unknown), exactly as the snapshots already skip one.
        val items = mutableListOf<PeekRef>()
        val seen = mutableSetOf<String>()
        for (ref in refs) {
            if (ref.readCap.isEmpty() || !capValidForHeader(ref.readCap)) continue
            if (!isValidInboxId(ref.inboxId)) continue
            if (!seen.add(ref.inboxId)) continue
            items.add(ref)
        }
        if (items.isEmpty()) return BatchPeekOutcome.Counts(emptyMap())
        val out = mutableMapOf<String, Int?>()
        for (chunk in items.chunked(BATCH_PEEK_MAX_ITEMS)) {
            when (val outcome = peekBatchOnce(chunk)) {
                is BatchPeekOutcome.Counts -> out.putAll(outcome.byInboxId)
                else -> return outcome
            }
        }
        return BatchPeekOutcome.Counts(out)
    }

    /** ONE `POST /peek` for at most [BATCH_PEEK_MAX_ITEMS] refs. See [peekInboxesBatch]. */
    private fun peekBatchOnce(items: List<PeekRef>): BatchPeekOutcome {
        val body = StringBuilder("{\"v\":1,\"items\":[")
        for ((index, ref) in items.withIndex()) {
            if (index > 0) body.append(',')
            body.append("{\"id\":").append(jsonEscapeString(ref.inboxId))
            body.append(",\"rc\":").append(jsonEscapeString(ref.readCap)).append('}')
        }
        body.append("]}")
        val bytes = body.toString().encodeToByteArray()
        // NEWNYM ABORT: opted in (read-only, non-destructive — re-asking costs
        // nothing), so an app-fired NEWNYM cancels a POST parked on a retired
        // circuit. An abandoned POST is re-sent ONCE at once on the fresh circuits
        // rather than reported Failed: Failed would send the prime down the full
        // pre-batch path (control pre-drain + per-inbox fan-out), far slower.
        var result: HttpResult? = null
        for (round in 0..1) {
            val epochAtStart = circuitResetEpoch
            val r = try {
                httpClient.post(
                    "$relayBaseUrl/peek", bytes, BATCH_PEEK_CONTENT_TYPE, emptyMap(),
                    DEFAULT_RELAY_HTTP_TIMEOUT_SECONDS, suppressLog = false, cancelOnNewCircuit = true,
                )
            } catch (e: Exception) {
                if (round == 0 && circuitResetEpoch != epochAtStart) continue
                // Class/message only — never an id, a cap or a url.
                platformLogWarn(LOG_TAG, "batch peek threw: ${e::class.simpleName}")
                return BatchPeekOutcome.Failed
            }
            if (round == 0 && r.code <= 0 && circuitResetEpoch != epochAtStart) {
                platformLog(LOG_TAG, "batch peek abandoned for fresh circuits (NEWNYM or relay address switch) — re-sending once")
                continue
            }
            result = r
            break
        }
        if (result == null) return BatchPeekOutcome.Failed
        if (result.code in BATCH_PEEK_UNSUPPORTED_CODES) {
            batchPeekUnsupported = true
            platformLog(
                LOG_TAG,
                "batch peek unsupported by this relay (code=${result.code}) — per-inbox peeks for this transport",
            )
            return BatchPeekOutcome.Unsupported
        }
        if (!result.isSuccess || result.body == null) {
            platformLogWarn(LOG_TAG, "batch peek failed (code=${result.code})")
            return BatchPeekOutcome.Failed
        }
        // Raw MALICIOUS-RELAY input: non-regex, non-recursive, element-capped at what
        // we asked for (the same rules parseStringArrayField follows).
        val objects = parseObjectArrayField(result.body, "results", items.size)
            ?: return BatchPeekOutcome.Failed
        val counts = mutableMapOf<String, Int?>()
        for ((index, element) in objects.withIndex()) {
            if (index >= items.size) break            // the element cap already refused it
            val ref = items[index]
            // The element CAP above bounds how many results the relay may send,
            // not how big ONE of them is — a single 16 MiB element of short keys is
            // the same OOM as the whole-body case, so this parse is guarded too. A
            // refusal leaves every field absent, which lands on `pending = null` =
            // UNKNOWN for that inbox — never a count, and never "empty".
            val fields = parseRelayJsonOrNull(element) ?: emptyMap()
            // MATCH BY INDEX, never by the echo: the relay answers one result per
            // item in REQUEST ORDER and echoes the id verbatim, so the echo is a
            // CROSS-CHECK only. A result whose echoed id is not this position's is a
            // misordered (or forged) answer, and the only safe reading of it is
            // UNKNOWN — never a count attributed to the wrong inbox.
            val echoed = fields["id"]?.takeIf { it.isString }?.text
            // A `status` item is the relay saying what the single GET /peek would
            // have said (404 gone/bad cap, 429 rate-limited) ⇒ UNKNOWN. So is a
            // missing / unparsable / negative `pending`. All of them are null here;
            // none of them is ever zero.
            val pending = when {
                echoed != null && echoed != ref.inboxId -> null
                fields.containsKey("status") -> null
                else -> fields["pending"]?.takeIf { !it.isString }?.text?.toIntOrNull()?.takeIf { it >= 0 }
            }
            counts[ref.inboxId] = pending
            if (pending != null && ref.controlContactId != null) {
                // Exactly [peekControlRef]'s side effect, for exactly its refs.
                noteRelayHealthy(ref.controlContactId, Chan.CTL)
            }
        }
        // A 2xx from the relay over `.onion` IS a completed round trip — the same
        // evidence [peekControlRef] and the health probe latch on.
        markRelayRoundTripCompleted()
        return BatchPeekOutcome.Counts(counts)
    }

    /**
     * Non-destructively asks the relay how many blobs are queued in [contactId]'s
     * INBOUND CONTROL inbox, so the background control sweep can decide whether the
     * drain is worth making at all.
     *
     * Why the sweep needs it: every drain is a LEASED retrieve (`?lease=1`, settled by
     * `POST /ack`, see [prepareDrain]), so a drain whose response is lost on a
     * cold/wedged circuit costs a re-delivery once the lease lapses, not the messages
     * — but on a cold circuit that GET can block its full transport budget, and it
     * carries the lease/ack round trip. The overwhelmingly common case is an EMPTY
     * control inbox, where `/peek` costs one cheap GET and saves that round trip.
     *
     * Layered strictly ABOVE [peekOnce] — same request, same cap/inbox-id validation
     * — plus exactly the three side effects the control channel's own poll performs
     * and the parallel unread prime deliberately must not (see [peekInboxRef], whose
     * ABSENCE of these is its safety property):
     *
     *  1. the read-cap rotation reconcile FIRST, the same call [pollChannel] makes, so the
     *     cap this probes with is the reconciled one;
     *  2. [noteRelayHealthy] on success — a healthy peek clears this channel's 404
     *     streak exactly as a healthy drain would;
     *  3. the [hasCompletedRelayRoundTrip] latch on success — a `/peek` that answered
     *     IS a completed `.onion` round-trip, the same evidence the health probe
     *     latches on.
     *
     * Returns the queued-blob count, or **null = UNKNOWN** (contact/inbox gone,
     * missing or unusable cap, 404, 429, transport failure, unreadable body). A
     * caller MUST treat null conservatively — drain anyway — never as zero: a failed
     * peek says nothing about what is waiting, and reading it as "empty" would starve
     * control delivery behind a transient failure. It deliberately records NO 404 of
     * its own: an unknown outcome drains, and that drain's own 404 branch does the
     * [noteRelay404] bookkeeping, so the streak keeps counting one 404 per cycle
     * instead of two.
     *
     * Blocking (vault + network) — background dispatcher only.
     */
    internal fun peekControlPending(contactId: String): Int? {
        // Freeze gate. `null` is this method's documented UNKNOWN, which the caller
        // answers by draining anyway — and that drain is [pollChannel], gated too, so
        // the conservative fall-through stays correct and still reaches the relay
        // zero times. Bridged straight to Swift (IosAppController.peekControlPending),
        // so the session-layer provider gate does not cover it.
        if (moveFrozen("control peek")) return null
        // No control inbox at all is the normal PRE-V7 pairing: unknown rather
        // than zero, and the drain it falls through to is itself a no-op there.
        val inboxRecord = readOwnedInboxRecord(contactId, DIR_INBOUND_CTL, "control peek") ?: return null
        val readCap = inboxRecord.cap ?: return null
        val outcome = peekOnce(inboxRecord.inboxId, readCap)
        if (!outcome.live) return null
        // A 2xx on THIS inbox under the cap we hold is the same proof the drain's own
        // 200 carries, so it clears the control channel's 404 streak; without this,
        // skipping the drain on an idle cycle would leave a stale streak standing.
        noteRelayHealthy(contactId, Chan.CTL)
        markRelayRoundTripCompleted()
        return outcome.pending
    }

    /**
     * SNAPSHOT for the control sweep's BOUNDED-PARALLEL peek phase
     * (2026-09-16) — the same per-contact resolution [peekControlPending] does,
     * for a whole contact set, on ONE coroutine, BEFORE any fan-out exists.
     *
     * Everything that touches the vault lives here: the contact row check, the
     * read-cap reconcile (`maybeReconcileReadCap`, which can WRITE), the
     * inbound-ctl row read and the cap/inbox-id shape checks. The workers then
     * call [peekControlRef], which touches no vault at all — the same
     * snapshot-then-fan-out discipline [inboundTextPeekTargets] /
     * [peekInboxRef] established, and for the same reason: `DatabaseManager` /
     * `IosVaultDatabase` thread-safety under genuinely concurrent access is
     * unproven on both platforms and must not acquire a second concurrent
     * caller.
     *
     * A contact that resolves to nothing (unknown contact, pre-v7 pairing with
     * no control inbox, missing/malformed cap, malformed inbox id) is SKIPPED,
     * and the caller must treat a missing entry as UNKNOWN — i.e. drain — never
     * as "nothing queued". That is the same fall-through [peekControlPending]'s
     * nulls produce.
     *
     * Order is preserved (the caller already CSPRNG-shuffled it). Blocking
     * (vault) — background dispatcher only.
     */
    internal fun inboundControlPeekTargets(contactIds: List<String>): List<PeekTarget> =
        // Freeze gate (inside), same as [inboundTextPeekTargets]: this snapshot hands
        // LIVE read capabilities to workers that have no vault of their own, so a
        // frozen phone must not produce it at all. Empty ⇒ every contact is
        // unknown ⇒ the caller falls through to the drain, which is itself
        // freeze-gated and reaches the relay zero times.
        ownedInboxPeekTargets(contactIds, DIR_INBOUND_CTL, "control peek snapshot")

    /**
     * The shared body of [inboundControlPeekTargets] and [inboundGroupPeekTargets]:
     * per contact, the contact-row check, the read-cap reconcile (BEFORE the cap is
     * read, exactly as [pollChannel] does), the [direction] row read and the cap /
     * inbox-id shape checks. A contact that resolves to nothing is skipped (UNKNOWN
     * to the caller). [label] is both the freeze-gate op and the log phrase.
     */
    private fun ownedInboxPeekTargets(contactIds: List<String>, direction: String, label: String): List<PeekTarget> {
        if (moveFrozen(label)) return emptyList()
        val out = mutableListOf<PeekTarget>()
        for (contactId in contactIds) {
            try {
                if (!contactExists(contactId)) continue
                maybeReconcileReadCap(contactId, direction)
                val rec = databaseManager.getInboxIdForContact(contactId, direction) ?: continue
                val cap = rec.cap
                if (cap.isNullOrEmpty() || !capValidForHeader(cap)) continue
                if (!isValidInboxId(rec.inboxId)) continue
                out.add(PeekTarget(contactId, rec.inboxId, cap))
            } catch (e: Exception) {
                platformLogWarn(LOG_TAG, "$label failed: ${e::class.simpleName}")
            }
        }
        return out
    }

    /**
     * The shared resolve step of [peekControlPending] and [peekGroupInboxPending]
     * (their side effects stay at the call sites): the contact-row check, then the
     * self-heal — finish any INTERRUPTED read-cap rotation BEFORE the cap is used, so
     * a peek can't 404 merely because we still hold the pre-rotation candidate
     * (cheap-gated on one `_meta` lookup) — then the [direction] row. null = UNKNOWN
     * (no contact, no row, or the read threw — logged under [logPhrase]).
     */
    private fun readOwnedInboxRecord(contactId: String, direction: String, logPhrase: String): InboxIdRecord? {
        if (!contactExists(contactId)) return null
        maybeReconcileReadCap(contactId, direction)
        return try {
            databaseManager.getInboxIdForContact(contactId, direction)
        } catch (e: Exception) {
            platformLogWarn(LOG_TAG, "$logPhrase: inbox read failed: ${e::class.simpleName}")
            null
        }
    }

    /**
     * The PURE-HTTP half of [peekControlPending], against an ALREADY-RESOLVED
     * target from [inboundControlPeekTargets] — byte-for-byte the same `/peek`
     * request, with every VAULT access removed so several of these can run at
     * once.
     *
     * It keeps the two RAM-only side effects the control peek owns and the
     * parallel unread prime deliberately does not — [noteRelayHealthy] (a 2xx on
     * this inbox under the cap we hold clears the control channel's 404 streak
     * exactly as a healthy drain would) and the [hasCompletedRelayRoundTrip]
     * latch — because both are lock-guarded RAM, not vault state. It records NO
     * 404 of its own, for the same reason [peekControlPending] does not: the
     * drain an unknown answer falls through to does that bookkeeping, and
     * counting it twice would trip the re-pair badge in half the cycles.
     *
     * Returns the queued-blob count, or null = UNKNOWN (drain anyway).
     */
    internal fun peekControlRef(target: PeekTarget): Int? {
        if (moveFrozen("control peek")) return null
        val outcome = peekOnce(target.inboxId, target.readCap)
        if (!outcome.live) return null
        noteRelayHealthy(target.contactId, Chan.CTL)
        markRelayRoundTripCompleted()
        return outcome.pending
    }

    /**
     * Peeks every contact's inbound text inbox and returns a map of contactId
     * → pending blob count, for contacts with at least one waiting (count
     * drives an OS-style numeric unread badge). Shuffled order + small
     * inter-request jitter, matching the control poll's traffic discipline so
     * an observer can't align the sweep across cycles. Blocking — call from a
     * background dispatcher. Contacts whose peek is "unknown" (null) are
     * omitted (no badge rather than a wrong one).
     */
    fun peekUnreadCounts(blockedContactIds: Set<String> = emptySet()): Map<String, Int> =
        peekUnreadCountsWithGroup(blockedContactIds, emptySet()).text

    /**
     * What one steady-state unread sweep learned. [text] is exactly what
     * [peekUnreadCounts] has always returned — the 1:1 TEXT inbox depths, and the
     * ONLY input to a contact's unread dot. [group] is the GROUP inbox depth of the
     * contacts the caller asked about, and it is deliberately a SEPARATE map: it
     * must never be summed into, subtracted from, or otherwise reach the contact
     * term, and keeping the two apart at the type level is what makes that
     * reviewable at every call site.
     *
     * [complete] (2026-10-14) is true ONLY when every peek this sweep issued got a
     * definite answer — every text peek and every group peek non-null, and the
     * sweep was not refused by the move freeze. A group peek that is null because
     * the pairing has no group inbox yet also counts as incomplete: conservative,
     * since the one consumer (Android's late-FCM-wake suppression,
     * `PushWakeFreshness`) may only claim "the app has seen every inbox" on proof.
     * It never feeds a count.
     */
    internal class UnreadPeek(
        val text: Map<String, Int>,
        val group: Map<String, Int>,
        val complete: Boolean = false,
    )

    /**
     * The steady-state unread sweep, now covering the GROUP inbox too.
     *
     * **Filtered on purpose** ([groupSharingContactIds]): a third inbox per contact
     * would grow this serial, jittered sweep by 50 % for everyone, and a pairing we
     * share no group with can have nothing in its group inbox worth a round trip.
     * The caller passes exactly the contacts it shares a group with (one cheap
     * vault read there, the same predicate the drain and the backfill use), so for
     * the 1:1-only majority this sweep is byte-identical to what it has always been
     * — same requests, same order, same jitter.
     *
     * A contact in [groupSharingContactIds] pays ONE extra `/peek` and one extra
     * inter-request sleep, both inside the same CSPRNG-shuffled walk, so the sweep
     * gains no new shape beyond its length.
     */
    internal fun peekUnreadCountsWithGroup(
        blockedContactIds: Set<String>,
        groupSharingContactIds: Set<String>,
    ): UnreadPeek {
        // Freeze gate BEFORE the contact walk, so a frozen phone pays neither the
        // vault enumeration nor the 100–400 ms inter-request sleeps. [peekInbox] is
        // gated too; this one only makes the refusal cheap.
        if (moveFrozen("unread sweep")) return UnreadPeek(emptyMap(), emptyMap())
        // Only the ids are used below: wipe every decoded secret at once.
        val contacts = databaseManager.getAllContacts()
            .onEach { it.sharedSecret.secureWipe() }
            .filter { it.contactId !in blockedContactIds }  // never poll a blocked inbox
            .toMutableList()
        contacts.secureShuffle()  // CSPRNG Fisher–Yates — non-predictable sweep order
        val counts = mutableMapOf<String, Int>()
        val groupCounts = mutableMapOf<String, Int>()
        var requests = 0
        var complete = true
        for (c in contacts) {
            jitterBeforeRequest(requests); requests++
            val n = peekInbox(c.contactId)
            if (n == null) complete = false
            if (n != null && n > 0) counts[c.contactId] = n
            if (c.contactId !in groupSharingContactIds) continue
            jitterBeforeRequest(requests); requests++
            val g = peekGroupInboxPending(c.contactId)
            // Unknown (null) is NOT zero — it simply leaves the previous depth
            // standing, exactly as an unknown text peek leaves the previous dot.
            if (g == null) complete = false
            if (g != null) groupCounts[c.contactId] = g
        }
        return UnreadPeek(counts, groupCounts, complete)
    }

    /** The sweep's inter-request traffic discipline, single-sourced so the text
     *  and group peeks can never drift apart: 100–400 ms of jitter before every
     *  request except the very first ([requestsSoFar] == 0) of a pass. */
    private fun jitterBeforeRequest(requestsSoFar: Int) {
        if (requestsSoFar > 0) sleepMillis(jitterMs(RELAY_REQUEST_JITTER_BASE_MS, RELAY_REQUEST_JITTER_SPREAD_MS))
    }

    /**
     * Non-destructively asks the relay how many blobs are queued in [contactId]'s
     * INBOUND GROUP inbox. The group sibling of [peekInbox], and the same three
     * rules apply: it NEVER drains (group texts survive on the relay until their
     * group conversation is opened, exactly like 1:1 texts), `null` means UNKNOWN
     * and never "empty", and it records NO 404 of its own — the drain owns that
     * bookkeeping, and here it would double-count toward the self-heal streak.
     *
     * Two deliberate differences from [peekInbox], both mirroring the CONTROL peek:
     *
     *  - **the read-cap reconcile runs first.** The group inbox is drained only
     *    when a conversation is open, so an interrupted rotation could otherwise sit
     *    unreconciled for days while every sweep peeked with a cap the relay no
     *    longer holds — feeding the per-inbox read-strike lockout. Cheap-gated on
     *    one `_meta` read, so the steady state costs one vault lookup.
     *  - **the lease re-stamp still happens** ([noteInboxProvenLive]): for a
     *    pairing that never exchanges group texts this peek is the ONLY thing that
     *    ever touches that inbox, so it is the only lease refresh it will get.
     *
     * Returns null for a pairing with no `inbound-grp` row (legacy / not yet
     * backfilled) WITHOUT touching the network. Blocking — background only.
     */
    internal fun peekGroupInboxPending(contactId: String): Int? {
        if (moveFrozen("group unread peek")) return null
        val inboxRecord = readOwnedInboxRecord(contactId, DIR_INBOUND_GRP, "group peek") ?: return null
        val readCap = inboxRecord.cap ?: return null
        val outcome = peekOnce(inboxRecord.inboxId, readCap)
        if (!outcome.live) return null
        noteInboxProvenLive(inboxRecord)
        return outcome.pending
    }

    /**
     * One contact's inbound TEXT inbox, pre-resolved and pre-validated so a
     * `/peek` can be issued against it with NO further vault access. See
     * [inboundTextPeekTargets].
     */
    internal class PeekTarget(val contactId: String, val inboxId: String, val readCap: String) {
        // The read cap is the inbox OWNER capability (drain / DELETE / rotate BOTH
        // caps / push register), so never let a stray log or string interpolation
        // print it — same redaction rule as [InboundInboxRef].
        override fun toString() =
            "PeekTarget(contactId=[redacted], inboxId=[redacted], readCap=[redacted])"
    }

    /**
     * SNAPSHOT for the connect-time unread prime: every non-blocked contact's
     * inbound TEXT inbox as a (contactId, inboxId, readCap) triple, resolved with
     * exactly the per-contact lookup + shape checks [peekInbox] performs
     * (`getInboxIdForContact(id, "inbound")`, non-empty header-safe cap, valid inbox
     * id). Same rules as [allInboundTextInboxes] uses for push registration; this
     * one additionally carries the contactId the unread badge is keyed by, which
     * that enumeration deliberately drops.
     *
     * It exists so the parallel prime does ALL of its vault I/O here, once, on the
     * CALLING coroutine, BEFORE any fan-out — the workers then run pure HTTP
     * ([peekInboxRef]) and never touch the vault. `DatabaseManager` /
     * `IosVaultDatabase` thread-safety under genuinely concurrent access is
     * unproven, so this ordering is what keeps the prime from becoming its first
     * concurrent caller.
     *
     * A contact with no resolvable / malformed inbound inbox is silently SKIPPED —
     * there is nothing to peek, and a skipped contact simply gets no emission
     * (merge-only; see [GroupManager.primeUnreadCounts]). A per-contact vault read
     * that throws skips that contact rather than failing the snapshot. Blocking
     * (vault reads) — call from a background dispatcher.
     */
    internal fun inboundTextPeekTargets(blockedContactIds: Set<String> = emptySet()): List<PeekTarget> {
        // Freeze gate. No network here, but this snapshot hands LIVE read
        // capabilities to workers that then run with no vault of their own — so a
        // frozen phone must not produce it at all rather than rely on the per-worker
        // gate in [peekInboxRef]. Empty = nothing to fan out; the prime emits nothing.
        if (moveFrozen("unread prime")) return emptyList()
        val out = mutableListOf<PeekTarget>()
        // Only the ids are used below: wipe every decoded secret at once.
        for (contact in databaseManager.getAllContacts().onEach { it.sharedSecret.secureWipe() }) {
            val contactId = contact.contactId
            if (contactId in blockedContactIds) continue   // never poll a blocked inbox
            val rec = try {
                databaseManager.getInboxIdForContact(contactId, "inbound")
            } catch (e: Exception) {
                platformLogWarn(LOG_TAG, "unread prime: inbox read failed: ${e::class.simpleName}")
                null
            } ?: continue
            val cap = rec.cap
            if (cap.isNullOrEmpty() || !capValidForHeader(cap)) continue
            if (!isValidInboxId(rec.inboxId)) continue
            out.add(PeekTarget(contactId, rec.inboxId, cap))
        }
        return out
    }

    /**
     * SNAPSHOT of the INBOUND GROUP inboxes for [contactIds] — the group sibling of
     * [inboundControlPeekTargets], and resolved with exactly the per-contact lookup
     * + shape checks [peekGroupInboxPending] performs (including the read-cap
     * reconcile, so the batch never asks with a cap the single peek would not use —
     * "never batch a cap you would not single-peek").
     *
     * The CALLER filters: it passes only contacts it shares a group with, so a
     * 1:1-only device adds nothing at all to the connect-time batch.
     *
     * A contact that resolves to nothing (no group row — legacy or not yet
     * backfilled, missing/malformed cap, malformed id) is SKIPPED, and its absence
     * from the answer means UNKNOWN: the group depth simply stays as it was, never
     * "empty". Order is preserved (the caller already shuffled). Blocking (vault) —
     * background dispatcher only.
     */
    internal fun inboundGroupPeekTargets(contactIds: List<String>): List<PeekTarget> =
        ownedInboxPeekTargets(contactIds, DIR_INBOUND_GRP, "group peek snapshot")

    // --- Relay-loss detection (control channel) -------------------------------
    // A PERSISTENT 404 on a contact's control inbox (the relay is up — it answered
    // 404 — but no longer knows the inbox) means the relay lost that contact's
    // inboxes. Inbox IDs are relay-minted, so a lost ID can't be re-registered:
    // the only recovery is re-pair, which we surface per-contact. Written from
    // both the control-poll and the on-demand message-poll coroutines (which can
    // run concurrently on different dispatchers), so access is lock-guarded; the
    // platform layer reads it right after the sweep and hands it to the UI via a
    // StateFlow / @Published.
    internal val RELAY_LOST_404_STREAK = 4   // internal so RelayLossTest pins the exact threshold
    // A 404 streak must ALSO persist for this wall-clock window before
    // it flags "relay-lost" — a burst of 404s (a fast-poll/converging window, or a
    // hostile relay 404-ing rapidly) then can't force a spurious "tap to re-pair"
    // badge; a genuine inbox-gone persists across it. `relayLostClockMs` is an
    // injectable clock seam so RelayLossTest drives the window without real waits.
    internal val RELAY_LOST_MIN_WINDOW_MS = 180_000L   // 3 min
    internal var relayLostClockMs: () -> Long = { currentTimeMillis() }
    // Each channel keeps its own 404 streak. A contact is "relay-lost" when a
    // BADGING channel's streak crosses the threshold, and the flag clears only
    // once every channel is healthy again. Plain maps/sets are not thread-safe
    // (on Kotlin/Native an unguarded race can corrupt/crash, not merely
    // interleave), so every read and write goes through [relayLossLock].
    private val relayLossLock = SyncLock()
    // Per-channel streak + the wall-clock (ms) of the FIRST 404 in that channel's
    // CURRENT streak. One map each, keyed by (channel, contactId), so a third
    // channel cannot be added by forgetting a fourth map.
    private val relay404Streak = mutableMapOf<Chan, MutableMap<String, Int>>()
    private val relay404FirstMs = mutableMapOf<Chan, MutableMap<String, Long>>()
    private val relayLostSet = mutableSetOf<String>()

    /**
     * The channels whose persistent 404 raises the "tap to re-pair" badge.
     *
     * [Chan.GRP] is deliberately ABSENT, and that is the one deliberate exception
     * in the 404 ladder: WE own that inbox, so a fresh mint plus a `{"gib","gwc"}`
     * announce restores the channel with no user action, and the pairing itself
     * (text + control) is untouched. Badging a re-pair for it would demand an IRL
     * meeting to fix something the device can fix in band. Until it converges,
     * group texts fall back to the text inbox — degraded, never broken.
     * [groupInboxSelfHealDue] is the reader that drives that self-heal.
     */
    private val badgingChannels = listOf(Chan.MAIN, Chan.CTL)

    /** contactIds whose inbox the relay has persistently 404'd — flag for re-pair. */
    fun relayLostContacts(): Set<String> = relayLossLock.withLock { relayLostSet.toSet() }

    /** Streak / first-ms map for one channel, created on first use. */
    private fun streakMap(chan: Chan) = relay404Streak.getOrPut(chan) { mutableMapOf() }
    private fun firstMsMap(chan: Chan) = relay404FirstMs.getOrPut(chan) { mutableMapOf() }

    /** A channel trips only when its streak has BOTH crossed the
     *  count threshold AND persisted for [RELAY_LOST_MIN_WINDOW_MS]. */
    private fun channelTripped(chan: Chan, contactId: String, now: Long): Boolean {
        val cnt = relay404Streak[chan]?.get(contactId) ?: 0
        val since = relay404FirstMs[chan]?.get(contactId)
        return cnt >= RELAY_LOST_404_STREAK && since != null && now - since >= RELAY_LOST_MIN_WINDOW_MS
    }

    /** Record a 404 on [contactId]'s [chan] inbox; flag past the streak. */
    private fun noteRelay404(contactId: String, chan: Chan) = relayLossLock.withLock {
        val m = streakMap(chan)
        val prev = m[contactId] ?: 0
        if (prev == 0) firstMsMap(chan)[contactId] = relayLostClockMs()   // first 404 of a fresh streak
        m[contactId] = prev + 1
        val now = relayLostClockMs()
        if (badgingChannels.any { channelTripped(it, contactId, now) }) relayLostSet.add(contactId)
    }

    /**
     * True when [contactId]'s GROUP inbox has 404'd persistently enough to be
     * treated as GONE — the signal that the inbox should be re-minted and
     * re-announced in band (never a re-pair badge; see [badgingChannels]).
     *
     * Same evidence bar as the badge: [RELAY_LOST_404_STREAK] consecutive 404s
     * spanning at least [RELAY_LOST_MIN_WINDOW_MS], so a converging burst or a
     * hostile relay 404-ing rapidly cannot trigger a mint. A contact with no group
     * row never reaches the network on that channel, so it can never be due.
     *
     * Read by the throttled group-inbox backfill, which is also what bounds
     * it: the mint is rate-limited per contact, so this cannot loop.
     */
    internal fun groupInboxSelfHealDue(contactId: String): Boolean = relayLossLock.withLock {
        channelTripped(Chan.GRP, contactId, relayLostClockMs())
    }

    /**
     * The relay has PROVEN [record]'s inbox alive — a 2xx on that exact inbox id,
     * authenticated with the capability we hold for it. That is the ONLY evidence
     * that justifies re-stamping the row's informational `expiresAt`, so this is
     * never reachable from a 404/429/transport-failure path: a genuinely reaped inbox
     * must keep falling through to the persistent-404 → re-pair signal, not be papered
     * over here.
     *
     * Steady state costs nothing (a comparison on a row the caller already read); the
     * write only happens inside the last [INBOX_LEASE_RENEW_BEFORE_MS] of the stamp,
     * or on a vault whose rows are already past it (the one-time repair). The write
     * itself is a forward-only single-column UPDATE keyed by the primary key, so it
     * can neither clobber a concurrently-rotated `cap` nor resurrect a deleted row.
     */
    private fun noteInboxProvenLive(record: InboxIdRecord) {
        val now = currentTimeMillis()
        if (record.expiresAt > now + INBOX_LEASE_RENEW_BEFORE_MS) return
        val renewed = now + VaultSeedDefaults.INBOX_LIFETIME_MS
        if (renewed <= record.expiresAt) return   // never walk the stamp backward
        try {
            databaseManager.touchInboxExpiry(record.inboxId, renewed)
        } catch (e: Exception) {
            // Best-effort hygiene — a failure changes nothing operational.
            platformLogWarn(
                LOG_TAG,
                "inbox lease re-stamp failed: ${e::class.simpleName}",
            )
        }
    }

    /** Record a healthy poll on one channel; clear the flag only if EVERY badging
     *  channel is healthy. */
    private fun noteRelayHealthy(contactId: String, chan: Chan) = relayLossLock.withLock {
        streakMap(chan).remove(contactId)
        firstMsMap(chan).remove(contactId)   // reset streak start
        if (badgingChannels.all { (relay404Streak[it]?.get(contactId) ?: 0) < RELAY_LOST_404_STREAK }) {
            relayLostSet.remove(contactId)
        }
    }

    // -----------------------------------------------------------------------
    // The GROUP-inbox BACKFILL.
    //
    // Every pairing made before the third inbox existed has no group inbox, so
    // without this they would stay on the legacy route forever
    // and the invariant would have a permanent, pairing-shaped hole. It is
    // also the 404 self-heal: the group inbox is the ONE inbox in the vault that
    // can be replaced IN BAND, because a re-mint produces a fresh write cap we
    // legitimately hold and can state in an announce.
    //
    // What it is NOT: a periodic task. The caller arms it from the control sweep
    // for contacts it SHARES A GROUP WITH; the durable throttle below is what
    // stops an inert pairing from becoming a Tor beacon.
    // -----------------------------------------------------------------------

    /** What one [maybeBackfillGroupInbox] pass did — for the caller's per-sweep budget and the tests. */
    internal enum class GroupBackfillOutcome {
        /** Nothing to do: both rows already exist and the channel is healthy. */
        CONVERGED,

        /** Refused before any work: frozen, no transport round-trip yet, no contact, throttled, or exhausted. */
        SKIPPED,

        /** A fresh inbox was minted (or re-minted) and its announce was sent. */
        ANNOUNCED,

        /** An attempt was made and did not land (mint failed, announce refused). Counted against the budget. */
        FAILED,
    }

    /**
     * One throttled backfill/self-heal step for [contactId]'s GROUP inbox.
     *
     * The caller ([GroupManager]) owns the ELIGIBILITY half — "do we share a group
     * with this contact (or hold a parked invite from them)" — because that is
     * group state this layer does not model. This owns the MECHANICS half: the
     * freeze gate, the throttle, the mint, the persist and the announce.
     *
     * Exactly TWO states do work, and the third deliberately does none:
     *
     *  1. **`inbound-grp` absent** (every pairing made before this shipped) ⇒ mint
     *     ONE inbox ([mintInbox], not the pair), persist it, announce
     *     `{"gib","gwc"}`. The mint is what the throttle exists for.
     *  2. **`inbound-grp` present and the 404 streak says it is GONE**
     *     ([groupInboxSelfHealDue]) ⇒ re-mint + re-announce, the deliberate
     *     exception to the re-pair badge. Safe to destroy the old inbox here and
     *     ONLY here: the relay has been answering 404 for it across the whole
     *     streak window, so nothing of the peer's can be queued on it.
     *  3. **`inbound-grp` present, `outbound-grp` absent** (we are the new side of a
     *     mixed-vintage pairing) ⇒ **NOTHING.** The design sketch called for a bare
     *     re-announce here, and it is not implementable: our own inbound WRITE cap
     *     is never persisted, so the only `gwc` we can honestly state is one a mint
     *     just produced — and re-minting would replace an inbox **the peer may
     *     already have learned from our QR**, either destroying group texts queued
     *     on it or orphaning a row whose live read cap `resetRelayAccess` would
     *     then never rotate (the worst mistake available here). This pairing
     *     converges from the PEER's side instead: once they upgrade, THEIR backfill
     *     announces their `gib` to us and the outbound row appears. Known
     *     limitation: until then a re-pair is the repair.
     *
     * **The freeze gate is mandatory and is this method's own.** [mintInbox] is
     * deliberately NOT freeze-gated (it is the move's transfer-inbox primitive), so
     * a frozen old phone would otherwise mint inboxes the exported bundle does not
     * contain — live capabilities on a relay that no device will ever own.
     *
     * Never throws. Blocking (vault + PoW + network) — background dispatcher only.
     */
    internal fun maybeBackfillGroupInbox(contactId: String): GroupBackfillOutcome {
        if (moveFrozen("group inbox backfill")) return GroupBackfillOutcome.SKIPPED
        // A cold circuit is the 6a0c138 lesson: never grind PoW before the relay
        // has answered this transport at least once.
        if (!hasCompletedRelayRoundTrip()) return GroupBackfillOutcome.SKIPPED
        if (!(try { contactExists(contactId) } catch (_: Exception) { false })) return GroupBackfillOutcome.SKIPPED
        // A pairing that has not learned the peer's own inbox yet is still
        // mid-pairing: the announce would have nowhere to go, so refuse BEFORE the
        // PoW grind rather than after it. (`sendEnvelopeSerialized` refuses too;
        // this is what keeps the mint from being spent first.)
        val peerRoute = try {
            databaseManager.getInboxIdForContact(contactId, DIR_OUTBOUND_CTL)
                ?: databaseManager.getInboxIdForContact(contactId, "outbound")
        } catch (_: Exception) { null }
        if (peerRoute == null) return GroupBackfillOutcome.SKIPPED
        val inbound = try {
            databaseManager.getInboxIdForContact(contactId, DIR_INBOUND_GRP)
        } catch (_: Exception) { return GroupBackfillOutcome.SKIPPED }
        val outbound = try {
            databaseManager.getInboxIdForContact(contactId, DIR_OUTBOUND_GRP)
        } catch (_: Exception) { return GroupBackfillOutcome.SKIPPED }
        val selfHealDue = inbound != null && groupInboxSelfHealDue(contactId)
        if (inbound != null && !selfHealDue) {
            // Our inbox exists and the relay still answers for it. Either the
            // pairing is CONVERGED (both rows) or it is case 3 above, which does
            // nothing — and in both we drop a spent throttle record so a LATER
            // self-heal starts from a full budget, BUT only once the record's last
            // attempt is at least [GROUP_BACKFILL_MIN_INTERVAL_MS] old
            // (2026-10-17). A peer cannot trigger this branch, but the RELAY can:
            // it decides whether our inbox answers 404 (arming the self-heal) or
            // 200 (this branch), and [backfillMintAndAnnounce] clears the streak
            // itself, so an unconditional delete let a hostile relay force one
            // PoW mint + announce per streak window — the 24 h / 4-attempt bound
            // never accumulated for the self-heal path. The 24 h floor makes the
            // relay's lever one re-mint per day; the record is NOT made permanent
            // (that would exhaust the budget after four GENUINE losses).
            try {
                val record = databaseManager.getMeta(groupBackfillKey(contactId))
                if (record != null) {
                    val lastMs = record.substringAfter('|', "").toLongOrNull() ?: 0L
                    val now = currentTimeMillis()
                    // A malformed or future stamp (backward clock step) is treated as
                    // expired, mirroring the mint path's "a future stamp is due now".
                    if (lastMs !in 1..now || now - lastMs >= GROUP_BACKFILL_MIN_INTERVAL_MS) {
                        databaseManager.deleteMeta(groupBackfillKey(contactId))
                    }
                }
            } catch (_: Exception) { /* best effort — a stale record only costs budget */ }
            return if (outbound != null) GroupBackfillOutcome.CONVERGED else GroupBackfillOutcome.SKIPPED
        }
        val now = currentTimeMillis()
        val record = try { databaseManager.getMeta(groupBackfillKey(contactId)) } catch (_: Exception) { null }
        val attempts = record?.substringBefore('|')?.toIntOrNull() ?: 0
        val lastMs = record?.substringAfter('|', "")?.toLongOrNull() ?: 0L
        if (attempts >= GROUP_BACKFILL_MAX_ATTEMPTS) return GroupBackfillOutcome.SKIPPED
        // A backward clock step must not wedge the throttle open OR shut: treat a
        // future stamp as "due now" (the attempt cap is the real bound).
        if (lastMs in 1..now && now - lastMs < GROUP_BACKFILL_MIN_INTERVAL_MS) {
            return GroupBackfillOutcome.SKIPPED
        }
        // Spend the attempt BEFORE the work, durably. A crash mid-mint must cost a
        // budget slot, never re-enter the grind on the next sweep.
        try {
            databaseManager.putMeta(groupBackfillKey(contactId), "${attempts + 1}|$now")
        } catch (e: Exception) {
            // An unwritable throttle is the one state that could loop, so refuse.
            platformLogWarn(LOG_TAG, "group backfill: throttle write failed — skipping this pass: ${e::class.simpleName}")
            return GroupBackfillOutcome.SKIPPED
        }
        // Only case 1 (no inbox) and case 2 (ours is provably gone) reach here.
        return backfillMintAndAnnounce(contactId, replacing = if (selfHealDue) inbound else null)
    }

    /**
     * Mints ONE group inbox, persists it (replacing [replacing] when the self-heal
     * is swapping a dead one), and announces `{"gib","gwc"}` to the peer.
     *
     * Ordering is the safety property: the row is only replaced AFTER a successful
     * mint, and the announce carries the write cap the mint just produced — the one
     * capability we legitimately hold for our own inbox and can therefore state
     * in-band. If the announce is refused, the row still stands and the next
     * allowed attempt re-announces it (the peer's copy is what is missing, not
     * ours).
     */
    private fun backfillMintAndAnnounce(contactId: String, replacing: InboxIdRecord?): GroupBackfillOutcome {
        val minted = try { mintInbox() } catch (e: Exception) {
            platformLogWarn(LOG_TAG, "group backfill: mint threw: ${e::class.simpleName}")
            null
        } ?: return GroupBackfillOutcome.FAILED
        val now = currentTimeMillis()
        try {
            databaseManager.withTransaction {
                // Ownership gate, exactly as pairing and the announce apply it: a
                // freshly minted id is unknown to this vault, so this can only fire
                // on a relay that handed us an id we already hold.
                firstUnavailableInboxClaim(
                    databaseManager,
                    listOf(InboxClaim(minted.inboxId, contactId, DIR_INBOUND_GRP)),
                )?.let { throw InboxInUseException() }
                databaseManager.insertInboxId(
                    InboxIdRecord(
                        inboxId = minted.inboxId, contactId = contactId,
                        createdAt = now, expiresAt = now + VaultSeedDefaults.INBOX_LIFETIME_MS,
                        direction = DIR_INBOUND_GRP, cap = minted.readCapability,
                    )
                )
            }
        } catch (e: Exception) {
            platformLogWarn(LOG_TAG, "group backfill: persist failed: ${e::class.simpleName}")
            return GroupBackfillOutcome.FAILED
        }
        // The replaced inbox is ours and is now unreferenced; destroying it is
        // unambiguous (it answered 404 for the whole streak that armed this, so the
        // DELETE almost always 404s too — which costs nothing). Best effort, and
        // never before the new row is committed.
        val oldCap = replacing?.cap
        if (replacing != null && replacing.inboxId != minted.inboxId && !oldCap.isNullOrEmpty()) {
            try { deleteInbox(replacing.inboxId, oldCap) } catch (_: Exception) { }
        }
        // The 404 streak described an inbox that no longer exists locally, so it
        // must not keep this contact "due" and re-arm the self-heal every sweep.
        noteRelayHealthy(contactId, Chan.GRP)
        val announced = try {
            sendInboxAnnounce(
                contactId,
                myInboxId = null, peerWriteCap = null,
                myGrpInboxId = minted.inboxId, peerGrpWriteCap = minted.writeCapability,
            )
        } catch (e: Exception) {
            platformLogWarn(LOG_TAG, "group backfill: announce threw: ${e::class.simpleName}")
            false
        }
        platformLog(LOG_TAG, "group inbox backfill: minted and announced (ok=$announced)")
        return if (announced) GroupBackfillOutcome.ANNOUNCED else GroupBackfillOutcome.FAILED
    }

    // -----------------------------------------------------------------------
    // Double Ratchet (text channel). Engaged only when `dr-on/{id}` is set;
    // everything above (the static AES-GCM envelope + epoch/counter anti-replay)
    // is the unchanged legacy path for every other contact. See [ratchetManager].
    // -----------------------------------------------------------------------

    /** Ratchet-channel envelope — the static one MINUS epoch/counter, since the
     *  ratchet itself supplies message ordering and replay rejection. */
    private fun ratchetEnvelopeJson(plaintext: String, extraFieldsJson: String) =
        """{"t":${roundTimestampToMinute(currentTimeMillis())}$extraFieldsJson,"m":${jsonEscape(plaintext)}}"""

    /** Our (inbound, outbound) TEXT inbox ids — the inputs to ratchet role
     *  assignment. Null until BOTH exist (the responder learns its outbound
     *  inbox in-band, after pairing), and only if both pass ID validation. */
    private fun textInboxIds(contactId: String): Pair<String, String>? {
        val inb = databaseManager.getInboxIdForContact(contactId, "inbound")?.inboxId ?: return null
        val out = databaseManager.getInboxIdForContact(contactId, "outbound")?.inboxId ?: return null
        if (!isValidInboxId(inb) || !isValidInboxId(out)) return null
        return inb to out
    }

    /**
     * The v2 ratchet role for [contactId], or **null** to keep the
     * legacy id-order rule.
     *
     * Reads the two durable, per-contact role inputs written at pairing
     * ([drPeerRoleRuleV2Key] — the peer proved it runs v2; [drRoleOrderKey] — our
     * immutable ordering against the peer's pairing contribution) and combines them
     * with the pairing secret's parity bit. The result is a pure function of values
     * fixed at pairing, so it is the SAME answer on every call — which is what makes
     * a post-[onCorruptReinit] re-init land on the role it had before, and what stops
     * a later `inbox` announce or an inbox rotation from moving it.
     *
     * Fails toward null on EVERY ambiguity — no marker, a marker that is not exactly
     * `"1"`/`"0"`, an unreadable vault, a throwing `_meta` read. That direction is the
     * brick-safe one and it is also the only CORRECT one: a role rule must AGREE with
     * the peer, and a peer we have no v2 evidence from is using the id rule. Never
     * refuses a send, never wipes anything, never surfaces to the user.
     *
     * Only consulted on a FRESH init (see [RatchetManager.loadOrInit]); an existing
     * ratchet blob is its own authority and is never re-roled.
     */
    private fun ratchetSelfIsBobOverride(contactId: String, contact: ContactRecord): Boolean? = try {
        if (databaseManager.getMeta(drPeerRoleRuleV2Key(contactId)) != "1") null
        else when (databaseManager.getMeta(drRoleOrderKey(contactId))) {
            "1" -> ratchetSelfIsBobFromRoleOrder(contact.sharedSecret, true)
            "0" -> ratchetSelfIsBobFromRoleOrder(contact.sharedSecret, false)
            else -> null
        }
    } catch (_: Exception) { null }

    /**
     * Encrypt [envelopeJson] through the text ratchet and POST it, magic-tagged
     * so the peer routes it to its ratchet decoder. Tri-state:
     *   true  → sent;  false → transport/cap failure (give up);
     *   null  → ratchet NOT ready to send (responder before its first ratchet
     *           receive) — caller falls back to a legacy envelope.
     */
    private fun sendOverTextRatchet(
        contactId: String, contact: ContactRecord, envelopeJson: String, noPush: Boolean = false,
        // Where to POST. null = our outbound TEXT inbox (the normal case). An
        // inbox ANNOUNCE passes its control-inbox row so the wire lands on the
        // control channel while still being sealed by the TEXT ratchet — the
        // ratchet instance/role is always keyed on the text inbox pair.
        postTo: InboxIdRecord? = null,
        // Relay retention override for THIS append, identical in meaning to the
        // static path's. Non-null only for the announce (the uniform control ttl);
        // a text send passes null and emits the same URL it always has.
        ttlSeconds: Long? = null,
        // @see SendStatus — threaded so the group-inbox 404 fallback works on
        // the ratchet path too (a dr-on pairing's group text takes THIS branch, so
        // without it the fallback would only ever fire on legacy pairings).
        status: SendStatus? = null,
    ): Boolean? {
        val (myInbound, myOutbound) = textInboxIds(contactId) ?: return null
        val target = postTo ?: databaseManager.getInboxIdForContact(contactId, "outbound") ?: return null
        val writeCap = target.cap
        if (writeCap.isNullOrEmpty() || !capValidForHeader(writeCap)) {
            platformLogWarn(LOG_TAG, "ratchet send: outbound writeCap invalid")
            return false
        }
        val wire = try {
            ratchetManager.tryEncrypt(
                contactId, RATCHET_TEXT_CHANNEL, contact.sharedSecret,
                myInbound, myOutbound, padMessage(envelopeJson.encodeToByteArray()),
                // null ⇒ the id-order rule, byte-identical to before.
                selfIsBobOverride = ratchetSelfIsBobOverride(contactId, contact),
            )
        } catch (e: Exception) {
            platformLogError(LOG_TAG, "ratchet encrypt failed: ${e::class.simpleName}")
            return false
        }
        // No sending chain yet (responder pre-bootstrap) → let the caller send
        // legacy instead; the peer auto-detects the format.
        if (wire == null) return null
        val url = validatedInboxUrl(target.inboxId, ttlSeconds = ttlSeconds)
        // Idempotent transient retry, SAME as the static path: the wire was
        // produced ONCE (the ratchet already advanced + persisted its chain), so
        // re-POSTing the same bytes is replay-safe — the receiver drops a replayed
        // ratchet header. Without this, a single Tor drop after the advance loses
        // the plaintext permanently.
        val posted = postWithTransientRetry(url, RATCHET_WIRE_MAGIC + wire, sendHeaders(writeCap, noPush),
            Chan.entries.firstOrNull { it.outDir == target.direction }?.logLabel ?: "text")
        if (posted?.code == 404) status?.inboxGone = true
        // Transport-class failure: the chain has advanced (the peer will see one
        // skipped key), and a re-drive is a FRESH encrypt — exactly what a manual
        // Retry does today.
        if (posted == null) status?.transportFailed = true
        return posted?.isSuccess == true
    }

    // --- Legacy fallback: bounded, visible, and finally REFUSED ---------------
    //
    // The responder's pre-bootstrap fallthrough above is a real bootstrap cost, but
    // it was uncapped, uncounted and silent, so a relay that selectively drops the
    // initiator's ratchet blobs could hold one whole direction on the static
    // (no-forward-secrecy) envelope indefinitely and nothing anywhere would notice.
    // It is now observable, and the other half of the same picture is covered too —
    // the both-ALICE collision, which produces NO fallback at all — and turns a
    // sustained, permanent downgrade into a loud, recoverable refusal:
    //
    //   dr-legacyfb/{id}    our sends falling back  (both-Bob   detector)
    //   dr-rat-unacked/{id} their receives with no ratchet (both-Alice detector)
    //   dr-refused/{id}     the latch either of them arms at its threshold
    //
    // Both counters are CONSECUTIVE: one inbound ratchet blob that decrypts clears
    // both and the latch, on either channel, with no user action. Nothing here ever
    // touches `dr/{id}/text` — a refusal blocks sends, it must not wipe or re-init a
    // working ratchet.

    /**
     * Consecutive legacy sends made on a `dr-on` contact whose ratchet had no sending
     * chain. 0 in the healthy steady state. Never throws — it crosses the Swift bridge
     * and a vault read can fail transiently; an unreadable counter reads as 0 (a
     * false "not stalled" only omits a warning, while a false "stalled" would tell a
     * user their channel is degraded when it is not).
     */
    fun ratchetFallbackCount(contactId: String): Int = try {
        databaseManager.getMeta(drLegacyFallbackKey(contactId))?.toIntOrNull()?.coerceAtLeast(0) ?: 0
    } catch (_: Exception) { 0 }

    /**
     * True once [ratchetFallbackCount] has reached [RATCHET_FALLBACK_STALL_THRESHOLD]
     * — "forward secrecy has not engaged with this contact". Consumed since cd55cf44 by
     * the `fs_stalled_notice` row in the 1:1 conversation screen on both platforms
     * (refreshed on open and after every send).
     *
     * This threshold ALSO arms [ratchetRefused], which is the gate.
     * The two readers stay separate on purpose: this one describes the CHANNEL ("no
     * forward secrecy"), which is also true at counts the refusal deliberately tolerates
     * on the way up, while [ratchetRefused] describes what this device will now REFUSE
     * to do about it.
     */
    fun forwardSecrecyStalled(contactId: String): Boolean =
        ratchetFallbackCount(contactId) >= RATCHET_FALLBACK_STALL_THRESHOLD

    /** Records one legacy fallback; warns exactly once, on the crossing, and arms the
     *  refusal from the threshold onward (see [drLegacyFallbackKey]). */
    private fun noteRatchetFallbackToLegacy(contactId: String) {
        val cur = ratchetFallbackCount(contactId)
        val next = if (cur >= RATCHET_FALLBACK_COUNT_CAP) cur else cur + 1
        putMetaBestEffort(drLegacyFallbackKey(contactId), next.toString())
        if (next == RATCHET_FALLBACK_STALL_THRESHOLD) {
            // Counts only — never an identifier, not even a truncated one.
            platformLogWarn(
                LOG_TAG,
                "forward secrecy has NOT engaged for one contact — " +
                    "$next consecutive legacy sends with no ratchet sending chain",
            )
        }
        // `>=`, not `==`: a failed latch write (transient vault error) re-arms on the
        // next fallback instead of leaving the contact permanently un-refused.
        if (next >= RATCHET_FALLBACK_STALL_THRESHOLD) armRatchetRefusal(contactId)
    }

    /** Clears the counter after a ratchet send lands. Gated on a read so the steady
     *  state (no marker) costs one vault lookup and zero writes.
     *
     *  Deliberately does NOT clear [drRefusedKey]: a landed ratchet SEND proves only
     *  that WE hold a sending chain, which is already true in the both-Alice collision
     *  where every one of those sends fails the peer's AEAD. Only an inbound ratchet
     *  blob that DECRYPTS proves the two roles are compatible — see
     *  [noteInboundRatchetProven]. */
    private fun noteRatchetSendLanded(contactId: String) {
        // Best effort: a stale count only over-warns.
        deleteMetaIfPresentBestEffort(drLegacyFallbackKey(contactId))
    }

    // --- The both-Alice detector + the refusal ---------------------------------

    /**
     * Consecutive inbound TEXT drains that carried blobs but no decryptable ratchet
     * blob, while this device had already sent [RATCHET_SENDS_BEFORE_UNACKED_EVIDENCE]
     * unanswered ratchet blobs. 0 in the healthy steady state, and 0 whenever the value
     * is missing or unreadable — the same fail direction as [ratchetFallbackCount]
     * (absence is never evidence). Crosses the Swift bridge; never throws.
     */
    fun ratchetUnackedCount(contactId: String): Int = try {
        databaseManager.getMeta(drRatUnackedKey(contactId))?.toIntOrNull()?.coerceAtLeast(0) ?: 0
    } catch (_: Exception) { 0 }

    /**
     * True when the secure channel with [contactId] has provably failed to establish
     * and this device therefore REFUSES to send its text on the static envelope —
     * "re-pair this contact". Read by the conversation UI on both
     * platforms, beside [forwardSecrecyStalled], with the same access pattern.
     *
     * The durable latch is the authority and the send gate reads only that (one vault
     * lookup); this reader additionally reports the evidence itself, so a latch write
     * that failed transiently still surfaces. Never throws, and fails toward NOT
     * refused on an unreadable vault: a false "refused" would tell a user to re-pair a
     * healthy contact, and a false "fine" costs at most one more legacy send, which is
     * the level the pairing is already running at.
     *
     * Cleared by the first inbound ratchet blob that decrypts, and by a re-pair
     * (`deleteContact` purges [drRefusedKey] with the rest of the per-contact set).
     */
    fun ratchetRefused(contactId: String): Boolean = try {
        refusalLatched(contactId) ||
            ratchetFallbackCount(contactId) >= RATCHET_FALLBACK_STALL_THRESHOLD ||
            ratchetUnackedCount(contactId) >= RATCHET_UNACKED_REFUSE_THRESHOLD
    } catch (_: Exception) { false }

    /** The durable latch alone — the cheap read the send gate uses. Absent ⇒ false. */
    private fun refusalLatched(contactId: String): Boolean = try {
        databaseManager.getMeta(drRefusedKey(contactId)) == "1"
    } catch (_: Exception) { false }

    /** Arms the refusal latch once, idempotently, and logs the crossing exactly once. */
    private fun armRatchetRefusal(contactId: String) {
        try {
            if (refusalLatched(contactId)) return
            databaseManager.putMeta(drRefusedKey(contactId), "1")
            // Counts only, no identifier: which of the two detectors fired, and at what
            // count — enough to tell a both-Bob collision from a both-Alice one in a
            // bug report without naming the conversation.
            platformLogWarn(
                LOG_TAG,
                "ratchet role collision refused for one contact: " +
                    "${ratchetFallbackCount(contactId)} consecutive legacy fallbacks, " +
                    "${ratchetUnackedCount(contactId)} consecutive unacked receives",
            )
        } catch (_: Exception) { /* best effort — re-armed by the next piece of evidence */ }
    }

    /**
     * POSITIVE evidence that the peer's ratchet is compatible with ours: at least one
     * inbound blob on this drain decrypted through the ratchet. Clears BOTH detectors
     * and the refusal, so a relay that stops dropping ratchet blobs — or a peer that
     * re-pairs/recovers — restores the conversation with no user action.
     *
     * Accepted from EITHER channel (a ratchet-sealed announce decrypted on the control inbox
     * advances the same text ratchet), unlike the increment below, which only counts
     * the channel where a ratchet blob is actually expected. Every write is gated on a
     * read, so the steady state (nothing set) costs three lookups and zero writes.
     */
    private fun noteInboundRatchetProven(contactId: String) {
        try {
            if (databaseManager.getMeta(drRatUnackedKey(contactId)) != null) {
                databaseManager.deleteMeta(drRatUnackedKey(contactId))
            }
            if (databaseManager.getMeta(drLegacyFallbackKey(contactId)) != null) {
                databaseManager.deleteMeta(drLegacyFallbackKey(contactId))
            }
            if (databaseManager.getMeta(drRefusedKey(contactId)) != null) {
                databaseManager.deleteMeta(drRefusedKey(contactId))
            }
        } catch (_: Exception) { /* best effort — a stale count only over-warns */ }
    }

    /**
     * One inbound TEXT drain that carried blobs and produced no decryptable ratchet
     * blob. Counted ONLY when this device has already sent
     * [RATCHET_SENDS_BEFORE_UNACKED_EVIDENCE] ratchet blobs since the peer's ratchet
     * last provably answered (the ratchet's own send counter, which resets on every
     * receiving DH step) — so a device with no sending chain, a contact that never
     * ratcheted, and every honest one-directional burst are all structurally excluded.
     *
     * A blob we dropped for any reason (undecryptable ratchet wire, legacy blob dropped
     * by the receive lock, replay, malformed) still counts as "the peer answered and the
     * ratchet did not work": in the both-Alice collision the peer's blobs ARE ratchet
     * wires that cannot decrypt, so requiring a cleanly-accepted legacy message here
     * would make the detector blind to the very case it exists for. A hostile relay can
     * serve junk to drive this counter, which is the trade-off stated plainly — and it
     * gains nothing by it, since a device that still holds a sending chain is never
     * blocked by the refusal, only told about it.
     */
    private fun noteRatchetUnackedReceive(contactId: String) {
        try {
            if (!ratchetSendOn(contactId)) return
            if (!ratchetManager.hasSentAtLeast(
                    contactId, RATCHET_TEXT_CHANNEL, RATCHET_SENDS_BEFORE_UNACKED_EVIDENCE,
                )
            ) return
            val cur = ratchetUnackedCount(contactId)
            val next = if (cur >= RATCHET_UNACKED_COUNT_CAP) cur else cur + 1
            databaseManager.putMeta(drRatUnackedKey(contactId), next.toString())
            if (next == RATCHET_UNACKED_REFUSE_THRESHOLD) {
                // Counts only — never an identifier.
                platformLogWarn(
                    LOG_TAG,
                    "ratchet blobs unanswered for one contact — $next consecutive inbound " +
                        "drains with no decryptable ratchet blob",
                )
            }
            if (next >= RATCHET_UNACKED_REFUSE_THRESHOLD) armRatchetRefusal(contactId)
        } catch (_: Exception) { /* best effort — an uncounted drain only delays the signal */ }
    }

    /**
     * Persist the peer's control-ratchet adverts. [cap] latches
     * [drCtlCapKey]; [watermark] — already filtered by the caller to ratchet blobs
     * decrypted past the bootstrap window — keeps the LOWEST value ever proven
     * (each one is a true commitment, and the earliest is the tightest). Every write
     * is gated on a read (steady state: two lookups, zero writes) and on the contact
     * still existing (a delete during the poll's round trip must not resurrect
     * satellite state). Best effort: a lost write only delays the gate it feeds.
     */
    private fun recordPeerCtlAdverts(
        contactId: String, cap: Boolean, watermark: Long?, capStep: Int? = null, withdraw: Boolean = false,
    ) {
        if (!cap && watermark == null && !withdraw) return
        try {
            if (!contactExists(contactId)) return
            if (withdraw) {
                // (see the caller): the peer now runs a build without sealed control.
                if (databaseManager.getMeta(drCtlCapKey(contactId)) != null ||
                    databaseManager.getMeta(drCtlWatermarkKey(contactId)) != null
                ) {
                    databaseManager.deleteMeta(drCtlCapKey(contactId))
                    databaseManager.deleteMeta(drCtlWatermarkKey(contactId))
                    databaseManager.deleteMeta(drCtlCapStepKey(contactId))
                    platformLogWarn(LOG_TAG, "sealed control withdrawn: the peer's build no longer advertises it")
                }
                return
            }
            if (capStep != null) {
                val cur = peerCtlCapStep(contactId)
                if (cur == null || capStep > cur) databaseManager.putMeta(drCtlCapStepKey(contactId), capStep.toString())
            }
            if (cap && databaseManager.getMeta(drCtlCapKey(contactId)) != "1") {
                databaseManager.putMeta(drCtlCapKey(contactId), "1")
            }
            if (watermark != null && watermark >= 0L) {
                val cur = peerCtlWatermark(contactId)
                if (cur == null || watermark < cur) {
                    databaseManager.putMeta(drCtlWatermarkKey(contactId), watermark.toString())
                }
            }
        } catch (_: Exception) { /* best effort — see kdoc */ }
    }

    /**
     * Arm the sticky text receive-lock (dr-rxlock) iff the
     * ratchet has advanced past the sharedSecret-forgeable bootstrap window
     * (DoubleRatchet.hasRatchetedPastBootstrap → >= 2 receiving DH steps). Called on
     * EVERY text poll so the lock arms as soon as local state is past-bootstrap —
     * a hostile relay cannot keep the receiver un-armed by delivering one genuine
     * ratchet blob then suppressing the rest — while a single forged bootstrap
     * message (which drives only ONE receiving DH step) never arms it. The
     * getMeta check keeps the common (already-armed) case cheap; the ratchet-state
     * load only runs while a contact is un-armed.
     *
     * Known limitations:
     *  - dhRecvSteps reaches 2 only if the peer sends AGAIN with a new key, so
     *    a mostly one-directional / peer-went-silent pairing stalls at 1 forever and
     *    NEVER arms — legacy static-key blobs stay accepted there. This is the price
     *    of the 2-step gate; it is NOT strictly stronger than the old
     *    single-decrypt arming, just harder to trip maliciously.
     *  - Even at 2 steps, arming is forgeable under sharedSecret + write-cap +
     *    header observation (see drRecvLockKey). This is best-effort downgrade
     *    protection, not an unforgeability guarantee.
     */
    private fun maybeArmRecvLock(contactId: String, armedFrom: Chan = Chan.MAIN) {
        if (databaseManager.getMeta(drRecvLockKey(contactId)) == "1") return
        if (!ratchetManager.hasRatchetedPastBootstrap(contactId, RATCHET_TEXT_CHANNEL)) return
        // A TEXT drain that arms the lock read it at its start, so its own
        // legacy blobs were still accepted — the lock's one-poll grace. A CONTROL drain that
        // arms it gives the text channels no such drain, so the grace is recorded
        // explicitly FIRST (never a lock without its grace) and consumed by the next
        // drain of each text channel.
        if (!armedFrom.isText) {
            try {
                databaseManager.putMeta(drRecvLockGraceKey(contactId), "${Chan.MAIN.tag},${Chan.GRP.tag}")
            } catch (_: Exception) { return }   // no grace recorded ⇒ do not arm from here
        }
        putMetaBestEffort(drRecvLockKey(contactId), "1")
    }

    /** Is [chan]'s one-drain grace still owed? Unreadable ⇒ no grace
     *  (the pre-fix behaviour; the lock itself is the security property). */
    private fun graceOwed(contactId: String, chan: Chan): Boolean = try {
        databaseManager.getMeta(drRecvLockGraceKey(contactId))?.split(',')?.contains(chan.tag) == true
    } catch (_: Exception) { false }

    private fun consumeGrace(contactId: String, chan: Chan) {
        try {
            val left = (databaseManager.getMeta(drRecvLockGraceKey(contactId)) ?: return)
                .split(',').filter { it.isNotEmpty() && it != chan.tag }
            if (left.isEmpty()) databaseManager.deleteMeta(drRecvLockGraceKey(contactId))
            else databaseManager.putMeta(drRecvLockGraceKey(contactId), left.joinToString(","))
        } catch (_: Exception) { /* best effort — a stale grace costs one more legacy drain */ }
    }

    // --- Deferred sealed control -----------------------------------------------
    // The wire is ratchet ciphertext only — no key material; the ratchet state that
    // opens it is in the same vault anyway.

    /** One deferred sealed-control wire: when it was first deferred, how long it may
     *  stay deferred, and the ratchet ciphertext itself. */
    private class DeferredCtl(val stampMs: Long, val maxAgeMs: Long, val wire: ByteArray)

    // Stored as `<stampMs>:<maxAgeMs>:<base64 wire>` entries joined by ',' (none of
    // the separators is in the base64 alphabet).
    private fun loadDeferredCtl(contactId: String): List<DeferredCtl> = try {
        val raw = databaseManager.getMeta(drCtlDeferredKey(contactId))
        if (raw.isNullOrEmpty()) emptyList()
        else raw.split(',').mapNotNull { e ->
            val parts = e.split(':')
            if (parts.size != 3) return@mapNotNull null
            val stamp = parts[0].toLongOrNull() ?: return@mapNotNull null
            val age = parts[1].toLongOrNull()?.coerceIn(0L, CTL_DEFER_MAX_AGE_MS) ?: return@mapNotNull null
            val wire = try { decodeBase64(parts[2]) } catch (_: Exception) { null }
            if (wire == null || wire.isEmpty()) null else DeferredCtl(stamp, age, wire)
        }.sortedBy { it.stampMs }
    } catch (_: Exception) { emptyList() }

    /** Does [contactId] hold deferred sealed control? The control sweep drains
     *  such a contact even when its peek answers 0, so the deferral is retried / aged. */
    internal fun hasDeferredSealedControl(contactId: String): Boolean = hasDeferredCtl(contactId)

    /**
     * Must the control sweep DRAIN [contactId] even though its control inbox
     * peeked empty? Only when a deferral is actually DUE — a held entry whose hold has
     * expired (or is over the count bound), or a retry the text path requested after
     * draining texts. A deferral merely being held is NOT a reason: draining and
     * re-peeking every sweep would be a steady per-contact pattern on the wire.
     */
    internal fun sealedControlDrainDue(contactId: String): Boolean {
        if (!hasDeferredCtl(contactId)) return false
        if (sealedControlCatchUpLock.withLock { contactId in deferredRetryRequested }) return true
        val entries = loadDeferredCtl(contactId)
        val now = currentTimeMillis()
        val forcedCount = entries.size - minOf(entries.size, MAX_DEFERRED_CTL_RETRY)
        return entries.withIndex().any { (i, d) -> deferralForced(i, forcedCount, d, now) }
    }

    /** A stored deferral that must be processed now: over the retry bound, past its
     *  own hold, or stamped in the FUTURE (clock stepped back — fail toward processing,
     *  never toward a deferral that could outlive its bound). */
    private fun deferralForced(index: Int, forcedCount: Int, d: DeferredCtl, nowMs: Long): Boolean =
        index < forcedCount || nowMs < d.stampMs || nowMs - d.stampMs >= d.maxAgeMs

    private fun hasDeferredCtl(contactId: String): Boolean = try {
        !databaseManager.getMeta(drCtlDeferredKey(contactId)).isNullOrEmpty()
    } catch (_: Exception) { false }

    /** Replaces the stored deferral list with [entries], keeping the NEWEST within
     *  [MAX_DEFERRED_CTL_STORED] entries and [MAX_DEFERRED_CTL_BYTES] wire bytes; the
     *  oldest beyond [MAX_DEFERRED_CTL_RETRY] are force-processed by the next drain. */
    private fun storeDeferredCtl(contactId: String, entries: List<DeferredCtl>) {
        try {
            if (!contactExists(contactId)) return   // never resurrect
            val kept = ArrayList<DeferredCtl>()
            var bytes = 0
            for (e in entries.sortedByDescending { it.stampMs }) {
                if (kept.size >= MAX_DEFERRED_CTL_STORED || bytes + e.wire.size > MAX_DEFERRED_CTL_BYTES) break
                kept.add(e); bytes += e.wire.size
            }
            kept.reverse()
            if (kept.size < entries.size) {
                platformLogWarn(LOG_TAG, "sealed control: deferral store full — ${entries.size - kept.size} oldest blob(s) dropped")
            }
            if (kept.isEmpty()) databaseManager.deleteMeta(drCtlDeferredKey(contactId))
            else databaseManager.putMeta(
                drCtlDeferredKey(contactId),
                kept.joinToString(",") { "${it.stampMs}:${it.maxAgeMs}:${encodeBase64(it.wire)}" },
            )
        } catch (e: Exception) {
            platformLogWarn(LOG_TAG, "sealed control: deferral store write failed: ${e::class.simpleName}")
        }
    }

    /** Undrained blobs waiting in [contactId]'s TEXT + GROUP inboxes, by
     *  non-destructive peek; null = unknown (any peek failed). A pairing with no group
     *  row counts that inbox as 0 without a request. */
    private fun peekUndrainedTextCount(contactId: String): Int? {
        val now = currentTimeMillis()
        sealedControlCatchUpLock.withLock {
            undrainedPeekCache[contactId]?.let { (at, n) ->
                if (now >= at && now - at < UNDRAINED_PEEK_CACHE_MS) return n
            }
        }
        val n = peekUndrainedTextCountUncached(contactId)
        // Only a definite answer is cached; an unknown one is re-asked next time.
        if (n != null) sealedControlCatchUpLock.withLock {
            if (undrainedPeekCache.size >= MAX_SEALED_CONTROL_CATCH_UPS) {
                undrainedPeekCache.keys.firstOrNull()?.let { undrainedPeekCache.remove(it) }
            }
            undrainedPeekCache[contactId] = now to n
        }
        return n
    }

    private fun peekUndrainedTextCountUncached(contactId: String): Int? {
        val text = try { peekInbox(contactId) } catch (_: Exception) { null } ?: return null
        val hasGrp = try {
            databaseManager.getInboxIdForContact(contactId, DIR_INBOUND_GRP) != null
        } catch (_: Exception) { return null }
        val grp = if (!hasGrp) 0 else (try { peekGroupInboxPending(contactId) } catch (_: Exception) { null } ?: return null)
        return text + grp
    }

    /** The newest receiving-step ordinal at which an advert-bearing
     *  envelope was decrypted in order; null = never (or unreadable). */
    private fun peerCtlCapStep(contactId: String): Int? = try {
        databaseManager.getMeta(drCtlCapStepKey(contactId))?.toIntOrNull()?.takeIf { it >= 0 }
    } catch (_: Exception) { null }

    /** Decode magic-stripped ratchet wire blobs into displayable messages,
     *  advancing/persisting the ratchet per blob. Tampered / replayed /
     *  undecryptable blobs drop. */
    private fun receiveOverTextRatchet(
        contactId: String, contact: ContactRecord, wires: List<ByteArray>,
        // WHICH inbox these wires were drained from. All three channels ride the one
        // text ratchet, so the chain cannot tell them apart — this is what applies
        // the per-inbox routing rules:
        //   CTL       — the inbox announce and the integrity-critical control
        //     kinds ([isRatchetSealedControlKind]) legitimately ride the control
        //     inbox sealed; anything else is a relay splice.
        //   GRP       — a group TEXT and nothing else: no control kind, and a "g".
        // A dropped blob still consumed its ratchet message key, which is the same
        // outcome as the relay having dropped it.
        chan: Chan = Chan.MAIN,
        // Invoked once if ANY wire in this drain decrypted through the
        // ratchet — the positive evidence that the two roles are compatible. A local
        // callback rather than a field, so the text and control polls (different
        // coroutines) can never see each other's result.
        onRatchetDecrypted: () -> Unit = {},
        // Every ratchet envelope that decrypted AND parsed, before any routing
        // drop — the peer's [CTL_RATCHET_CAP_FIELD] / [CTL_RATCHET_WATERMARK_FIELD]
        // adverts are facts about the PEER, true whatever this blob carried.
        // The second argument says where the wire sat in the peer's chain history
        // (opened from a skipped key? which receiving step?) — what the sealed-control
        // downgrade signal needs to tell a NEWER cap-less envelope from a stale one.
        onEnvelope: (Envelope, RatchetManager.WireOrigin?) -> Unit = { _, _ -> },
        // Defer (never decrypt) wires that would destroy undrained text
        // keys — see [RatchetManager.decryptBatch]. Their indices land in [report].
        deferDamaging: Boolean = false,
        report: RatchetManager.DecryptBatchReport? = null,
        // Retrieve-ack: a conversation screen's drain keeps the advance uncommitted
        // (see [RatchetManager.decryptBatch]); [drainGroup] is its drain group — an
        // opaque identity token for one screen poll, unrelated to group messaging.
        drainGroup: Any? = null,
    ): List<ReceivedMessage> {
        val batchReport = report ?: RatchetManager.DecryptBatchReport()
        val (myInbound, myOutbound) = textInboxIds(contactId) ?: run {
            // No role inputs, so nothing is decrypted. Under the retrieve lease what
            // happens to these wires is decided here:
            //  - the contact row is GONE (deleted while this drain was in flight): the
            //    wires are left REJECTED, i.e. acked — nothing will ever drain this
            //    inbox again (a drain needs the contact row) and the delete path
            //    destroys the inbox on the relay anyway;
            //  - otherwise (the contact is there, or the read threw): a missing TEXT
            //    row is not proof the mail is dead — a secret-only pairing still
            //    waiting for the peer's inbox announce, or an iOS read of a vault that
            //    is not answering (the bridge returns no rows on a SQLite error) — so
            //    every wire is NOT_PROCESSED: not acked, the relay hands it back after
            //    the lease. Bounded: by the blob's relay TTL, and only while this
            //    contact is still being drained.
            val contactGone = try { !contactExists(contactId) } catch (_: Exception) { false }
            if (!contactGone) batchReport.notProcessed.addAll(wires.indices)
            if (wires.isNotEmpty()) {
                platformLogWarn(
                    LOG_TAG,
                    if (contactGone) "ratchet drain: no text inbox ids, contact gone — discarding ${wires.size} blob(s)"
                    else "ratchet drain: no text inbox ids — ${wires.size} blob(s) left for the next drain",
                )
            }
            return emptyList()
        }
        val out = mutableListOf<ReceivedMessage>()
        // UI id ("dr-{n}", see [receiveDedupeId]): ratchet messages have no sender
        // counter, so n comes from the process-wide RAM [RatchetReceiveIds] — never
        // persisted (the old per-contact `dr-rxc` lifetime count was message volume at
        // rest). The relay can re-deliver under the lease; a re-delivered blob whose key
        // the ratchet already consumed fails decrypt as a replay and takes no id.
        var consumedIds = false
        // Decrypt the WHOLE drain against one ratchet load (not one
        // SQLCipher reload + deserialize per blob), so a relay can't amplify per-poll
        // DB/CPU/battery by stuffing thousands of forged ratchet blobs. Drops
        // (tamper / replay / malformed / too short) come back as null, in order.
        val decrypted = ratchetManager.decryptBatch(
            contactId, RATCHET_TEXT_CHANNEL, contact.sharedSecret, myInbound, myOutbound, wires,
            // Same resolved role as the send path — a receive that
            // happens to be the first ratchet op for this contact must init into the
            // role the pairing fixed, not the one the current outbound row implies.
            selfIsBobOverride = ratchetSelfIsBobOverride(contactId, contact),
            deferDamaging = deferDamaging,
            report = batchReport,
            maxDeferrableWireBytes = MAX_DEFERRABLE_CTL_WIRE_BYTES,
            persist = drainGroup == null,
            drainGroup = drainGroup,
        )
        // (2026-09-11) A ratchet blob that fails to decrypt used to vanish
        // with NO log line anywhere — the only COMPLETELY silent drop left on the
        // receive path, and the reason `cross:move-i2i`'s "the relay delivered it,
        // nothing rendered" could not be root-caused from device logs. Report it.
        // What is logged is the COUNT plus each dropped blob's header indices: the
        // ratchet header (sender pubkey ‖ PN ‖ N) travels in the CLEAR on the wire,
        // so PN/N are already relay-visible and naming them here discloses nothing
        // new — while they are exactly what separates a chain DESYNC (plausible
        // PN/N that still will not open) from a MAX_SKIP refusal (PN far past our
        // receiving chain) and from a forged/replayed blob. No key material, no
        // inbox id, no plaintext. Both platforms route this into LogBuffer.
        // One AEAD-authenticated ratchet blob is proof enough — report it
        // BEFORE the envelope/routing checks below, which drop perfectly valid ratchet
        // blobs (a non-announce blob on the control inbox, an unknown control kind)
        // whose decryption is exactly the evidence we need.
        if (decrypted.any { it != null }) onRatchetDecrypted()
        // A DEFERRED wire is not a drop — it is kept in the vault and retried.
        val deferredIdx = batchReport.deferred.keys
        if (deferredIdx.isNotEmpty()) {
            platformLogWarn(LOG_TAG, "sealed control: ${deferredIdx.size} blob(s) deferred behind an undrained text backlog")
        }
        // Retrieve-ack: a wire the batch never looked at (cutoff tail, spent budget,
        // held behind an uncommitted screen advance) is not a drop — the relay hands
        // it back because it is not acked.
        val notProcessedIdx = batchReport.notProcessed
        val droppedWires = decrypted.indices.count { decrypted[it] == null && it !in deferredIdx && it !in notProcessedIdx }
        if (droppedWires > 0) {
            // A duplicate shortly after an ack that was never confirmed is the relay
            // RE-DELIVERING (lease expired before the ack landed), not a replay —
            // indistinguishable cryptographically, so this is a label only.
            val why = if (likelyRedelivery(contactId, chan)) "likely re-delivery after a lost ack"
                else "tamper / replay / chain desync"
            platformLogWarn(
                LOG_TAG,
                "ratchet drop: $droppedWires of ${wires.size} blob(s) on the ${chan.logLabel} inbox " +
                    "failed to decrypt ($why)${describeUndecryptableWires(wires, decrypted, notProcessedIdx)}",
            )
        }
        for ((wireIndex, padded) in decrypted.withIndex()) {
            if (padded == null) continue
            val plaintext = try { unpadMessage(padded) } catch (_: Exception) {
                platformLogWarn(LOG_TAG, "ratchet: padding validation failed"); continue
            }
            // Same blind spot, one layer in: a decrypted-but-unparseable payload was
            // dropped silently too. It can only come from a peer on a newer envelope
            // format, so it is worth a line and never an error.
            val env = parseEnvelope(plaintext.decodeToString())
            if (env == null) {
                platformLogWarn(LOG_TAG, "ratchet drop: envelope did not parse"); continue
            }
            onEnvelope(env, batchReport.decrypted[wireIndex])
            if (env.groupId != null && !isValidGroupId(env.groupId)) {
                platformLogWarn(LOG_TAG, "ratchet drop: malformed group id"); continue
            }
            if (env.controlKind != null && env.controlKind.length > MAX_CONTROL_KIND_CHARS) {
                platformLogWarn(LOG_TAG, "ratchet drop: malformed control kind"); continue
            }
            // The GROUP inbox carries group TEXT and nothing else — checked BEFORE
            // the announce branch below, so a routing-rewriting announce can never be
            // applied off the group inbox (the same rule the control inbox applies in
            // reverse). Mirrors the static path's guard in [legacyDropReason].
            if (chan == Chan.GRP && (env.controlKind != null || env.groupId == null)) {
                platformLogWarn(LOG_TAG, "ratchet drop: non-group-text blob on the group inbox"); continue
            }
            // A direct inbox announce can also ride the (established) ratchet —
            // and MUST, once the peer's receive lock is armed.
            if (env.controlKind == CONTROL_KIND_INBOX && env.groupId == null) {
                applyInboxAnnounce(contactId, env.controlBody); continue
            }
            // Besides the announce, the control inbox now legitimately carries
            // the integrity-critical control kinds sealed by the ratchet — the referral
            // handshake and group membership control. Anything else (a bare text, a
            // chatty kind, an unknown kind) is still a relay splice and is dropped.
            // The allowlist is the SAME predicate the sender seals by, so the two can
            // never drift. Surfaced exactly like their legacy copies, with no UI id:
            // control items never reach a conversation list, so they take no
            // [RatchetReceiveIds] number.
            if (chan == Chan.CTL) {
                if (!isRatchetSealedControlKind(env.controlKind, groupScoped = env.groupId != null)) {
                    platformLogWarn(LOG_TAG, "ratchet drop: unsealable ratchet blob on the control inbox"); continue
                }
                out.add(env.toReceived())
                continue
            }
            // 1:1 screenshot notice — applied, never surfaced (mirrors the announce
            // above). Replay protection here is the ratchet's own (one-shot message
            // keys), not the epoch/counter pair the legacy path uses. `env.timestamp`
            // is the sender's minute-rounded capture time, carried through for
            // display only (see noteScreenshotNotice).
            if (env.controlKind == CONTROL_KIND_SCREENSHOT && env.groupId == null) {
                noteScreenshotNotice(contactId, env.timestamp); continue
            }
            if (env.groupId == null && env.controlKind != null &&
                !isKnownDirectControlKind(env.controlKind)
            ) {
                platformLogWarn(LOG_TAG, "ratchet drop: unknown direct control"); continue
            }
            val rxId = RatchetReceiveIds.next()
            consumedIds = true
            out.add(env.toReceived(counter = rxId, dedupeId = receiveDedupeId(ratchet = true, counter = rxId)))
        }
        // Migrate-on-write: a vault written by an older build still holds the retired
        // per-contact count. Deleted on the first drain that surfaced a text (one read,
        // the same as the old read-modify-write; a delete only when the key is there).
        if (consumedIds) deleteMetaIfPresentBestEffort(drRxCounterKey(contactId))
        return out
    }

    /**
     * `" [pn=..,n=..]"` for each wire `RatchetManager.decryptBatch` refused,
     * appended to the drop warning above. Header-only and best effort — it re-parses the CLEARTEXT
     * 40-byte header the wire already carries (never the ciphertext, never a key),
     * and an unparseable one is reported as such rather than thrown. Runs only on
     * the drop path, so the healthy poll pays nothing.
     */
    private fun describeUndecryptableWires(wires: List<ByteArray>, decrypted: List<ByteArray?>, skip: Set<Int> = emptySet()): String {
        val sb = StringBuilder()
        for (i in wires.indices) {
            if (i >= decrypted.size || decrypted[i] != null || i in skip) continue
            val header = try { decodeRatchetWire(wires[i]).header } catch (_: Exception) { null }
            if (header == null) sb.append(" [unparseable header]")
            else sb.append(" [pn=${header.pn},n=${header.n}]")
        }
        return sb.toString()
    }

    /**
     * Promote a ratchet-capable contact (intent marker set) to SEND-ratchet
     * (dr-on) once BOTH text inboxes exist AND we've received ≥1 message from
     * the peer (dr-rxseen). Gating on rxseen keeps the FIRST exchange on the
     * legacy envelope — the unavoidable bootstrap cost — and guarantees both
     * devices are fully paired before either starts sending ratchet, so they
     * converge without a mid-pairing format split. Idempotent; safe to call from
     * the poll loop. No-ops for any contact that never paired under this build.
     */
    private fun enableRatchetIfReady(contactId: String) {
        if (databaseManager.getMeta(drOnKey(contactId)) == "1") return        // already on
        if (databaseManager.getMeta(drIntentKey(contactId)) != "1") return    // not ratchet-capable
        if (databaseManager.getMeta(drRxSeenKey(contactId)) != "1") return    // peer not confirmed yet
        if (textInboxIds(contactId) == null) return                          // inbox pair incomplete
        try { databaseManager.putMeta(drOnKey(contactId), "1") } catch (_: Exception) { return }
        platformLog(LOG_TAG, "ratchet enabled for a contact")
    }

    private fun pollChannel(contactId: String, chan: Chan, acks: AckBatch? = null): List<ReceivedMessage> {
        val prepared = prepareDrain(contactId, chan) ?: return emptyList()
        return finishDrain(prepared, fetchDrain(prepared), acks)
    }

    /** [pollMessages] / [pollControlMessages] / [pollGroupInbox] with the retrieve-ack
     *  collected into [acks] instead of sent at once — a sweep or a group fan-out
     *  sends ONE `POST /ack` for every inbox it drained ([flushAcks]), after it has
     *  applied what came back. */
    internal fun pollChannelAcking(contactId: String, chan: Chan, acks: AckBatch): List<ReceivedMessage> =
        pollChannel(contactId, chan, acks)

    // -----------------------------------------------------------------------
    // Retrieve-ack (2026-11-03, docs/vault-relay-internals.md "Retrieve-ack").
    // Every drain asks the relay to
    // LEASE (`GET /inbox/{id}?lease=1`): nothing is deleted at fetch, the blobs are
    // hidden from every other retrieve and peek for the lease, and `POST /ack`
    // deletes the ones we PROCESSED and releases the rest at once. A response lost
    // over Tor, or an app torn down with a poll in flight, therefore costs a
    // re-delivery (dropped by the anti-replay) instead of a message.
    //
    // Per blob the drain decides one [BlobOutcome]; everything but NOT_PROCESSED is
    // acked. WHEN it is acked:
    //  - background drains (the control sweep, the connect-time pre-drain, the
    //    group fan-out and every plain poll*) persist ratchet / counter state exactly
    //    as before, THEN ack (fire-and-forget, batched per pass);
    //  - a conversation screen ([pollChannelPending], GroupManager.pollGroupPending /
    //    pollDirectPending) decrypts WITHOUT persisting and gets a [PendingDrain];
    //    its commit() — after the messages are on screen — persists, then acks. No
    //    commit (teardown, navigation mid-poll) ⇒ nothing persisted, nothing acked ⇒
    //    the relay re-delivers after its lease and the blobs decrypt again.
    // -----------------------------------------------------------------------

    /** What happened to ONE blob of a drain. */
    internal enum class BlobOutcome {
        /** Decrypted and taken: surfaced, or applied (announce, notice, control). */
        ACCEPTED,
        /** Looked at and refused for good: tamper, malformed, replay / duplicate /
         *  re-delivery, wrong channel or epoch, unknown kind, a routing drop. */
        REJECTED,
        /** A sealed control wire parked in the vault deferral store. */
        DEFERRED,
        /** Not looked at (cutoff tail, spent work budget, beyond the per-poll cap,
         *  held behind an uncommitted screen advance, a baseline that could not be
         *  persisted). NEVER acked — the relay hands it back. */
        NOT_PROCESSED,
    }

    /** What an acked blob's ack DEPENDS on in a pending (screen) drain. */
    private enum class AckDep { NONE, RATCHET, LEGACY }

    /** One inbox's settle request: delete [deleteIds], release every other blob of
     *  [token]. [labelKey] is RAM-only bookkeeping for the re-delivery log label. */
    internal class AckItem(
        val inboxId: String,
        val readCap: String,
        val token: String,
        val deleteIds: List<String>,
        val labelKey: String,
    )

    /** Collects the acks of several drains for ONE `POST /ack` ([flushAcks]). */
    internal class AckBatch {
        private val lock = SyncLock()
        private val items = mutableListOf<AckItem>()
        fun add(item: AckItem) = lock.withLock { items.add(item) }
        fun take(): List<AckItem> = lock.withLock { items.toList().also { items.clear() } }
    }

    /** Sends everything [batch] collected (fire-and-forget). Never throws. */
    internal fun flushAcks(batch: AckBatch) {
        try { sendAcks(batch.take()) } catch (e: Exception) {
            platformLogWarn(LOG_TAG, "retrieve-ack: flush failed: ${e::class.simpleName}")
        }
    }

    internal class DrainOutcome(
        val messages: List<ReceivedMessage>,
        /** Persist-mode ack (already decided), or null. */
        val ack: AckItem?,
        /** Pending-mode commit unit, or null. */
        val part: PendingPart?,
    ) {
        companion object { val EMPTY = DrainOutcome(emptyList(), null, null) }
    }

    /** The leased-retrieve fields: [token] names the lease; [ids] parallels the blobs,
     *  null when the relay's ids are missing / malformed (then nothing can be acked by
     *  id and the lease simply expires). */
    private class Lease(val token: String, val ids: List<String>?)

    /**
     * The `?lease=1` answer's `token` / `ids`, validated as UNTRUSTED relay input:
     * both are 22-char base64url ([isValidBlobRef]) before they can ever reach an ack
     * body, and `ids` must be exactly as long as `blobs`. null = no lease (an
     * empty inbox's `""` token, or a relay that predates the lease and therefore
     * deleted at fetch, exactly as before).
     */
    private fun parseLease(body: String, blobCount: Int): Lease? {
        val token = try { firstStringFieldAnywhere(body, "token") } catch (_: Exception) { null }
        if (token.isNullOrEmpty()) return null
        if (!isValidBlobRef(token)) {
            platformLogWarn(LOG_TAG, "retrieve-ack: malformed lease token — nothing will be acked for this drain")
            return null
        }
        val ids = try { parseStringArrayField(body, "ids") } catch (_: Exception) { null }
        if (ids == null || ids.size != blobCount || !ids.all { isValidBlobRef(it) }) {
            platformLogWarn(LOG_TAG, "retrieve-ack: lease ids missing or malformed — the lease will expire instead")
            return Lease(token, null)
        }
        return Lease(token, ids)
    }

    /**
     * One pending (screen) drain of one inbox: what its commit must persist and
     * which blob ids each persist decides. Created by [finishDrainCore] in pending
     * mode; settled exactly once by [commitPendingPartAck] or [abandonPendingParts].
     */
    internal class PendingPart internal constructor(
        internal val contactId: String,
        internal val chan: Chan,
        /** The screen poll's drain-session token (identity only — not group messaging). */
        internal val drainGroup: Any,
        internal val inboxId: String,
        internal val readCap: String,
        /** null = the relay did not lease (it deleted at fetch): committed inline. */
        internal val token: String?,
        internal val freeIds: List<String>,
        internal val ratchetIds: List<String>,
        internal val legacyIds: List<String>,
        internal val ratchetTicket: RatchetManager.PendingTicket?,
        internal val ratchetBase: RatchetManager.PendingTicket?,
        /** The legacy baseline to persist at commit (null = nothing advanced). */
        internal val legacyBaseline: Long?,
        internal val legacyEpoch: String,
        internal val consumeGrace: Boolean,
        internal val createdAtMs: Long,
    ) {
        // Guarded by MessageManager.pendingLock.
        internal var settled = false
        internal var leaseReleased = false
        internal var legacyDiscarded = false
    }

    /**
     * `contactId|chanTag → the pending part whose legacy baseline is not yet
     * persisted`. The strict-monotonic counter cannot accept a lower counter once a
     * higher one is persisted, so while a screen drain's legacy advance is
     * uncommitted, no OTHER drain of that channel may persist past it (see
     * [legacyPendingBlocks]). In-RAM contact ids: emptied by [scrubInMemory].
     * PROCESS-wide, not per instance: a Tor restart rebuilds MessageManager without
     * a scrub while the vault (and its baselines) stays the same, so an old
     * instance's uncommitted screen drain must still hold the new instance's drains.
     */
    private val pendingLegacy: MutableMap<String, PendingPart> get() = PendingLegacyRegistry.map

    /** Guards [pendingLegacy], every [PendingPart] flag, and is the scrub FENCE for
     *  commit-time vault writes (held across the legacy persist; never across I/O). */
    private val pendingLock: SyncLock get() = PendingLegacyRegistry.lock

    /** Set by [scrubInMemory]: no ack is launched or sent and no commit writes after it. */
    @Volatile
    private var acksClosed = false

    private val ackJob = SupervisorJob()
    private val ackScope = CoroutineScope(ackJob + ioDispatcher)

    /** Where a `POST /ack` runs. Test seam (production: an IO coroutine, never the
     *  caller's thread — a poll result or a commit never waits on the round trip). */
    internal var ackLauncher: (() -> Unit) -> Unit = { work -> ackScope.launch { work() } }

    /** `contactId|chanTag → when an ack for it was last sent and not yet confirmed`.
     *  Feeds the "re-delivery" log label only. RAM-only, bounded, scrubbed. */
    private val ackUnconfirmed = mutableMapOf<String, Long>()
    private val ackUnconfirmedLock = SyncLock()

    // One key per (contact, channel), with TWO roles: the lost-ack re-delivery label
    // ([ackUnconfirmed]) and the uncommitted-legacy registry slot
    // ([PendingLegacyRegistry]). Both must agree, or a held legacy drain releases the
    // wrong slot. ([AckItem.labelKey] carries the label role only.)
    private fun drainChannelKey(contactId: String, chan: Chan) = "$contactId|${chan.tag}"

    /** Was an ack for this channel recently sent and never confirmed? Then a
     *  duplicate here is most likely the relay re-delivering after that lost ack,
     *  not a replay — the cheap, honest distinction (cryptographically they are
     *  the same blob). Log label only; the blob is dropped either way. */
    private fun likelyRedelivery(contactId: String, chan: Chan): Boolean {
        val now = currentTimeMillis()
        return ackUnconfirmedLock.withLock {
            val at = ackUnconfirmed[drainChannelKey(contactId, chan)] ?: return@withLock false
            now >= at && now - at < ACK_REDELIVERY_LABEL_WINDOW_MS
        }
    }

    /**
     * Fire-and-forget `POST /ack` for [items]: chunked to the relay's limits
     * ([ACK_BATCH_MAX_ITEMS] items, [ACK_MAX_IDS_PER_ITEM] ids per item, the
     * [ACK_BATCH_MAX_BODY_BYTES] byte budget under the proxy's 128 KiB) and LAUNCHED — never awaited. A failed ack is a
     * re-delivery, which the anti-replay drops. Never throws.
     */
    internal fun sendAcks(items: List<AckItem>) {
        if (items.isEmpty() || acksClosed) return
        // Freeze gate: a frozen phone reaches the relay zero times. The un-acked
        // blobs are released when their lease ends and the NEW phone (whose imported
        // state already consumed them) drops and acks them.
        if (moveFrozen("retrieve ack")) return
        val valid = items.mapNotNull { item ->
            if (!isValidInboxId(item.inboxId) || item.readCap.isEmpty() || !capValidForHeader(item.readCap) || !isValidBlobRef(item.token)) null
            else AckItem(item.inboxId, item.readCap, item.token, item.deleteIds.filter { isValidBlobRef(it) }.distinct(), item.labelKey)
        }
        for (chunk in chunkAcks(valid)) {
            val now = currentTimeMillis()
            ackUnconfirmedLock.withLock {
                for (item in chunk) {
                    if (ackUnconfirmed.size >= MAX_ACK_UNCONFIRMED && item.labelKey !in ackUnconfirmed) {
                        ackUnconfirmed.keys.firstOrNull()?.let { k -> ackUnconfirmed.remove(k) }
                    }
                    ackUnconfirmed[item.labelKey] = now
                }
            }
            try { ackLauncher { postAckChunk(chunk) } } catch (e: Exception) {
                platformLogWarn(LOG_TAG, "retrieve-ack: launch failed: ${e::class.simpleName}")
            }
        }
    }

    /** Splits into relay-sized bodies; an item with more ids than one item may carry
     *  becomes several items for the same token (the relay is idempotent per id). */
    internal fun chunkAcks(items: List<AckItem>): List<List<AckItem>> {
        val split = items.flatMap { item ->
            if (item.deleteIds.size <= ACK_MAX_IDS_PER_ITEM) listOf(item)
            else item.deleteIds.chunked(ACK_MAX_IDS_PER_ITEM).map { AckItem(item.inboxId, item.readCap, item.token, it, item.labelKey) }
        }
        val out = mutableListOf<List<AckItem>>()
        var cur = mutableListOf<AckItem>()
        var bytes = ACK_BODY_OVERHEAD_BYTES
        for (item in split) {
            val size = ackItemBytes(item)
            if (cur.isNotEmpty() && (cur.size >= ACK_BATCH_MAX_ITEMS || bytes + size > ACK_BATCH_MAX_BODY_BYTES)) {
                out.add(cur); cur = mutableListOf(); bytes = ACK_BODY_OVERHEAD_BYTES
            }
            cur.add(item); bytes += size
        }
        if (cur.isNotEmpty()) out.add(cur)
        return out
    }

    private fun ackItemBytes(item: AckItem): Int =
        ACK_ITEM_JSON_OVERHEAD_BYTES + item.inboxId.length + item.readCap.length + item.token.length +
            item.deleteIds.sumOf { it.length + ACK_ID_JSON_OVERHEAD_BYTES }

    /** `{"v":1,"items":[{"id","rc","token","delete":[…]},…]}` — every value was
     *  validated to a JSON-safe alphabet before it got here; escaped anyway. */
    internal fun ackBody(items: List<AckItem>): String {
        val sb = StringBuilder("{\"v\":1,\"items\":[")
        for ((i, item) in items.withIndex()) {
            if (i > 0) sb.append(',')
            sb.append("{\"id\":").append(jsonEscapeString(item.inboxId))
            sb.append(",\"rc\":").append(jsonEscapeString(item.readCap))
            sb.append(",\"token\":").append(jsonEscapeString(item.token))
            sb.append(",\"delete\":[")
            item.deleteIds.forEachIndexed { j, id -> if (j > 0) sb.append(','); sb.append(jsonEscapeString(id)) }
            sb.append("]}")
        }
        return sb.append("]}").toString()
    }

    /** ONE `POST /ack`. Runs on [ackLauncher]'s thread. Counts only in every line. */
    private fun postAckChunk(chunk: List<AckItem>) {
        if (acksClosed) return
        val ids = chunk.sumOf { it.deleteIds.size }
        val result = try {
            httpClient.post("$relayBaseUrl/ack", ackBody(chunk).encodeToByteArray(), ACK_CONTENT_TYPE, emptyMap(), DEFAULT_RELAY_HTTP_TIMEOUT_SECONDS)
        } catch (e: Exception) {
            platformLogWarn(LOG_TAG, "retrieve-ack: ${chunk.size} inbox(es) not acked (${e::class.simpleName}) — the lease will expire and the blobs come back")
            return
        }
        if (result.code == 200) {
            ackUnconfirmedLock.withLock { for (item in chunk) ackUnconfirmed.remove(item.labelKey) }
            platformLog(LOG_TAG, "retrieve-ack: ${chunk.size} inbox(es), $ids blob(s) deleted")
        } else {
            platformLogWarn(LOG_TAG, "retrieve-ack: ${chunk.size} inbox(es) not acked (code=${result.code}) — the lease will expire and the blobs come back")
        }
    }

    /**
     * The legacy half of the pending rule: may this drain process its LEGACY blobs
     * on [key] now? An uncommitted pending legacy advance on the same channel blocks
     * it — a persisting drain waits (its legacy blobs are NOT_PROCESSED and come
     * back), a screen drain of ANOTHER group (the previous poll was abandoned)
     * discards the stale one (releasing its lease, so its blobs return at once) and
     * still waits one round, because the stale blobs and its own must meet in ONE
     * sorted drain or the strict-monotonic check would drop the lower counters.
     * An entry older than [RatchetManager.PENDING_ADVANCE_MAX_AGE_MS] is discarded
     * first (an abandoned poll nobody released).
     */
    private fun legacyPendingBlocks(key: String, drainGroup: Any?): Boolean {
        var release: PendingPart? = null
        val blocked = pendingLock.withLock {
            val e = pendingLegacy[key] ?: return@withLock false
            val now = currentTimeMillis()
            val expired = now < e.createdAtMs || now - e.createdAtMs >= RatchetManager.PENDING_ADVANCE_MAX_AGE_MS
            when {
                expired -> {
                    pendingLegacy.remove(key); e.legacyDiscarded = true; release = e
                    false
                }
                drainGroup == null -> true
                e.drainGroup === drainGroup -> false
                else -> {
                    pendingLegacy.remove(key); e.legacyDiscarded = true; release = e
                    true
                }
            }
        }
        release?.let {
            platformLogWarn(LOG_TAG, "retrieve-ack: a stale uncommitted legacy drain was discarded — its blobs come back")
            releaseLease(it)
        }
        return blocked
    }

    /** Releases [part]'s lease once (ack deleting only its unconditionally-processed
     *  ids), so its other blobs are visible again at once. */
    private fun releaseLease(part: PendingPart) {
        val token = part.token ?: return
        val send = pendingLock.withLock {
            if (part.leaseReleased || acksClosed) false else { part.leaseReleased = true; true }
        }
        if (send) sendAcks(listOf(AckItem(part.inboxId, part.readCap, token, part.freeIds, drainChannelKey(part.contactId, part.chan))))
    }

    /** Returns the ack for [part] once its persists have run; null when there is
     *  nothing to send. Idempotent: a settled part returns null. */
    private fun commitPendingPartAck(part: PendingPart): AckItem? {
        if (acksClosed) return null
        val first = pendingLock.withLock { if (part.settled) false else { part.settled = true; true } }
        if (!first) return null
        val ratchetOk = part.ratchetTicket?.let { ratchetManager.commitPending(it) }
            ?: part.ratchetBase?.let { ratchetManager.isCommitted(it) }
            ?: true
        // The legacy persist runs UNDER pendingLock, which [scrubInMemory] also takes:
        // a commit racing a lock/wipe either writes before the scrub returns or not
        // at all — never into a torn-down session.
        val legacyOk = pendingLock.withLock {
            if (acksClosed) return@withLock false
            val baseline = part.legacyBaseline
            val ok = if (baseline == null) true else {
                if (part.legacyDiscarded) false else {
                    val k = drainChannelKey(part.contactId, part.chan)
                    if (pendingLegacy[k] === part) pendingLegacy.remove(k)
                    persistLegacyBaseline(part.contactId, part.chan, part.legacyEpoch, baseline)
                }
            }
            if (ok && part.consumeGrace) consumeGrace(part.contactId, part.chan)
            ok
        }
        val token = part.token ?: return null
        val ids = part.freeIds + (if (ratchetOk) part.ratchetIds else emptyList()) + (if (legacyOk) part.legacyIds else emptyList())
        if (!ratchetOk || !legacyOk) {
            platformLogWarn(LOG_TAG, "retrieve-ack: a screen drain committed partially — ${(if (ratchetOk) 0 else part.ratchetIds.size) + (if (legacyOk) 0 else part.legacyIds.size)} blob(s) left for re-delivery")
        }
        return AckItem(part.inboxId, part.readCap, token, ids, drainChannelKey(part.contactId, part.chan))
    }

    /** [PendingDrain.commit]: persist every part, then ONE fire-and-forget ack. */
    internal fun commitPendingParts(parts: List<PendingPart>) {
        val acks = parts.mapNotNull { p ->
            try { commitPendingPartAck(p) } catch (e: Exception) {
                platformLogWarn(LOG_TAG, "retrieve-ack: commit failed: ${e::class.simpleName}"); null
            }
        }
        sendAcks(acks)
    }

    /** [PendingDrain.abandon]: discard the uncommitted advances, persist nothing,
     *  release the leases (so the blobs return on the next poll, not in 60 s). */
    internal fun abandonPendingParts(parts: List<PendingPart>) {
        for (part in parts) {
            try {
                val first = pendingLock.withLock {
                    if (part.settled) false else {
                        part.settled = true
                        val k = drainChannelKey(part.contactId, part.chan)
                        if (pendingLegacy[k] === part) pendingLegacy.remove(k)
                        part.legacyDiscarded = true
                        true
                    }
                }
                if (!first) continue
                part.ratchetTicket?.let { ratchetManager.abandonPending(it) }
                releaseLease(part)
            } catch (e: Exception) {
                platformLogWarn(LOG_TAG, "retrieve-ack: abandon failed: ${e::class.simpleName}")
            }
        }
    }

    /**
     * Retrieve-ack: a conversation SCREEN's poll of one text-bearing inbox
     * ([Chan.MAIN] or [Chan.GRP]) — decrypted, NOT persisted, NOT acked. Show
     * [PendingDrain.messages], then call [PendingDrain.commit]. Blocking I/O —
     * background dispatcher only. [group] ties several inbox drains of ONE screen
     * poll together (a contact's text inbox then its group inbox share one ratchet
     * chain; the second builds on the first's uncommitted advance).
     */
    internal fun pollChannelPending(contactId: String, chan: Chan, drainGroup: Any = Any()): PendingDrain<ReceivedMessage> {
        require(chan.isText) { "only text-bearing inboxes have a screen" }
        val out = pollChannelPendingOutcome(contactId, chan, drainGroup)
        return PendingDrain(out.messages, listOfNotNull(out.part), this)
    }

    /** [pollChannelPending] without the wrapper — GroupManager composes several. */
    internal fun pollChannelPendingOutcome(contactId: String, chan: Chan, drainGroup: Any): DrainOutcome {
        require(chan.isText) { "only text-bearing inboxes have a screen" }
        val prepared = prepareDrain(contactId, chan) ?: return DrainOutcome.EMPTY
        return finishDrainCore(prepared, fetchDrain(prepared), drainGroup = drainGroup)
    }

    /** Pending (screen) twin of [finishDrain] for the group fan-out's concurrent GETs. */
    internal fun finishDrainPending(p: PreparedDrain, fetched: HttpResult?, drainGroup: Any): DrainOutcome {
        require(p.chan.isText) { "only text-bearing inboxes have a screen" }
        return finishDrainCore(p, fetched, drainGroup = drainGroup)
    }

    /** Retrieve-ack: the 1:1 screen's TEXT inbox, uncommitted (see [pollChannelPending]). */
    fun pollMessagesPending(contactId: String): PendingDrain<ReceivedMessage> = pollChannelPending(contactId, Chan.MAIN)

    /** Retrieve-ack: this contact's GROUP inbox, uncommitted (see [pollChannelPending]). */
    fun pollGroupInboxPending(contactId: String): PendingDrain<ReceivedMessage> = pollChannelPending(contactId, Chan.GRP)

    /**
     * GROUP-FANOUT (2026-10-06): [pollChannel] split at its single HTTP GET, so a
     * group poll can run its members' GETs CONCURRENTLY
     * ([GroupManager.pollGroupIntoBuffer]) while everything that reads or WRITES
     * state stays serial on the caller's thread: [prepareDrain] (freeze gate, ratchet
     * activation, read-cap reconcile, inbox-row validation) BEFORE the GET, and
     * [finishDrain] (404/health bookkeeping, decrypt, ratchet step, anti-replay
     * counter persist) AFTER it. [fetchDrain] touches nothing but the HTTP client.
     * `pollChannel` is exactly `prepare → fetch → finish`, so every other caller is
     * byte-for-byte unchanged.
     */
    internal class PreparedDrain internal constructor(
        internal val contactId: String,
        internal val chan: Chan,
        internal val contact: ContactRecord,
        internal val inboxRecord: InboxIdRecord,
        internal val url: String,
        internal val headers: Map<String, String>,
    )

    /** The TEXT inbox's [prepareDrain] (GroupManager has no [Chan]). */
    internal fun prepareTextDrain(contactId: String): PreparedDrain? = prepareDrain(contactId, Chan.MAIN)

    /** The GROUP inbox's [prepareDrain]. */
    internal fun prepareGroupInboxDrain(contactId: String): PreparedDrain? = prepareDrain(contactId, Chan.GRP)

    /** Serial pre-GET stage of [pollChannel]; null = nothing to fetch this cycle. */
    internal fun prepareDrain(contactId: String, chan: Chan): PreparedDrain? {
        // "Move to new device" FREEZE GATE, ahead of every vault read and the drain.
        // RECEIVING advances the Double Ratchet exactly as sending does, so the old
        // phone must stop POLLING too (docs/device-move.md fact 5) — and this is the
        // single funnel behind BOTH [pollMessages] and [pollControlMessages], which
        // the conversation screens and the push-wake path call directly on this
        // object. Returning null is what both callers already treat as
        // "nothing this cycle"; the relay is never touched, so nothing is drained.
        if (moveFrozen("poll")) return null
        val contact = databaseManager.getContact(contactId)
        if (contact == null) { platformLog(LOG_TAG, "poll: no contact"); return null }
        // [contact] — a fresh decode carrying the pairing secret — is handed to the
        // [PreparedDrain], whose [finishDrainCore] wipes it; every return that does not
        // hand it off wipes it here.
        var handedOff = false
        try {
            // Flip SEND activation (dr-on) on the text poll tick once the contact is
            // ratchet-capable, both inboxes exist, and we've already heard from the
            // peer — so the very next send on this contact goes ratchet.
            if (chan.isText) enableRatchetIfReady(contactId)
            // Self-heal: finish any INTERRUPTED read-cap rotation for THIS channel
            // before its inbox row is read below, so the poll uses the reconciled cap.
            // Gated on a cheap `_meta` lookup, so the steady state costs one vault read
            // and ZERO network calls. Runs on every channel, so all three inboxes heal.
            // Never on the send path (a send must not block on a probe).
            maybeReconcileReadCap(contactId, chan.inDir)
            val inboxRecord = databaseManager.getInboxIdForContact(contactId, chan.inDir)
            if (inboxRecord == null) {
                // For control (pre-v7 pairing) and for group (legacy / not yet
                // backfilled) this is normal — stay quiet, and return BEFORE any HTTP so
                // such a contact can never record a 404 or a streak on that channel.
                if (chan == Chan.MAIN) platformLog(LOG_TAG, "poll: no inbound text inbox")
                return null
            }
            val readCap = inboxRecord.cap
            if (readCap.isNullOrEmpty()) {
                platformLogWarn(LOG_TAG, "inbound inbox has no readCap — re-pair required")
                return null
            }
            // Defense-in-depth: validate the STORED cap before it goes into the
            // X-Read-Capability header (CRLF/header injection guard, mirrors send).
            if (!capValidForHeader(readCap)) {
                platformLogWarn(LOG_TAG, "inbound readCap fails header validation — refused")
                return null
            }
            // Validate up-front so validatedInboxUrl() can't throw out of
            // pollMessages on a legacy/corrupt record.
            if (!isValidInboxId(inboxRecord.inboxId)) {
                platformLogWarn(LOG_TAG, "inbound inbox ID not valid — re-pair required")
                return null
            }

            // The legacy AES key is derived LATER, right before the
            // decrypt loop, so the 404/429/empty returns in [finishDrainCore] never leave it
            // live in RAM.
            val prepared = PreparedDrain(
                contactId, chan, contact, inboxRecord,
                // Retrieve-ack: ALWAYS the leasing drain. The bare GET (no query) still
                // deletes at fetch on the relay and must never be used from here again.
                url = validatedInboxUrl(inboxRecord.inboxId) + RETRIEVE_LEASE_QUERY,
                headers = mapOf(READ_CAP_HEADER to readCap),
            )
            handedOff = true
            return prepared
        } finally {
            if (!handedOff) contact.sharedSecret.secureWipe()
        }
    }

    /** The ONLY concurrent stage: the GET. Never throws; null = the request failed. */
    internal fun fetchDrain(p: PreparedDrain): HttpResult? = try {
        httpClient.get(p.url, headers = p.headers)
    } catch (e: Exception) {
        // Class name only — a transport exception's message can carry the relay host.
        platformLogError(LOG_TAG, "poll failed (${p.chan.logLabel}): ${e::class.simpleName}")
        null
    }

    /**
     * Serial post-GET stage of [pollChannel]. [fetched] null = the GET failed.
     * Persist mode: ratchet + counter state are persisted inside, then the
     * retrieve-ack is added to [acks] (a sweep / fan-out flushes it after applying
     * what came back) or, with no batch, sent at once — fire-and-forget either way.
     */
    internal fun finishDrain(p: PreparedDrain, fetched: HttpResult?, acks: AckBatch? = null): List<ReceivedMessage> {
        val out = finishDrainCore(p, fetched, drainGroup = null)
        out.ack?.let { if (acks != null) acks.add(it) else sendAcks(listOf(it)) }
        return out.messages
    }

    /**
     * The drain proper. [drainGroup] null = PERSIST mode (every background caller):
     * state is persisted here and [DrainOutcome.ack] carries the ack. Non-null (a
     * conversation screen, text-bearing inboxes only) = PENDING mode: the ratchet
     * advance stays uncommitted in RAM, the legacy baseline is not written, and
     * [DrainOutcome.part] is what [commitPendingParts] later persists and acks. A
     * relay that did not lease (no token: it already deleted at fetch) gets the
     * pending part committed INLINE — exactly today's semantics.
     */
    private fun finishDrainCore(p: PreparedDrain, fetched: HttpResult?, drainGroup: Any?): DrainOutcome =
        try {
            finishDrainCoreHoldingSecret(p, fetched, drainGroup)
        } finally {
            // [PreparedDrain.contact] is a FRESH decode ([prepareDrain]) used only by this
            // drain (the derived legacy key and the ratchet calls inside); nothing keeps it
            // past here — [PendingPart] holds no contact — so its copy of the pairing
            // secret is wiped instead of waiting for GC (~1 Hz per open conversation).
            p.contact.sharedSecret.secureWipe()
        }

    private fun finishDrainCoreHoldingSecret(p: PreparedDrain, fetched: HttpResult?, drainGroup: Any?): DrainOutcome {
        val result = fetched ?: return DrainOutcome.EMPTY
        val contactId = p.contactId
        val chan = p.chan
        val contact = p.contact
        val inboxRecord = p.inboxRecord
        val inboxId = inboxRecord.inboxId
        platformLog(
            LOG_TAG,
            // CODE ONLY (see the relay probe's note): on the code = -1 transport path
            // the body is the raw transport error text, which can embed the onion host.
            "poll → code=${result.code} (${chan.logLabel})",
        )

        // 404: generic rejection (gone / wrong cap / locked). 429: rate-limited.
        // The relay collapses NOT_FOUND/UNAUTHORIZED/LOCKED into 404 and gives no
        // in-band signal to distinguish — but a PERSISTENT 404 (the relay
        // answered, so it's up) means it really lost this contact's inbox. Track
        // the streak per channel: an attacker who rotates a victim's read
        // cap out from under them would otherwise silently kill text delivery
        // with NO UI signal (the message channel previously never flagged).
        if (result.code == 404) {
            noteRelay404(contactId, chan)
            return DrainOutcome.EMPTY
        }
        if (result.code == 429) return DrainOutcome.EMPTY  // transient rate-limit, not a loss
        if (!result.isSuccess || result.body == null) return DrainOutcome.EMPTY
        // Healthy response (an empty inbox is still a 200) → this channel is
        // alive: clear its 404 streak and, once every channel is healthy, the flag.
        noteRelayHealthy(contactId, chan)
        // Same evidence, second use — the relay answering 2xx for THIS inbox under
        // our read cap proves it still holds it, which is what lets us re-stamp the
        // row's informational lease (and repair a vault already past its stamp). The
        // 404/429 returns above are ahead of this line on purpose.
        noteInboxProvenLive(inboxRecord)

        val blobs = try {
            parseJsonStringArray(result.body, "blobs")
        } catch (_: Exception) {
            platformLogWarn(LOG_TAG, "poll: unparseable blobs array in a 2xx response — drain yielded no messages")
            // Nothing to ack by id: the lease (if any) expires and the relay retries.
            return DrainOutcome.EMPTY
        }
        // Retrieve-ack: the lease token + per-blob ids (untrusted, validated).
        val lease = parseLease(result.body, blobs.size)
        // PENDING mode only for the text-bearing inboxes; a CTL drain is always a
        // background drain.
        val pendingMode = drainGroup != null && chan.isText
        val pendingDrainGroup: Any? = if (pendingMode) drainGroup else null
        // Per-blob outcome (index = position in the relay's answer) and what its ack
        // waits for in pending mode. Default NOT_PROCESSED: a path that forgets to
        // decide leaves the blob for re-delivery (a duplicate the anti-replay drops),
        // never an ack for something unseen.
        val ledger = BlobLedger(blobs.size)

        // Defense-in-depth — cap how many blobs we decode/decrypt per
        // poll. The HTTP layer already bounds the response body size.
        // Retrieve-ack: the tail beyond the cap stays NOT_PROCESSED — un-acked, the
        // relay hands it back on the next drain (it used to be silently lost).
        val cappedBlobs = if (blobs.size > MAX_BLOBS_PER_POLL) {
            platformLogWarn(LOG_TAG, "poll: ${blobs.size} blobs exceeds cap $MAX_BLOBS_PER_POLL — processing first $MAX_BLOBS_PER_POLL, the rest next drain")
            blobs.take(MAX_BLOBS_PER_POLL)
        } else {
            blobs
        }

        // Self-describing split (text channel): a ratchet blob carries the wire
        // magic and is decoded through the Double Ratchet; everything else goes
        // to the legacy AES-GCM/epoch/counter decoder below. Routing PER BLOB
        // (not by our own dr-on flag) makes a mid-transition poll lossless — a
        // peer that has/hasn't flipped yet can send either format and we still
        // read it. Base64 is decoded once here.
        // Once we've decrypted a ratchet blob from this peer (sticky
        // dr-rxlock), a non-magic legacy TEXT blob is a downgrade/forgery — an
        // attacker with a stolen sharedSecret can mint a valid static-key blob but
        // not a ratchet blob — so DROP it. Read the lock at the START of the poll
        // and set it AFTER (below), which gives a natural one-poll grace for
        // pre-flip legacy blobs still queued at the relay. Control is not
        // ratcheted EXCEPT for the inbox announce: a ratchet-magic blob on
        // the control inbox is decoded through the text ratchet, and a LEGACY
        // announce is dropped once the lock is armed (announceLocked, below).
        val lockArmed = databaseManager.getMeta(drRecvLockKey(contactId)) == "1"
        // Both TEXT channels are covered: a legacy static-key blob on the GROUP
        // inbox after the lock is armed is the same downgrade/forgery as one on the
        // text inbox (a stolen sharedSecret mints either), and by then the peer's
        // own group texts ride the same ratchet.
        // When the lock was armed by a CONTROL drain, the text channels
        // never got the one-poll grace (the arming drain is what normally provides
        // it: the lock is read at its start). [drRecvLockGraceKey] lists the text
        // channels still owed that one drain; this drain consumes its own tag below.
        val textGrace = chan.isText && lockArmed && graceOwed(contactId, chan)
        val recvLocked = chan.isText && lockArmed && !textGrace
        val announceLocked = lockArmed
        val split = splitDrainBlobs(cappedBlobs, recvLocked, ledger)
        // Retrieve-ack, legacy half of the pending rule ([legacyPendingBlocks]):
        // decided BEFORE any legacy work. Held ⇒ every legacy blob of this drain is
        // NOT_PROCESSED and comes back on the next drain together with the held ones.
        val legacyKey = drainChannelKey(contactId, chan)
        val legacyHeld = split.legacyBlobs.isNotEmpty() && legacyPendingBlocks(legacyKey, pendingDrainGroup)
        if (legacyHeld) {
            platformLogWarn(LOG_TAG, "poll: ${split.legacyBlobs.size} legacy blob(s) left for the next drain (an uncommitted screen drain holds this channel)")
        }

        val adverts = PeerAdvertsSeen()
        val half = drainRatchetHalf(contactId, contact, chan, split, ledger, adverts, pendingDrainGroup)
        // The both-Alice detector. A decryptable ratchet blob (either
        // channel) clears both counters and any refusal; a TEXT drain that carried
        // blobs and produced none is one consecutive piece of evidence — but only once
        // this device has ratchet blobs of its own outstanding (see
        // [noteRatchetUnackedReceive]). Zero blobs is NOT evidence: an empty inbox says
        // nothing about the peer's roles, and counting it would arm the refusal on an
        // idle conversation.
        // Retrieve-ack: a drain whose every blob was left for the next drain (held
        // behind an uncommitted advance) looked at nothing — not evidence either.
        val lookedAtAny = ledger.outcome.any { it != BlobOutcome.NOT_PROCESSED } || (split.legacyBlobs.isNotEmpty() && !legacyHeld)
        afterRatchetHalf(contactId, chan, half, adverts, lockArmed, lookedAtAny, cappedNonEmpty = cappedBlobs.isNotEmpty())
        // Retrieve-ack: a PENDING drain consumes the grace at commit (with the legacy
        // baseline it protects) — consuming it now and losing the drain would drop
        // the re-delivered legacy blobs under the lock.
        val persistLegacyAtCommit = pendingMode && lease != null
        if (textGrace && !persistLegacyAtCommit) consumeGrace(contactId, chan)

        // Anti-replay state. The accepted counter is scoped to
        // the current shared-secret epoch; a different stored epoch (re-pair
        // with a new secret) resets the baseline so fresh low counters from
        // the new epoch are not mistaken for replays.
        val expectedEpoch = messageEpoch(contact.sharedSecret)
        val startCounter =
            if (contact.inboundEpoch == expectedEpoch) chan.inCounterOf(contact) else 0L
        // The control-counter forward-jump cap, measured from the baseline this
        // drain STARTED at (not the running one), so neither one blob nor a stack of
        // them in a single drain can push the baseline more than
        // [CTL_COUNTER_MAX_FORWARD_JUMP] ahead. CONTROL inbox only: the text inboxes
        // are receive-locked once the ratchet matures, and a 1:1 backlog has no comparable
        // bound to size a cap from.
        val ctlCeiling =
            if (chan == Chan.CTL) ctlCounterCeiling(startCounter) else Long.MAX_VALUE
        // Sealed-control receive lock, decided ONCE for the drain from persisted state: a LEGACY
        // copy of an integrity-critical control kind is dropped iff this peer's ratchet
        // is mature (`lockArmed`) AND it has proven over that ratchet that it seals
        // those kinds, from the control counter it reported on. Null = no lock, which
        // is the un-upgraded-peer / fresh / unreadable default and NEVER a drop.
        val ctlSealWatermark: Long? =
            if (chan == Chan.CTL && lockArmed) peerCtlWatermark(contactId) else null

        // First pass: decode/decrypt/unpad/parse every (legacy) blob and collect
        // the valid, same-epoch envelopes. Legacy/no-counter and wrong-epoch
        // envelopes are dropped here (order-independent). Ratchet blobs were
        // already split off above.
        // Has this peer ever sent a channel-tagged ("ch") blob? Once it has,
        // we require the tag on every subsequent blob (see the check below).
        // Fix the channel-tag decision for the WHOLE drain from
        // persisted state up front. The relay controls arrival order, so flipping this
        // mid-drain (and then dropping later untagged blobs) let a hostile — or merely
        // unlucky — relay serve a peer's first tagged blob ahead of genuinely-legacy
        // untagged ones and get those legit older messages dropped during the one-time
        // upgrade. We accept both during the upgrade drain and persist the flag AFTER
        // it, so the NEXT drain starts enforcing the tag.
        val peerTagsChannelsAtStart = databaseManager.getMeta(channelTagSeenKey(contactId)) == "1"
        // The same one-time-upgrade machinery, for the destination-inbox
        // binding ("di"). Decided for the WHOLE drain up front (like the channel tag) so a
        // hostile relay can't reorder a peer's first bound blob ahead of genuinely-legacy
        // ones and get those legit older messages dropped during the upgrade drain.
        val peerBindsInboxAtStart = databaseManager.getMeta(inboxBoundSeenKey(contactId)) == "1"
        val firstPass = openLegacyBlobs(
            contact, if (legacyHeld) emptyList() else split.legacyBlobs, split.legacyBlobIdx,
            LegacyDrainContext(chan, inboxId, expectedEpoch, peerTagsChannelsAtStart, peerBindsInboxAtStart),
            ledger,
        )
        if (firstPass.seen.ctlCapAdvert) recordPeerCtlAdverts(contactId, cap = true, watermark = null)
        // The whole drain is decided — now persist the upgrade flag for FUTURE
        // drains if we saw any channel tag this round (deferred from mid-drain above).
        if (firstPass.seen.channelTag && !peerTagsChannelsAtStart) {
            putMetaBestEffort(channelTagSeenKey(contactId), "1")
        }
        // Same deferred persist for the inbox-binding upgrade — the NEXT
        // drain then starts REQUIRING "di" on every blob from this now-known-binding peer.
        if (firstPass.seen.inboxBind && !peerBindsInboxAtStart) {
            putMetaBestEffort(inboxBoundSeenKey(contactId), "1")
        }

        val legacy = applySortedLegacy(
            contactId, contact, chan, firstPass.candidates, startCounter, ctlCeiling, ctlSealWatermark, announceLocked, ledger,
        )
        val ratchetMessages = half.messages
        val messages = legacy.messages

        // Persist the advanced replay baseline (and the current epoch) so it
        // survives restarts and the next poll rejects re-served blobs.
        // NOTE: an epoch flip here (re-pair) resets EVERY channel's baseline
        // implicitly — the other channels' counters stay at their old values but
        // are re-scoped to the new epoch. Counters only ever grow per epoch on
        // the sender side, so the worst case is over-rejection right after a
        // re-pair, never replay acceptance.
        // Retrieve-ack: a PENDING drain (leased) persists it at commit instead.
        if (legacy.advanced && !persistLegacyAtCommit) {
            if (!persistLegacyBaseline(contactId, chan, expectedEpoch, legacy.lastCounter)) {
                // If we can't persist the advanced replay baseline, the
                // next poll would re-accept these counters, so a hostile relay
                // re-serving the same blobs could replay them. By design
                // (detection+rejection, not recovery) drop this batch rather
                // than deliver messages we can no longer protect against
                // replay. Retrieve-ack: the dropped legacy blobs are NOT acked
                // any more, so the relay re-delivers them and the next drain
                // (vault writable again) accepts them — no longer a loss.
                // Drop the LEGACY batch (re-servable → replay
                // risk without a persisted baseline), but NOT the ratchet messages
                // already decoded above — their chains have already advanced, so the
                // plaintext is unrecoverable if we discard it here, and a ratchet blob
                // carries its own one-shot replay protection (no baseline needed).
                platformLogError(LOG_TAG, "persist replay state failed — dropping legacy batch to avoid replay, left for re-delivery (keeping ${ratchetMessages.size} ratchet msg)")
                ledger.demoteLegacyToNotProcessed()
                return buildDrainOutcome(
                    p, ledger, blobs.size, lease, pendingMode, pendingDrainGroup, legacyKey, half.report, legacy,
                    persistLegacyAtCommit, expectedEpoch, textGrace, ratchetMessages,
                )
            }
        }

        // Any inbound TEXT (legacy or ratchet) proves the peer is paired and
        // sending — record it so SEND activation (dr-on) can flip, and try the
        // flip now so subsequent sends on this contact go ratchet promptly.
        // Re-check the contact still exists — a delete during this
        // poll's round-trip must not resurrect the dr-rxseen satellite flag (enableRatchet
        // -IfReady is already inert once dr-intent is purged, but the putMeta was not).
        if (chan.isText && (legacy.advanced || ratchetMessages.isNotEmpty()) &&
            contactExists(contactId)) {
            if (databaseManager.getMeta(drRxSeenKey(contactId)) != "1") {
                putMetaBestEffort(drRxSeenKey(contactId), "1")
            }
            enableRatchetIfReady(contactId)
        }

        val all = if (ratchetMessages.isEmpty()) messages else ratchetMessages + messages
        if (all.isNotEmpty()) {
            platformLog(LOG_TAG, "received ${all.size} message(s) from the ${chan.logLabel} inbox")
        }
        return buildDrainOutcome(
            p, ledger, blobs.size, lease, pendingMode, pendingDrainGroup, legacyKey, half.report, legacy,
            persistLegacyAtCommit, expectedEpoch, textGrace, all,
        )
    }

    // --- The drain's units (finishDrainCoreHoldingSecret's phases, in call order) ---

    // Per-blob outcome (index = position in the relay's answer) and what its ack
    // waits for in pending mode. Pure data, written by every phase of one drain.
    private class BlobLedger(size: Int) {
        val outcome = Array(size) { BlobOutcome.NOT_PROCESSED }
        val ackDep = Array(size) { AckDep.NONE }

        // Retrieve-ack: an envelope that survived every check of the sorted apply is
        // ACCEPTED, and in pending mode its ack waits on the legacy baseline.
        fun acceptLegacy(blobIdx: Int) { outcome[blobIdx] = BlobOutcome.ACCEPTED; ackDep[blobIdx] = AckDep.LEGACY }

        // The legacy batch could not be made replay-safe: every legacy blob goes back to
        // NOT_PROCESSED (re-delivered), the ratchet ones keep their outcome.
        fun demoteLegacyToNotProcessed() {
            for (blobIdx in outcome.indices) if (ackDep[blobIdx] == AckDep.LEGACY) {
                outcome[blobIdx] = BlobOutcome.NOT_PROCESSED
                ackDep[blobIdx] = AckDep.NONE
            }
        }
    }

    // The drain's blobs split by wire format; each list keeps its blob index.
    private class DrainSplit(
        val ratchetWires: List<ByteArray>,
        val ratchetWireBlob: List<Int>,   // ratchetWires[i] came from blob ratchetWireBlob[i]
        val legacyBlobs: List<String>,
        val legacyBlobIdx: List<Int>,     // same, for legacyBlobs
    )

    private fun splitDrainBlobs(cappedBlobs: List<String>, recvLocked: Boolean, ledger: BlobLedger): DrainSplit {
        val ratchetWires = mutableListOf<ByteArray>()
        val ratchetWireBlob = mutableListOf<Int>()   // ratchetWires[i] came from blob ratchetWireBlob[i]
        val legacyBlobs = mutableListOf<String>()
        val legacyBlobIdx = mutableListOf<Int>()     // same, for legacyBlobs
        for ((blobIdx, b64) in cappedBlobs.withIndex()) {
            val raw = try { decodeBase64(b64) } catch (_: Exception) {
                // One malformed blob must not abort the whole poll.
                ledger.outcome[blobIdx] = BlobOutcome.REJECTED
                platformLogWarn(LOG_TAG, "poll: skipping malformed base64 blob"); continue
            }
            if (isRatchetWire(raw)) {
                ratchetWires.add(raw.copyOfRange(RATCHET_WIRE_MAGIC.size, raw.size))
                ratchetWireBlob.add(blobIdx)
            } else if (recvLocked) {
                ledger.outcome[blobIdx] = BlobOutcome.REJECTED
                platformLogWarn(LOG_TAG, "poll: dropping legacy text blob after ratchet lock (receive-lock downgrade guard)")
            } else {
                legacyBlobs.add(b64)
                legacyBlobIdx.add(blobIdx)
            }
        }
        return DrainSplit(ratchetWires, ratchetWireBlob, legacyBlobs, legacyBlobIdx)
    }

    // The peer's adverts, as seen inside RATCHET envelopes this drain ([onEnvelope]
    // is handed to every ratchet decrypt of the drain).
    private class PeerAdvertsSeen {
        var sawCtlCapAdvert = false
        // The receiving-step ordinal of the newest IN-ORDER (not
        // opened from a cached skipped key) envelope with / without the advert.
        var newestCrStep: Int? = null
        var newestCapLessStep: Int? = null
        var lowestRatchetWatermark: Long? = null
        val onEnvelope: (Envelope, RatchetManager.WireOrigin?) -> Unit = { env, origin ->
            val inOrderStep = if (origin != null && !origin.fromSkippedKey) origin.receivingStep else null
            if (env.ctlRatchetCap == "1") {
                sawCtlCapAdvert = true
                if (inOrderStep != null) newestCrStep = maxOf(newestCrStep ?: inOrderStep, inOrderStep)
            } else if (inOrderStep != null) {
                newestCapLessStep = maxOf(newestCapLessStep ?: inOrderStep, inOrderStep)
            }
            parseCtlWatermark(env.ctlRatchetWatermark)?.let { w ->
                val cur = lowestRatchetWatermark
                if (cur == null || w < cur) lowestRatchetWatermark = w
            }
        }
    }

    // The ratchet half of one drain: what it surfaced, the guarded batch's report,
    // whether ANY wire decrypted, and whether the guarded batch had wires at all.
    private class RatchetHalf(
        val messages: List<ReceivedMessage>,
        val report: RatchetManager.DecryptBatchReport,
        val decrypted: Boolean,
        val hasGuardedWires: Boolean,
    )

    private fun drainRatchetHalf(
        contactId: String, contact: ContactRecord, chan: Chan, split: DrainSplit, ledger: BlobLedger,
        adverts: PeerAdvertsSeen, pendingDrainGroup: Any?,
    ): RatchetHalf {
        // Did any blob on this drain DECRYPT through the ratchet? Not
        // "was a ratchet blob present" — in the both-Alice role collision the peer's
        // blobs are ratchet wires that can never decrypt.
        var ratchetDecrypted = false
        // Sealed control drained ahead of an undrained text backlog is
        // DEFERRED (raw wire kept in the vault, bounded in count, bytes and age)
        // instead of decrypted at the cost of those texts' keys. Deferred wires from
        // earlier drains are retried here first; ones past their own force age (or
        // over the count bound) are processed unconditionally.
        // Retrieve-ack rule 3 ([RatchetManager] header): while a conversation screen
        // holds an uncommitted advance of this contact's ONE text ratchet, a control
        // drain does no ratchet work at all — the deferral store is left untouched and
        // its fresh ratchet wires come back NOT_PROCESSED (decryptBatch enforces the
        // same rule atomically; this pre-check just keeps the stored deferrals out of
        // it). The render window is sub-second; an abandoned poll ages out in 15 s.
        val ctlRatchetHeld = chan == Chan.CTL && ratchetManager.hasUncommittedAdvance(contactId, RATCHET_TEXT_CHANNEL)
        val deferredIn = if (chan == Chan.CTL && !ctlRatchetHeld) loadDeferredCtl(contactId) else emptyList()
        val nowMs = currentTimeMillis()
        val forcedCount = deferredIn.size - minOf(deferredIn.size, MAX_DEFERRED_CTL_RETRY)
        val forcedFlags = deferredIn.mapIndexed { i, d -> deferralForced(i, forcedCount, d, nowMs) }
        // This drain processes the deferrals, so any retry the text path asked for is served.
        if (!ctlRatchetHeld) sealedControlCatchUpLock.withLock { deferredRetryRequested.remove(contactId) }
        val forced = deferredIn.filterIndexed { i, _ -> forcedFlags[i] }
        val retried = deferredIn.filterIndexed { i, _ -> !forcedFlags[i] }
        // Retrieve-ack: a STORED deferral the batch did not process (cutoff tail, spent
        // budget, the rule-3 race) is kept in the store with its original stamp —
        // rewriting the store without it would lose it, and the relay no longer has it.
        val keepStored = mutableListOf<DeferredCtl>()
        val forcedReport = RatchetManager.DecryptBatchReport()
        val forcedMessages =
            if (forced.isNotEmpty()) receiveOverTextRatchet(
                contactId, contact, forced.map { it.wire }, chan,
                onRatchetDecrypted = { ratchetDecrypted = true },
                onEnvelope = adverts.onEnvelope,
                report = forcedReport,
            ) else emptyList()
        forcedReport.notProcessed.forEach { j -> forced.getOrNull(j)?.let { keepStored.add(it) } }
        if (forced.isNotEmpty()) {
            platformLogWarn(LOG_TAG, "sealed control: ${forced.size} deferred blob(s) processed past their deferral bound")
        }
        val guardedWires = retried.map { it.wire } + split.ratchetWires
        val guardedStamps = retried.map { it.stampMs } + List(split.ratchetWires.size) { nowMs }
        val report = RatchetManager.DecryptBatchReport()
        val guardedMessages =
            if (guardedWires.isNotEmpty()) receiveOverTextRatchet(
                contactId, contact, guardedWires, chan,
                onRatchetDecrypted = { ratchetDecrypted = true },
                onEnvelope = adverts.onEnvelope,
                deferDamaging = chan == Chan.CTL,
                report = report,
                drainGroup = pendingDrainGroup,
            )
            else emptyList()
        // A deferral is only worth its delay if the keys it protects
        // belong to texts still WAITING on the relay. Peek (never drain) the text and
        // group inboxes: both positively empty ⇒ the cached keys are dead (a lost
        // send, an expired text) ⇒ decrypt now. Otherwise the force age is 24 h only
        // for a BACKLOG skip with unread texts positively present; everything else —
        // an old-chain flush, or an unknown peek — is held at most
        // [CTL_DEFER_SHORT_AGE_MS].
        var lateMessages: List<ReceivedMessage> = emptyList()
        var toStore: List<DeferredCtl> = emptyList()
        // Retrieve-ack: guarded indices the LATE decrypt did not process.
        val lateNotProcessed = mutableSetOf<Int>()
        val lateDecrypted = mutableSetOf<Int>()
        if (chan == Chan.CTL && report.deferred.isNotEmpty()) {
            val pending = peekUndrainedTextCount(contactId)
            if (pending == 0) {
                val lateIdx = report.deferred.keys.toList()
                val lateReport = RatchetManager.DecryptBatchReport()
                lateMessages = receiveOverTextRatchet(
                    contactId, contact, lateIdx.map { guardedWires[it] }, chan,
                    onRatchetDecrypted = { ratchetDecrypted = true },
                    onEnvelope = adverts.onEnvelope,
                    report = lateReport,
                )
                lateReport.notProcessed.forEach { j -> lateIdx.getOrNull(j)?.let { lateNotProcessed.add(it) } }
                lateReport.decrypted.keys.forEach { j -> lateIdx.getOrNull(j)?.let { lateDecrypted.add(it) } }
            } else {
                toStore = report.deferred.map { (i, damage) ->
                    val long = damage == DoubleRatchet.SkipDamage.BACKLOG && pending != null && pending > 0
                    DeferredCtl(guardedStamps[i], if (long) CTL_DEFER_MAX_AGE_MS else CTL_DEFER_SHORT_AGE_MS, guardedWires[i])
                }
            }
        }
        val ratchetMessages = forcedMessages + guardedMessages + lateMessages
        // Retrieve-ack: per-wire outcome. A STORED (retried) wire maps to no relay
        // blob — if it was not processed it stays in the store; a FRESH wire maps to
        // its blob: not processed ⇒ NOT_PROCESSED (un-acked, re-delivered), parked in
        // the deferral store ⇒ DEFERRED, otherwise it was looked at against the
        // ratchet (decrypted or refused) ⇒ acked — in pending mode only once that
        // ratchet advance is committed.
        for (guardedIdx in guardedWires.indices) {
            val notProcessed = guardedIdx in report.notProcessed || guardedIdx in lateNotProcessed
            if (guardedIdx < retried.size) {
                if (notProcessed) keepStored.add(retried[guardedIdx])
                continue
            }
            val blobIdx = split.ratchetWireBlob[guardedIdx - retried.size]
            when {
                notProcessed -> ledger.outcome[blobIdx] = BlobOutcome.NOT_PROCESSED
                // Parked in the vault (the store path): acked — the vault copy is the
                // one that will be retried, the relay's is no longer needed.
                guardedIdx in report.deferred && toStore.isNotEmpty() -> ledger.outcome[blobIdx] = BlobOutcome.DEFERRED
                else -> {
                    // ACCEPTED = authenticated (a routing rule may still have dropped
                    // its content); REJECTED = refused by the AEAD / malformed.
                    ledger.outcome[blobIdx] = if (report.decrypted.containsKey(guardedIdx) || guardedIdx in lateDecrypted) BlobOutcome.ACCEPTED else BlobOutcome.REJECTED
                    ledger.ackDep[blobIdx] = AckDep.RATCHET
                }
            }
        }
        if (chan == Chan.CTL && (deferredIn.isNotEmpty() || toStore.isNotEmpty() || keepStored.isNotEmpty())) {
            storeDeferredCtl(contactId, toStore + keepStored)
        }
        return RatchetHalf(ratchetMessages, report, ratchetDecrypted, guardedWires.isNotEmpty())
    }

    private fun afterRatchetHalf(
        contactId: String, chan: Chan, half: RatchetHalf, adverts: PeerAdvertsSeen,
        lockArmed: Boolean, lookedAtAny: Boolean, cappedNonEmpty: Boolean,
    ) {
        if (half.decrypted) noteInboundRatchetProven(contactId)
        else if (chan.isText && cappedNonEmpty && lookedAtAny) noteRatchetUnackedReceive(contactId)

        // Arm the sticky receive-lock only once the ratchet is
        // PAST the sharedSecret-forgeable bootstrap window, and re-evaluate on EVERY
        // text poll (not just when a ratchet blob decrypted this round). See
        // maybeArmRecvLock. Also re-evaluated on the control poll: an
        // announce decrypted there advances the same text ratchet — and an arm from
        // there owes the text channels the lock's grace drain.
        maybeArmRecvLock(contactId, armedFrom = chan)

        // What the peer advertised INSIDE ratchet blobs. The capability is
        // honoured from any authenticated envelope (below too, for legacy ones). The
        // watermark only when this peer's ratchet was ALREADY past its bootstrap
        // window when the drain started (`lockArmed`): a bootstrap-window ratchet blob
        // is forgeable from sharedSecret alone, and a forged watermark is
        // precisely a lever to make us drop a genuinely old peer's legacy control.
        // Under the same maturity rule, a ratchet envelope WITHOUT the advert
        // (and none with it in this drain) is the peer running a build that predates
        // sealed control — e.g. its vault was moved onto an older install during store skew —
        // so both latches are withdrawn and the pairing reverts to legacy control.
        // The withdrawal needs a cap-less envelope PROVABLY NEWER than
        // the last advert-bearing one: decrypted in order (never from a cached skipped
        // key — a relay can withhold a genuine pre-upgrade blob and serve it alone)
        // on a receiving step strictly AFTER the newest advert-bearing in-order one we
        // ever saw ([drCtlCapStepKey]). With no such record (the advert was only ever
        // seen in legacy envelopes) nothing is provable and nothing is withdrawn.
        val lastCrStep = listOfNotNull(peerCtlCapStep(contactId), adverts.newestCrStep).maxOrNull()
        val capLessStep = adverts.newestCapLessStep
        recordPeerCtlAdverts(
            contactId,
            cap = adverts.sawCtlCapAdvert,
            watermark = if (lockArmed) adverts.lowestRatchetWatermark else null,
            capStep = adverts.newestCrStep,
            withdraw = lockArmed && capLessStep != null && lastCrStep != null && capLessStep > lastCrStep,
        )
        // Catch-up wake: only a TEXT drain whose decrypt left MORE
        // skipped keys than it found can have stranded a sealed control blob's key;
        // one that emptied the cache retires an earlier mark. A contact with
        // deferred sealed control is marked after any text drain that decrypted, so
        // the deferral is retried promptly. See [sealedControlCatchUp].
        if (chan.isText && half.hasGuardedWires) {
            if (half.report.skippedAfter > half.report.skippedBefore && peerCtlRatchetCapable(contactId)) {
                noteSealedControlCatchUp(contactId)
            } else if (half.report.skippedAfter == 0) {
                clearSealedControlCatchUp(contactId)
            }
            // A text drain changes how many texts are waiting: the cached peek is stale.
            sealedControlCatchUpLock.withLock { undrainedPeekCache.remove(contactId) }
            if (half.decrypted && hasDeferredCtl(contactId)) {
                // The texts a deferral protected may just have been read: ask the next
                // sweep to drain this contact despite an empty control inbox, once.
                sealedControlCatchUpLock.withLock { deferredRetryRequested.add(contactId) }
                noteSealedControlCatchUp(contactId)
            }
        }
    }

    // What the legacy first pass checks every envelope against — all decided from
    // persisted state BEFORE the drain (see the call site).
    private class LegacyDrainContext(
        val chan: Chan,
        val inboxId: String,
        val expectedEpoch: String,
        val peerTagsChannelsAtStart: Boolean,
        val peerBindsInboxAtStart: Boolean,
    )

    // What the first pass SAW this drain (persisted after it, never mid-drain).
    private class LegacySeen {
        var channelTag = false
        var inboxBind = false
        var ctlCapAdvert = false
    }

    private class LegacyFirstPass(val candidates: MutableList<Pair<Envelope, Int>>, val seen: LegacySeen)

    // The static-envelope key + AAD for [sharedSecret], wiped when [block] returns or
    // throws (parity with DoubleRatchet, which wipes every key). Shared by the drain's
    // first pass and the legacy send.
    private inline fun <T> withStaticEnvelopeKey(sharedSecret: ByteArray, block: (key: ByteArray, aad: ByteArray) -> T): T {
        val encryptionKey = sha256(sharedSecret)
        val aeadContext = sha256WithLabel(encryptionKey, "message-aead".encodeToByteArray())
        try {
            return block(encryptionKey, aeadContext)
        } finally {
            encryptionKey.secureWipe()
            aeadContext.secureWipe()
        }
    }

    // First pass: decode/decrypt/unpad/parse every (legacy) blob and collect the
    // valid, same-epoch envelopes (see the call site).
    private fun openLegacyBlobs(
        contact: ContactRecord, legacyBlobs: List<String>, legacyBlobIdx: List<Int>,
        ctx: LegacyDrainContext, ledger: BlobLedger,
    ): LegacyFirstPass {
        val legacyCandidates = mutableListOf<Pair<Envelope, Int>>()   // (envelope, blob index)
        val seen = LegacySeen()
        // Derive the static message key here and secureWipe it right
        // after the decrypt loop (parity with DoubleRatchet, which wipes every key).
        withStaticEnvelopeKey(contact.sharedSecret) { encryptionKey, aeadContext ->
            for ((legacyIdx, base64Blob) in legacyBlobs.withIndex()) {
                // Retrieve-ack: every early `continue` below is a final refusal (acked);
                // only an envelope that survives the sort loop is upgraded to ACCEPTED.
                val blobIdx = legacyBlobIdx[legacyIdx]
                ledger.outcome[blobIdx] = BlobOutcome.REJECTED
                val encryptedBytes = try {
                    decodeBase64(base64Blob)
                } catch (_: Exception) {
                    // One malformed base64 blob from a hostile/buggy relay
                    // must not abort the whole poll and silently drop every later
                    // legitimate message.
                    platformLogWarn(LOG_TAG, "poll: skipping malformed base64 blob")
                    continue
                }

                if (encryptedBytes.size < AES_GCM_MIN_BLOB_BYTES) {
                    platformLogWarn(LOG_TAG, "poll: skipping 1 blob shorter than 28 bytes")
                    continue
                }

                val paddedBytes = try {
                    aesGcmDecrypt(
                        ciphertext = encryptedBytes,
                        key = encryptionKey,
                        associatedData = aeadContext
                    )
                } catch (e: Exception) {
                    platformLogError(LOG_TAG, "decrypt failed: ${e::class.simpleName}")
                    continue
                }

                val plaintextBytes = try {
                    unpadMessage(paddedBytes)
                } catch (_: Exception) {
                    platformLogWarn(LOG_TAG, "Padding validation failed for received blob")
                    continue
                }

                val env = parseEnvelope(plaintextBytes.decodeToString())

                // Hard policy (2026-05-17): a message
                // without a valid counter+epoch — a legacy/plaintext envelope or
                // one a hostile relay stripped to the old form — is dropped. No
                // downgrade path.
                if (env == null || env.epoch == null || env.counter == null) {
                    platformLogWarn(LOG_TAG, "drop: no anti-replay counter")
                    continue
                }
                val drop = legacyDropReason(env, ctx, seen)
                if (drop != null) {
                    platformLogWarn(LOG_TAG, drop)
                    continue
                }
                // The peer accepts sealed control on its control inbox. Honoured from
                // a static-key envelope on purpose: it only changes how WE send, toward the
                // ratchet, and a peer that has not engaged its ratchet can say it no other way.
                if (env.ctlRatchetCap == "1") seen.ctlCapAdvert = true
                legacyCandidates.add(env to blobIdx)
            }
        }
        return LegacyFirstPass(legacyCandidates, seen)
    }

    // The per-envelope checks of the legacy first pass, in order: null = keep, else
    // the exact drop line. Marks what it [seen] on the way (a later check may still
    // drop the blob — the mark stays, exactly as before).
    private fun legacyDropReason(env: Envelope, ctx: LegacyDrainContext, seen: LegacySeen): String? {
        // Wrong key-epoch: a blob from a previous shared secret being
        // replayed. (A blob from a different contact already fails AEAD.)
        if (env.epoch != ctx.expectedEpoch) {
            return "drop: stale epoch"
        }
        // Channel binding: the sender seals which inbox-channel
        // this blob was for ("m" main / "c" control / "g" group) inside the AEAD.
        val expectedChannel = ctx.chan.tag
        if (env.channel != null) {
            // Tagged: it must match the inbox we actually polled, else a relay
            // cross-spliced an authentic blob between the pairing's inboxes
            // (independent counter spaces would let it pass the replay check).
            if (env.channel != expectedChannel) {
                return "drop: channel ${env.channel} != $expectedChannel (cross-channel splice)"
            }
            // First tag seen from this peer → mark tag-capable, but DEFER the persist
            // to after the drain so it can't retroactively drop legacy untagged
            // blobs served later in THIS same drain.
            seen.channelTag = true
        } else if (ctx.peerTagsChannelsAtStart) {
            // Untagged blob from a peer we KNOW tags its channels: a relay
            // downgrade / cross-splice / replay of a pre-tag blob. Drop. This
            // closes the residual splice for tag-capable peers; a genuinely
            // legacy peer never sets the marker, so it stays accepted.
            return "drop: missing channel tag from a channel-tagging peer"
        }
        // Destination-inbox binding. The sender sealed the inbox it
        // POSTed to ("di") inside the AEAD; it must equal the inbox we polled, else the
        // relay cross-spliced an authentic blob between this pairing's inboxes — e.g.
        // reflected our OWN outbound blob onto our inbound inbox, which passes the
        // replay check because the two directions keep separate counter baselines.
        // Distinguishes DIRECTION within a channel, which "ch" cannot.
        if (env.destInbox != null) {
            if (env.destInbox != ctx.inboxId) {
                return "drop: di != polled inbox (cross-inbox reflection/splice)"
            }
            seen.inboxBind = true
        } else if (ctx.peerBindsInboxAtStart) {
            // di-less blob from a peer we KNOW binds its inbox: a relay downgrade, or a
            // reflected pre-binding blob. Drop (a genuinely legacy peer never binds, so
            // it never sets the marker and stays accepted).
            return "drop: missing inbox binding from a binding-capable peer"
        }
        // Malformed group routing fields — drop the whole message rather
        // than mis-route it. (A well-formed 1:1 message has none of these.)
        if (env.groupId != null && !isValidGroupId(env.groupId)) {
            return "drop: malformed group id"
        }
        if (env.controlKind != null) {
            if (env.controlKind.length > MAX_CONTROL_KIND_CHARS) {
                return "drop: malformed control kind"
            }
            // DIRECT (group-less) control is allowlisted: the inbox announce
            // plus [isKnownDirectControlKind]. Anything else is unknown — drop,
            // never surface as a text bubble. This is also the forward-compat
            // rule: a kind this build predates is dropped silently here.
            if (env.groupId == null &&
                env.controlKind != CONTROL_KIND_INBOX &&
                !isKnownDirectControlKind(env.controlKind)) {
                return "drop: unknown direct control"
            }
        }
        // A bare TEXT envelope — one with no
        // control kind — has no legitimate reason to arrive on the CONTROL
        // inbox. The control inbox carries ONLY k/b control messages
        // (env.controlKind != null): sendGroupText routes group TEXT over a TEXT
        // channel ([Chan.MAIN] or [Chan.GRP]), and only
        // sendGroupControl/sendDirectControl/sendInboxAnnounce select
        // [Chan.CTL] — every one of them always writes "k". Accepting a bare text here
        // fed an unbounded RAM buffer (GroupManager.pendingDirect via
        // bufferAll = true on the background control sweep) with no conversation
        // ever open to drain it — see [MAX_PENDING_CONTENT_PER_KEY]. The ratchet
        // receive path is already gated for this
        // (receiveOverTextRatchet with Chan.CTL only accepts the announce and the
        // sealed control kinds, never a bare text); this closes the legacy fallback.
        //
        // (2026-09-16) The original guard also required
        // `env.groupId == null`, so a GROUP-TAGGED bare text ({"g":…} with no
        // "k") sailed straight through — the comment above already asserted the
        // invariant this now actually enforces. That was the delivery vector for
        // the unresolved-sender buffer flood: a removed member posting
        // group-tagged, control-kind-less blobs onto the victim's CONTROL inbox
        // reached GroupManager.acceptGroupText on the BACKGROUND sweep, with no
        // conversation open, and parked them.
        if (ctx.chan == Chan.CTL && env.controlKind == null) {
            return "drop: bare text on control inbox"
        }
        // The GROUP inbox's mirror of that guard, and its own sibling. Nothing
        // legitimate produces either shape: `sendGroupText` is the ONLY sender
        // that ever selects [Chan.GRP], and it always writes "g" and never "k".
        //   • no "g"  ⇒ a 1:1 text (or a spliced blob) parked where the receiver
        //     would route it to the group layer with no group to route it to;
        //   • a "k"   ⇒ group CONTROL, which stays on the control inbox — the
        //     buffer-flood vector, mirrored.
        // The TEXT inbox is deliberately UNCHANGED and still accepts a
        // group-tagged blob: dropping it there would lose every group message
        // from a legacy peer and every one sent during the backfill window.
        if (ctx.chan == Chan.GRP && (env.controlKind != null || env.groupId == null)) {
            return "drop: non-group-text blob on the group inbox"
        }
        return null
    }

    // The legacy envelopes the sorted, strict-monotonic apply accepted: surfaced
    // messages, the running baseline and whether it moved.
    private class LegacyApplied(val messages: List<ReceivedMessage>, val lastCounter: Long, val advanced: Boolean)

    private fun applySortedLegacy(
        contactId: String, contact: ContactRecord, chan: Chan, legacyCandidates: MutableList<Pair<Envelope, Int>>,
        startCounter: Long, ctlCeiling: Long, ctlSealWatermark: Long?, announceLocked: Boolean, ledger: BlobLedger,
    ): LegacyApplied {
        val messages = mutableListOf<ReceivedMessage>()
        var lastCounter = startCounter
        var advanced = false
        // Sort by counter BEFORE the strict-monotonic check. The relay controls
        // blob ORDER within a drain, so applying the monotonic rule in arrival
        // order would let a hostile relay permanently suppress a message by
        // serving a higher counter before a lower one (the lower then looks
        // like a replay and is dropped). Sorting recovers any in-drain reorder
        // while still rejecting genuine replays/duplicates and cross-poll
        // reorder-old (counter <= the persisted baseline).
        legacyCandidates.sortBy { it.first.counter ?: 0L }

        for ((env, blobIdx) in legacyCandidates) {
            val counter = env.counter ?: continue
            // Strict monotonic: replay / reordered-old / duplicate.
            if (counter <= lastCounter) {
                // Retrieve-ack: right after an ack that was never confirmed, this is the
                // relay RE-DELIVERING (lease expired before the ack landed), not a
                // replay. Same blob either way, same drop; the label keeps a real
                // replay distinguishable in a debug log.
                val why = if (likelyRedelivery(contactId, chan)) "re-delivery after a lost ack" else "replay/dup"
                platformLogWarn(LOG_TAG, "drop: counter $counter <= seen $lastCounter ($why)")
                continue
            }
            // Forward-jump cap (CONTROL inbox). Dropped WITHOUT advancing, so a
            // forged far-future counter costs the genuine traffic nothing. The pending
            // list is sorted, so everything after this one is above the ceiling too.
            if (counter > ctlCeiling) {
                platformLogWarn(LOG_TAG, "drop: control counter jumped past the forward cap")
                continue
            }
            // Sealed-control receive lock: a static-key copy of an integrity-critical control
            // kind above the peer's ratchet-proven commitment can only be a forgery
            // from a stolen sharedSecret (the real peer seals those on the ratchet from
            // that counter on). Dropped WITHOUT advancing the counter, mirroring the
            // announce lock below and the text receive lock, so the genuine stream behind it
            // is untouched. A copy at or below the commitment is a genuine pre-commit
            // blob still queued on the relay and is accepted.
            if (ctlSealWatermark != null && counter > ctlSealWatermark &&
                isRatchetSealedControlKind(env.controlKind, groupScoped = env.groupId != null)
            ) {
                platformLogWarn(LOG_TAG, "poll: dropping legacy integrity control after the peer's ratchet commitment (sealed-control watermark)")
                continue
            }
            // Direct inbox announce: apply to the vault, never surface as a
            // message. Applied only AFTER the anti-replay check above, so a
            // replayed announce can't resurrect a rotated-away inbox. The
            // counter still advances (below) — control messages consume
            // counter space like any other.
            if (env.controlKind == CONTROL_KIND_INBOX && env.groupId == null) {
                // Once this peer's text ratchet is past its
                // bootstrap window (dr-rxlock armed), a STATIC-key announce can only
                // be a post-compromise forgery — a vault image yields sharedSecret +
                // our control write cap, which is everything a legacy announce needs.
                // The real peer sends announces over the ratchet from dr-on onward.
                // Dropped WITHOUT advancing the counter (mirrors the text receive lock).
                if (announceLocked) {
                    platformLogWarn(LOG_TAG, "poll: dropping legacy inbox announce after ratchet lock (receive-lock downgrade guard)")
                    continue
                }
                applyInboxAnnounce(contact.contactId, env.controlBody)
                lastCounter = counter
                advanced = true
                ledger.acceptLegacy(blobIdx)
                continue
            }
            // 1:1 screenshot notice: park it for the conversation layer, never
            // surface it as a message. Deliberately here — AFTER the
            // strict-monotonic check — so a relay re-serving the blob cannot make
            // the notice fire twice; and the counter advances like any other
            // control message, so the notice consumes counter space as its
            // siblings do. `env.timestamp` (the sender's minute-rounded capture
            // time, already inside the AEAD) rides along for display only.
            if (env.controlKind == CONTROL_KIND_SCREENSHOT && env.groupId == null) {
                noteScreenshotNotice(contact.contactId, env.timestamp)
                lastCounter = counter
                advanced = true
                ledger.acceptLegacy(blobIdx)
                continue
            }
            // A forward jump means earlier messages were dropped (relay or
            // transit). Flag only once we have a baseline in this epoch.
            val gap = lastCounter > 0 && counter > lastCounter + 1
            messages.add(
                env.toReceived(counter = counter, sequenceGap = gap, dedupeId = receiveDedupeId(ratchet = false, counter = counter))
            )
            lastCounter = counter
            advanced = true
            ledger.acceptLegacy(blobIdx)
        }
        return LegacyApplied(messages, lastCounter, advanced)
    }

    // Retrieve-ack: what the drain hands back — the persist-mode ack, or the
    // pending part a conversation screen commits after render. Built LAST, after
    // every persist this drain does inline, so a background drain acks only what
    // it has made durable.
    private fun buildDrainOutcome(
        p: PreparedDrain, ledger: BlobLedger, blobCount: Int, lease: Lease?, pendingMode: Boolean,
        pendingDrainGroup: Any?, legacyKey: String, report: RatchetManager.DecryptBatchReport,
        legacy: LegacyApplied, persistLegacyAtCommit: Boolean, expectedEpoch: String, textGrace: Boolean,
        msgs: List<ReceivedMessage>,
    ): DrainOutcome {
        val contactId = p.contactId
        val chan = p.chan
        val inboxId = p.inboxRecord.inboxId
        val ids = lease?.ids
        val free = ArrayList<String>()
        val rIds = ArrayList<String>()
        val lIds = ArrayList<String>()
        if (ids != null) for (blobIdx in ledger.outcome.indices) {
            if (ledger.outcome[blobIdx] == BlobOutcome.NOT_PROCESSED) continue
            when (ledger.ackDep[blobIdx]) {
                AckDep.NONE -> free.add(ids[blobIdx])
                AckDep.RATCHET -> rIds.add(ids[blobIdx])
                AckDep.LEGACY -> lIds.add(ids[blobIdx])
            }
        }
        if (lease != null) {
            val held = ledger.outcome.count { it == BlobOutcome.NOT_PROCESSED }
            if (held > 0) platformLog(LOG_TAG, "retrieve-ack: $held of $blobCount blob(s) left un-acked for re-delivery")
        }
        val readCap = p.headers[READ_CAP_HEADER] ?: ""
        // No usable ids ⇒ no ack at all, not even a release: re-serving at once a
        // batch we cannot settle would only loop it; the lease expires instead.
        val ackToken = lease?.token?.takeIf { ids != null }
        if (!pendingMode) {
            val ack = ackToken?.let { AckItem(inboxId, readCap, it, free + rIds + lIds, legacyKey) }
            return DrainOutcome(msgs, ack, null)
        }
        val part = PendingPart(
            contactId, chan, checkNotNull(pendingDrainGroup) { "pending mode without a drain group" }, inboxId, readCap, token = ackToken,
            freeIds = free, ratchetIds = rIds, legacyIds = lIds,
            ratchetTicket = report.pendingTicket, ratchetBase = report.baseTicket,
            legacyBaseline = if (legacy.advanced && persistLegacyAtCommit) legacy.lastCounter else null,
            legacyEpoch = expectedEpoch,
            consumeGrace = textGrace && persistLegacyAtCommit,
            createdAtMs = currentTimeMillis(),
        )
        if (lease == null) {
            // The relay did not lease — it deleted at fetch, so there is nothing
            // to wait for: commit now (today's semantics, nothing to ack).
            try { commitPendingPartAck(part) } catch (e: Exception) {
                platformLogWarn(LOG_TAG, "retrieve-ack: inline commit failed: ${e::class.simpleName}")
            }
        } else {
            // Rules 2/4/5 discarding this advance release its lease at once.
            part.ratchetTicket?.onDiscarded = { releaseLease(part) }
            if (part.legacyBaseline != null) pendingLock.withLock { pendingLegacy[legacyKey] = part }
        }
        return DrainOutcome(msgs, null, part)
    }

    /**
     * Persists [chan]'s inbound anti-replay baseline [lastCounter] (and the shared
     * [expectedEpoch]) on a FRESH row. False only when the write failed; a contact
     * deleted meanwhile is not resurrected and counts as done (nothing to protect).
     */
    private fun persistLegacyBaseline(contactId: String, chan: Chan, expectedEpoch: String, lastCounter: Long): Boolean {
        return try {
            // Persist under the per-contact lock, re-reading the row
            // fresh INSIDE the lock. `contact` was snapshotted before the
            // (up-to-60s) Tor round-trip above; writing it back would roll the
            // OTHER channel's counter / the outbound counters backward to their
            // pre-round-trip values (a concurrent send or the other poll may
            // have advanced them meanwhile), reopening the replay window. Only
            // this channel's own counter + the shared epoch are updated on the
            // fresh row; sibling counters keep their current persisted values.
            counterLock(contactId).withLock {
                // Re-read the row fresh under the lock, and if the
                // contact was DELETED during the (up-to-60s) Tor round-trip above, do
                // NOT fall back to the pre-round-trip snapshot and re-persist it — that
                // would RESURRECT the deleted contact and re-write its sharedSecret +
                // alias (notable for a forensic-seizure threat model). Skip the write.
                val fresh = databaseManager.getContact(contactId)
                if (fresh == null) {
                    platformLogWarn(LOG_TAG, "contact gone during poll — skipping replay-baseline persist (not resurrecting)")
                } else {
                    // Monotonic WITHIN an epoch: a concurrent poll of this same
                    // channel may have already advanced the baseline past our
                    // lastCounter, so clamp to the max — never write a lower value
                    // (that would reopen the replay window). An epoch flip (re-pair)
                    // resets the baseline, matching the implicit-reset semantics
                    // documented above.
                    try {
                        val sameEpoch = fresh.inboundEpoch == expectedEpoch
                        val cur = if (sameEpoch) maxOf(lastCounter, chan.inCounterOf(fresh)) else lastCounter
                        databaseManager.insertContact(
                            chan.withInCounter(fresh.copy(inboundEpoch = expectedEpoch), cur)
                        )
                    } finally {
                        // The insert has bound the bytes; this decoded copy is dead.
                        fresh.sharedSecret.secureWipe()
                    }
                }
            }
            true
        } catch (e: Exception) {
            platformLogError(LOG_TAG, "persist replay state failed: ${e::class.simpleName}")
            false
        }
    }

    /**
     * Applies a received in-band inbox announce: upserts the OUTBOUND record for
     * [contactId] (where we send to this peer). Reached only for blobs that passed
     * AEAD under the pairwise secret AND the anti-replay check, so the SENDER is
     * provably this contact. That is NOT the same as "the announced inbox is theirs"
     * — see [firstUnavailableInboxClaim]: an authenticated contact can name a
     * THIRD party's inbox id, so ownership is checked separately. Shape-checks mirror
     * the QR-parse rules — a malformed announce is dropped whole.
     */
    private fun applyInboxAnnounce(contactId: String, body: String?) {
        // If the contact was DELETED (e.g. during a long poll
        // round-trip), do NOT re-create its capability-bearing inbox_ids rows — that
        // resurrects relay-routing metadata (inboxId + WRITE-capability) for a contact
        // deleteContact just purged (sibling of the contact-row guard, which covers
        // the contact row; this guards its satellite inbox rows).
        if (!contactExists(contactId)) {
            platformLogWarn(LOG_TAG, "inbox announce for gone contact — skipping (not resurrecting)")
            return
        }
        val raw = body ?: run {
            platformLogWarn(LOG_TAG, "inbox announce without body dropped")
            return
        }
        fun field(key: String) = firstStringFieldAnywhere(raw, key)
        // Every pair is OPTIONAL, both-or-neither and shape-checked; at least ONE
        // complete pair is required. `ib`/`wc` became optional deliberately and it is
        // mandatory rather than cosmetic: our own inbound WRITE cap is never
        // persisted (it is held in RAM at pairing only), so a LATER announce — the
        // group-inbox backfill, the 404 re-mint — physically cannot re-state
        // `wc`. It CAN state `gwc`, which comes straight out of the mint it just
        // performed, so a group-only announce carries `{"gib","gwc","rv"}` and
        // nothing else. A malformed pair still drops the WHOLE announce.
        var malformedPair = false
        fun pair(idKey: String, capKey: String, what: String): Pair<String, String>? {
            val id = field(idKey)
            val cap = field(capKey)
            if (id == null && cap == null) return null                      // absent
            if (id == null || cap == null || !isValidInboxId(id) || !isValidCapability(cap)) {
                platformLogWarn(LOG_TAG, "malformed $what pair in inbox announce dropped")
                malformedPair = true
                return null
            }
            return id to cap
        }
        val textPair = pair("ib", "wc", "text")
        val ctlPair = pair("cib", "cwc", "ctl")
        val grpPair = pair("gib", "gwc", "grp")
        if (malformedPair) return
        if (textPair == null && ctlPair == null && grpPair == null) {
            platformLogWarn(LOG_TAG, "inbox announce with no complete pair dropped")
            return
        }
        // An announce declares the PEER's inbox ids, which become
        // OUR outbound (send-to) targets — but `inbox_ids` is keyed by inboxId, so accepting
        // a claim on an id we already hold REASSIGNS that row. The claims are checked as ONE
        // batch (see [firstUnavailableInboxClaim]) so `ib == cib` — which the old per-id
        // check waved through, letting the two inserts below collide on one primary key and
        // destroy the outbound row — is rejected along with our own inbound inboxes (relay
        // reflected our own announce back at us → a self-echo DoS) and any row belonging to
        // ANOTHER contact (an authenticated peer eclipsing a third party's route). An unknown
        // id, and a re-announce by its rightful owner, both stay accepted.
        // `gib` joins the SAME batch, which is what keeps `ib == gib` (and a `gib`
        // naming a third party's inbox, or one of our own inbound inboxes reflected
        // back at us) rejected as ONE unit with nothing written — exactly as `ib ==
        // cib` already is.
        val claims = buildList {
            textPair?.let { (ib, _) -> add(InboxClaim(ib, contactId, "outbound")) }
            ctlPair?.let { (cib, _) -> add(InboxClaim(cib, contactId, DIR_OUTBOUND_CTL)) }
            grpPair?.let { (gib, _) -> add(InboxClaim(gib, contactId, DIR_OUTBOUND_GRP)) }
        }
        try {
            val now = currentTimeMillis()
            // CORRECTION 1: the inserts are ONE batch — an `ib` that lands followed by a
            // `cib` that throws used to leave the announce half-applied. withTransaction also
            // makes the ownership gate below atomic with the writes it guards: the control
            // and message channels poll on different coroutines, so a check made OUTSIDE the
            // transaction could be raced by a concurrent announce claiming the same id.
            // enableRatchetIfReady does its own writes and stays OUTSIDE (no nesting).
            databaseManager.withTransaction {
                firstUnavailableInboxClaim(databaseManager, claims)?.let { throw InboxInUseException() }
                fun upsert(direction: String, id: String, cap: String) {
                    val existing = databaseManager.getInboxIdForContact(contactId, direction)
                    if (existing == null || existing.inboxId != id || existing.cap != cap) {
                        databaseManager.insertInboxId(
                            InboxIdRecord(
                                inboxId = id, contactId = contactId,
                                createdAt = now, expiresAt = now + VaultSeedDefaults.INBOX_LIFETIME_MS,
                                direction = direction, cap = cap,
                            )
                        )
                    }
                }
                textPair?.let { (ib, wc) -> upsert("outbound", ib, wc) }
                ctlPair?.let { (cib, cwc) -> upsert(DIR_OUTBOUND_CTL, cib, cwc) }
                grpPair?.let { (gib, gwc) -> upsert(DIR_OUTBOUND_GRP, gib, gwc) }
            }
            platformLog(LOG_TAG, "in-band announce applied")
            // An announce is the peer's own authenticated, replay-checked
            // message, so an `rv:2` in it is evidence the peer runs the v2 role rule.
            // Recorded AFTER the transaction committed (a dropped/refused announce is
            // not evidence of anything) and strictly BEFORE enableRatchetIfReady, which
            // is the call that can flip `dr-on` and make the very next send the FIRST
            // ratchet op — i.e. the one that freezes the role. Absent ⇒ id rule.
            if (field(ROLE_RULE_FIELD) == ROLE_RULE_V2) notePeerRoleRuleV2(databaseManager, contactId)
            // The responder learns its outbound text inbox here — now both text
            // inboxes exist, so a ratchet-capable pairing can flip ratchet-ON and
            // (if we're the initiator) bootstrap. No-op for legacy contacts.
            enableRatchetIfReady(contactId)
        } catch (_: InboxInUseException) {
            // Silent drop, no UI: the announce is authenticated but names an id we
            // cannot give it. Nothing was written (the throw is the first statement
            // in the transaction, and it rolls back regardless).
            platformLogWarn(LOG_TAG, "inbox announce names an inbox already owned elsewhere — dropped")
            return
        } catch (e: Exception) {
            // Fail open-ish: the peer re-announces on no channel… it cannot.
            // A lost announce persist means the contact stays pending; the
            // user-visible state is honest ("waiting for their inbox").
            platformLogError(LOG_TAG, "inbox announce persist failed: ${e::class.simpleName}")
        }
    }

    // -----------------------------------------------------------------------
    // Rotation — owner-only (authenticated with the current READ cap). The READ
    // cap is rotated crash-safely by [rotateReadCap] / [resetRelayAccess] below;
    // the old non-durable `rotateReadCapability` (no pending marker, no production
    // caller) was removed.
    // -----------------------------------------------------------------------

    // Reject a capability with control chars (CRLF / header injection) or an
    // implausible length before it is placed into an HTTP header.
    private fun capValidForHeader(cap: String): Boolean =
        cap.isNotEmpty() && cap.length <= 256 &&
            cap.none { it.code < 0x20 || it.code == 0x7F }

    /**
     * Rotates the write capability on our inbound inbox. Authenticates with
     * our current READ cap (writers cannot rotate). After success, the new
     * writeCap must be delivered to the peer out-of-band — over Tor there's
     * no in-protocol channel for this, so a leaked writeCap recovery is
     * effectively another IRL meeting. The local persistence reflects what
     * the peer SHOULD now have, not necessarily what they do have.
     *
     * NO production caller, and non-durable (nothing is persisted, nothing is
     * delivered to the peer): write-cap rotation is deliberately not wired
     * (docs/vault-relay-internals.md, read-capability section). Kept only for the
     * header-injection and freeze-gate tests that cover it.
     */
    @Deprecated("No production caller; write-cap rotation is deliberately not wired. See rotateReadCap / resetRelayAccess.")
    fun rotateWriteCapabilityNonDurable(contactId: String, newWriteCap: String): Boolean {
        // Freeze gate, same reason as [resetRelayAccess] — and worse here, since
        // the peer holds the write cap this would invalidate out from under them.
        if (moveFrozen("write-cap rotate")) return false
        if (!capValidForHeader(newWriteCap)) {
            platformLogWarn(LOG_TAG, "rotateWriteCap: invalid new cap — refused")
            return false
        }
        val inboxRecord = databaseManager.getInboxIdForContact(contactId, "inbound") ?: return false
        val currentReadCap = inboxRecord.cap ?: return false
        // Mirror send/poll: validate the STORED cap + inbox ID before the header /
        // validatedInboxUrl() (CRLF-injection + uncaught-throw guard, as above).
        if (!capValidForHeader(currentReadCap) || !isValidInboxId(inboxRecord.inboxId)) {
            platformLogWarn(LOG_TAG, "rotateWriteCap: stored cap/inbox invalid — refused")
            return false
        }
        val url = validatedInboxUrl(inboxRecord.inboxId, "/write-capability")
        val result = try {
            httpClient.put(
                url = url, body = ByteArray(0), contentType = CONTENT_TYPE,
                headers = mapOf(READ_CAP_HEADER to currentReadCap, NEW_WRITE_CAP_HEADER to newWriteCap),
            )
        } catch (e: Exception) {
            platformLogError(LOG_TAG, "rotateWriteCap HTTP failed: ${e::class.simpleName}")
            return false
        }
        if (!result.isSuccess) {
            platformLogWarn(LOG_TAG, "rotateWriteCap → code=${result.code}")
            return false
        }
        platformLog(LOG_TAG, "rotated write cap")
        return true
    }

    // -----------------------------------------------------------------------
    // Crash-safe READ-capability rotation + explicit inbox delete.
    //
    // The read cap is the inbox OWNER capability, so a single compelled unlock (or
    // an imaged vault returned to the user) hands an operator INDEFINITE remote
    // ability to drain the inbound inboxes before the app polls, mint themselves a
    // write cap, rotate the user's own cap away, or register their own push token.
    // Rotating it is the only thing that closes all four. Only the READ cap is
    // rotated here: our own inbound WRITE cap is never persisted (PairingVault
    // stores read caps only), so an imaged vault yields the read cap alone.
    // -----------------------------------------------------------------------

    /**
     * Destroys an inbox on the relay (`DELETE /inbox/{id}`, authenticated with its
     * READ capability). Best-effort and NON-THROWING:
     *
     *  - a malformed id/cap is refused BEFORE any network call (the same CRLF /
     *    header-injection guard every other relay call site applies);
     *  - `404` — already gone, or the cap no longer authenticates — returns false;
     *  - any transport failure returns false.
     *
     * Deliberately NO retry loop: a lost DELETE costs only the orphan inbox we
     * already had (it expires under the relay's idle TTL), whereas retrying would
     * hold a user-visible delete on a wedged Tor circuit for minutes.
     *
     * Only call it where destroying the inbox is UNAMBIGUOUS — the contact was just
     * deleted locally, or the inbox was never persisted/shared. Never from a BLOCK
     * path (reversible UI must not fire an irreversible action) and never from a
     * WIPE path (crypto-erase-first forbids network I/O there, and a mass-DELETE
     * burst would broadcast a deniable wipe to the relay).
     *
     * NOT subject to the "move to new device" freeze gate: this is the primitive
     * [RelayMoveTransport] destroys the TRANSFER inbox with (and the export's own
     * failure paths depend on it landing while the vault is frozen). Its
     * contact-facing caller — [deleteContactAndPurgeRelay] — is a deliberate user
     * action off a screen a frozen phone never shows, and the local delete that
     * gates it is a vault write, not a relay one.
     */
    fun deleteInbox(inboxId: String, readCap: String): Boolean {
        if (!isValidInboxId(inboxId) || !capValidForHeader(readCap)) {
            platformLogWarn(LOG_TAG, "deleteInbox: malformed inbox/cap — refused")
            return false
        }
        val result = try {
            httpClient.delete(validatedInboxUrl(inboxId), mapOf(READ_CAP_HEADER to readCap))
        } catch (e: Exception) {
            platformLogWarn(LOG_TAG, "deleteInbox threw: ${e::class.simpleName}")
            return false
        }
        if (result.code == 404) {
            platformLog(LOG_TAG, "deleteInbox: already gone")
            return false
        }
        if (!result.isSuccess) {
            platformLogWarn(LOG_TAG, "deleteInbox → code=${result.code}")
            return false
        }
        platformLog(LOG_TAG, "deleted an inbox on the relay")
        return true
    }

    // Per-(contact, direction) rotation lock, mirroring [sendOrderLock] /
    // [counterLock]. It wraps the WHOLE rotate+reconcile sequence, which is
    // load-bearing rather than tidy: without it an ordinary un-debounced double-tap
    // lets two rotations both pass the "is a marker pending?" check, and the loser
    // then resolves NEITHER cap — landing permanently on UNKNOWN ("keep both") with
    // a marker that blocks every future rotation, i.e. the contact is wedged into
    // the relay-lost/re-pair path. That is worse than the race this closes.
    // Non-reentrant (iOS NSLock): the public entry points take it once and the
    // *Locked helpers below assume it is already held.
    //
    // Like [counterLock], the registry lives in [ContactRowLocks] rather than
    // in a private map here: both platforms recreate MessageManager on a Tor
    // reconnect via a bare unawaited cancel of the old poll job, so an
    // instance-scoped registry let a dying instance mid-rotation race the NEW
    // instance's poll-loop reconcile for the same (contact, direction) on two
    // disjoint locks — the two-unserialised-rotations wedge described above, minus
    // the double-tap.
    private fun rotationLock(contactId: String, direction: String): SyncLock =
        ContactRowLocks.forRotation(contactId, direction)

    /**
     * Control-flow sentinel thrown from INSIDE a rotation check-then-write
     * transaction when the inbox row vanished (contact deleted mid-flight) —
     * rolls the transaction back without writing, mirroring the announce path's
     * [InboxInUseException] pattern.
     */
    private class InboxRowGoneException : RuntimeException()

    // The rotation's check-then-write unit: ONE vault transaction that re-reads the
    // (contact, direction) inbox row LIVE and runs [block] only if it still is
    // [expectedInboxId]; otherwise it throws [InboxRowGoneException], which rolls the
    // transaction back with nothing written. deleteContact runs inside its own
    // transaction on both platforms, so a bare re-read followed by a write could land
    // AFTER that purge and re-create capability-bearing state (the non-resurrection
    // rule). A throwing re-read counts as "gone". The callers keep their own catch
    // ladders and phrases.
    private inline fun inTxWithLiveInboxRow(
        contactId: String,
        direction: String,
        expectedInboxId: String,
        crossinline block: (InboxIdRecord) -> Unit,
    ) {
        databaseManager.withTransaction {
            val live = try {
                databaseManager.getInboxIdForContact(contactId, direction)
            } catch (_: Exception) { null }
            if (live == null || live.inboxId != expectedInboxId) throw InboxRowGoneException()
            block(live)
        }
    }

    // Inbox ids whose read cap was just rotated — the relay's push registration for
    // them was evicted (see [onRotationCommitted]), so the platform must drop them
    // from its SESSION-scoped "already registered" set and let its existing re-sync
    // re-register OUR token under the new cap. Pull-based (drained on the platform's
    // control-poll cycle) rather than a callback, so it stays testable in commonTest
    // and adds no new registration call site. Bounded: a Set of at most this
    // device's own inbound inbox ids.
    private val rotatedPushLock = SyncLock()
    private val rotatedPushInboxIds = mutableSetOf<String>()

    /** Takes and clears the pending push-eviction set — see [rotatedPushInboxIds]. */
    fun drainRotatedPushInboxIds(): Set<String> = rotatedPushLock.withLock {
        val out = rotatedPushInboxIds.toSet()
        rotatedPushInboxIds.clear()
        out
    }

    /**
     * User-facing "Reset relay access": rotates the read capability on BOTH of this
     * contact's inbound inboxes (text + control — see [OWNED_READ_DIRECTIONS]).
     * Non-destructive: messages, history and the contact itself are untouched, and
     * the peer needs to do nothing (their WRITE caps are unaffected).
     *
     * Returns true only when every inbox that EXISTS rotated successfully. A pre-v7
     * pairing with no control inbox simply has nothing to rotate there and is not
     * counted as a failure. False means "not proven done" — never data loss: the
     * durable marker survives and the poll loop reconciles it (see
     * [reconcileReadCapRotation]).
     */
    fun resetRelayAccess(contactId: String): Boolean {
        // Freeze gate. Rotating a CONTACT inbox's read cap after the export snapshot
        // was taken would leave the new phone importing a cap the relay no longer
        // accepts — an inbox its owner can never drain again. Not reachable from the
        // frozen UI, but both platforms call it straight off this object
        // (RunViewModel.resetRelayAccessInBackground / AppState.resetRelayAccess).
        // `false` = "not proven done", which both call sites already surface.
        // The move's OWN rotation entry point ([rotateOwnedInboxReadCap], used by the
        // NEW phone's Securing step) is deliberately not gated.
        if (moveFrozen("reset relay access")) return false
        var rotated = 0
        var failed = 0
        for (direction in OWNED_READ_DIRECTIONS) {
            val present = try {
                databaseManager.getInboxIdForContact(contactId, direction) != null
            } catch (e: Exception) {
                platformLogWarn(LOG_TAG, "resetRelayAccess: inbox read failed: ${e::class.simpleName}")
                failed++
                continue
            }
            if (!present) continue   // pre-v7 pairing: no control inbox to rotate
            if (rotateReadCap(contactId, direction) == CapRotationOutcome.ROTATED) rotated++ else failed++
        }
        platformLog(LOG_TAG, "resetRelayAccess: rotated=$rotated failed=$failed")
        return rotated > 0 && failed == 0
    }

    /**
     * Rotates the READ capability on ONE inbound inbox, crash-safely. Ordering (the
     * crux — see [CapRotationOutcome]):
     *
     *  0. resolve any pending rotation FIRST (never chain onto an unresolved one);
     *  1. mint a fresh 32-byte cap;
     *  2. persist it as the DURABLE pending marker, before ANY network I/O;
     *  3. `PUT /inbox/{id}/read-capability` — whose response is ignored for the
     *     decision, it is only a hint;
     *  4. decide by probing, i.e. [reconcileReadCapRotation].
     */
    fun rotateReadCap(contactId: String, direction: String): CapRotationOutcome =
        rotationLock(contactId, direction).withLock {
            // Step 0. An unresolvable pending marker means we cannot tell which cap the
            // relay holds; starting a SECOND rotation on top would break the union
            // invariant. Report BUSY and let the poll-loop reconcile settle it.
            if (reconcileLocked(contactId, direction) == CapRotationOutcome.UNKNOWN) {
                CapRotationOutcome.BUSY
            } else {
                rotateLocked(contactId, direction)
            }
        }

    /**
     * Idempotent resolver for a pending rotation on one inbound inbox. Safe to call
     * at any time and from any thread; a no-op ([CapRotationOutcome.NOTHING_TO_DO])
     * when no marker exists.
     */
    fun reconcileReadCapRotation(contactId: String, direction: String): CapRotationOutcome =
        rotationLock(contactId, direction).withLock { reconcileLocked(contactId, direction) }

    /** Cheap gate + reconcile for the poll path — one `_meta` read in the steady state. */
    private fun maybeReconcileReadCap(contactId: String, direction: String) {
        val pending = try {
            databaseManager.getMeta(capPendingKey(contactId, direction))
        } catch (_: Exception) { null }
        if (pending.isNullOrEmpty()) return
        try {
            reconcileReadCapRotation(contactId, direction)
        } catch (e: Exception) {
            platformLogWarn(LOG_TAG, "read-cap reconcile failed: ${e::class.simpleName}")
        }
    }

    /** [rotateReadCap]'s body; the rotation lock is already held. */
    private fun rotateLocked(contactId: String, direction: String): CapRotationOutcome {
        val pendKey = capPendingKey(contactId, direction)
        val rec = try {
            databaseManager.getInboxIdForContact(contactId, direction)
        } catch (e: Exception) {
            platformLogWarn(LOG_TAG, "rotateReadCap: inbox read failed: ${e::class.simpleName}")
            null
        } ?: return CapRotationOutcome.FAILED
        val currentCap = rec.cap
        // Mirror send/poll: validate the STORED cap + inbox id before they reach the
        // X-Read-Capability header / validatedInboxUrl(), so a corrupt/legacy row can
        // neither inject a header (CRLF) nor make validatedInboxUrl() throw uncaught.
        if (currentCap.isNullOrEmpty() || !capValidForHeader(currentCap) || !isValidInboxId(rec.inboxId)) {
            platformLogWarn(LOG_TAG, "rotateReadCap: stored cap/inbox invalid — refused")
            return CapRotationOutcome.FAILED
        }
        val existingPending = try {
            databaseManager.getMeta(pendKey)
        } catch (e: Exception) {
            platformLogWarn(LOG_TAG, "rotateReadCap: marker read failed: ${e::class.simpleName}")
            return CapRotationOutcome.FAILED
        }
        if (existingPending != null) return CapRotationOutcome.BUSY
        val newCap = encodeBase64Url(generateSecureRandom(32))
        if (!isValidCapability(newCap) || !capValidForHeader(newCap)) {
            platformLogError(LOG_TAG, "rotateReadCap: generated cap failed validation — refused")
            return CapRotationOutcome.FAILED
        }
        // DURABLE FIRST. If this write fails, nothing has been sent and nothing has
        // changed — the caller simply retries later. The row re-check and the marker
        // write are ONE vault transaction (the same shape as [reconcileLocked]'s
        // commit branch): deleteContact purges this marker with the contact inside
        // its own transaction on both platforms, so a marker written after a bare
        // check could land AFTER that purge and re-create capability-bearing `_meta`
        // state for a just-deleted contact (the non-resurrection rule).
        try {
            inTxWithLiveInboxRow(contactId, direction, rec.inboxId) { databaseManager.putMeta(pendKey, newCap) }
        } catch (_: InboxRowGoneException) {
            platformLogWarn(LOG_TAG, "rotateReadCap: inbox row gone/replaced before the marker write — not rotating")
            return CapRotationOutcome.FAILED
        } catch (e: Exception) {
            platformLogError(LOG_TAG, "rotateReadCap: pending marker persist failed: ${e::class.simpleName}")
            return CapRotationOutcome.FAILED
        }
        try {
            val result = httpClient.put(
                url = validatedInboxUrl(rec.inboxId, "/read-capability"),
                body = ByteArray(0),
                contentType = CONTENT_TYPE,
                headers = mapOf(READ_CAP_HEADER to currentCap, NEW_READ_CAP_HEADER to newCap),
            )
            platformLog(LOG_TAG, "rotateReadCap → code=${result.code}")
        } catch (e: Exception) {
            // The PUT's outcome is only a hint; the probe below is the decision. A
            // dropped response is exactly the case the durable marker exists for.
            platformLogWarn(LOG_TAG, "rotateReadCap PUT threw: ${e::class.simpleName}")
        }
        return reconcileLocked(contactId, direction)
    }

    /** [reconcileReadCapRotation]'s body; the rotation lock is already held. */
    private fun reconcileLocked(contactId: String, direction: String): CapRotationOutcome {
        val pendKey = capPendingKey(contactId, direction)
        val pending = try { databaseManager.getMeta(pendKey) } catch (_: Exception) { null }
        if (pending.isNullOrEmpty()) return CapRotationOutcome.NOTHING_TO_DO
        val rec = try {
            databaseManager.getInboxIdForContact(contactId, direction)
        } catch (_: Exception) { null }
        if (rec == null || !isValidInboxId(rec.inboxId)) {
            // No usable row to attach a cap to (the contact was deleted mid-rotation —
            // deleteContact purges the marker with it). Change NOTHING; never recreate
            // a capability-bearing row here.
            return CapRotationOutcome.UNKNOWN
        }
        // Probe with the CANDIDATE. `/peek` and never a bare GET: `GET /inbox/{id}`
        // DRAINS the inbox, so probing with it would silently destroy every queued
        // message. A pending that fails header validation can NEVER be probed or used
        // (it can only come from at-rest corruption of a value validated before it was
        // written) — treat it exactly like a 404 below, so it can still be retired
        // against a proven-alive current cap instead of wedging every future rotation.
        val candidateUsable = capValidForHeader(pending)
        val newProbe = if (candidateUsable) peekProbeCode(rec.inboxId, pending) else null
        if (newProbe != null && newProbe in 200..299) {
            // Live under the candidate → the relay DID rotate. Commit it, but re-read
            // the row LIVE first: a delete during the probe round-trip must not be
            // resurrected by this write (the non-resurrection rule). The re-read
            // and the write are ONE vault transaction (the same shape as the announce
            // path): deleteContact runs inside its own transaction on both
            // platforms, so a delete landing BETWEEN a bare re-read and the insert
            // would otherwise still re-create an inbox row bearing a live owner
            // capability for the just-deleted contact.
            try {
                inTxWithLiveInboxRow(contactId, direction, rec.inboxId) { live ->
                    databaseManager.insertInboxId(live.copy(cap = pending))
                }
            } catch (_: InboxRowGoneException) {
                platformLogWarn(LOG_TAG, "rotateReadCap: inbox row gone/replaced mid-reconcile — not resurrecting")
                return CapRotationOutcome.UNKNOWN
            } catch (e: Exception) {
                // Keep BOTH: the relay holds `pending`, the record still holds the old
                // cap, and the marker survives — the next reconcile commits it.
                platformLogError(LOG_TAG, "rotateReadCap: cap persist failed — keeping pending: ${e::class.simpleName}")
                return CapRotationOutcome.UNKNOWN
            }
            try {
                databaseManager.deleteMeta(pendKey)
            } catch (e: Exception) {
                // Harmless: the marker now EQUALS the record's cap, so the next
                // reconcile probes it, gets 200, re-commits the same value and retries
                // this delete. Idempotent by construction.
                platformLogWarn(LOG_TAG, "rotateReadCap: pending marker delete failed: ${e::class.simpleName}")
            }
            onRotationCommitted(rec.inboxId, pending)
            platformLog(LOG_TAG, "rotated read cap ($direction)")
            return CapRotationOutcome.ROTATED
        }
        if (newProbe == 404 || !candidateUsable) {
            // The candidate does not authenticate. Dropping the marker is only safe if
            // the cap we STILL hold is proven alive — and that cap must be re-read LIVE
            // at this moment, never a value captured by an earlier rotate call.
            val live = try {
                databaseManager.getInboxIdForContact(contactId, direction)
            } catch (_: Exception) { null }
            val liveCap = live?.cap
            if (live != null && !liveCap.isNullOrEmpty() &&
                capValidForHeader(liveCap) && isValidInboxId(live.inboxId)
            ) {
                val oldProbe = peekProbeCode(live.inboxId, liveCap)
                if (oldProbe != null && oldProbe in 200..299) {
                    try {
                        databaseManager.deleteMeta(pendKey)
                    } catch (e: Exception) {
                        platformLogWarn(LOG_TAG, "rotateReadCap: stale marker delete failed: ${e::class.simpleName}")
                        return CapRotationOutcome.UNKNOWN
                    }
                    platformLog(LOG_TAG, "rotateReadCap: rotation never landed — kept the current cap")
                    return CapRotationOutcome.NOT_APPLIED
                }
            }
        }
        // 429 / transport failure / both 404 → we cannot tell. Keep BOTH caps and
        // change nothing; the next poll cycle reconciles again.
        return CapRotationOutcome.UNKNOWN
    }

    /** HTTP code from a NON-DESTRUCTIVE `/peek` with [cap], or null if it threw. */
    private fun peekProbeCode(inboxId: String, cap: String): Int? = try {
        httpClient.get(validatedInboxUrl(inboxId, "/peek"), headers = mapOf(READ_CAP_HEADER to cap)).code
    } catch (e: Exception) {
        platformLogWarn(LOG_TAG, "cap probe threw: ${e::class.simpleName}")
        null
    }

    /**
     * Push eviction. Rotating the read cap does NOT invalidate a push token already
     * registered on that inbox, so an attacker's token would keep receiving wake
     * pushes (a live metadata channel) after the rotation. DELETE the registration
     * with the cap that JUST answered 200 — proven current at this moment, never a
     * pre-rotation snapshot — and record the inbox so the platform's existing
     * re-sync re-registers OUR token on its next cycle.
     */
    private fun onRotationCommitted(inboxId: String, committedCap: String) {
        try {
            PushRegistration.unregister(httpClient, relayBaseUrl, inboxId, committedCap)
        } catch (e: Exception) {
            platformLogWarn(LOG_TAG, "push eviction after rotation failed: ${e::class.simpleName}")
        }
        rotatedPushLock.withLock { rotatedPushInboxIds.add(inboxId) }
    }

    // -----------------------------------------------------------------------
    // "Move to new device" transport primitives (docs/device-move.md, D5).
    //
    // A move uploads a sealed, chunked snapshot of the vault to ONE dedicated
    // relay inbox that belongs to NO CONTACT, and the new phone drains it once.
    // Everything below is a THIN wrapper over relay verbs this class already
    // speaks — same [validatedInboxUrl], same [capValidForHeader] / [isValidInboxId]
    // CRLF guard, same [sendHeaders], same [postWithTransientRetry] discipline —
    // with the per-contact bookkeeping deliberately ABSENT: no counter bump, no
    // 404-streak / re-pair flagging ([noteRelay404]), no inbox lease re-stamp
    // ([noteInboxProvenLive]), no ratchet routing and no envelope parsing. There
    // is no contact to book any of it against, and a transfer inbox has no vault
    // row for those side effects to touch.
    //
    // NO PROTOCOL CHANGE: no new endpoint, no new header, no new wire field. The
    // chunk BODY is opaque here — [MigrationSeal] emits fixed-size sealed chunks
    // ([MoveConstants.CHUNK_PLAINTEXT_BYTES]) that already carry their own
    // padding, so this layer must NOT pad a second time (a second pass would push
    // the blob into the 128 KiB bucket and past the relay's 64 KiB ceiling).
    //
    // The RESULT CARRIES THE HTTP CODE, unlike [peekOnce] / [pollChannel] which
    // collapse every failure into "empty". That distinction is the whole reason
    // these exist: the move state machine must tell a genuine 404 (the transfer
    // inbox is gone — drained by the new phone, or TTL-expired) from "we could
    // not reach the relay", because the first is evidence and the second is not.
    //
    // NONE of them is subject to the freeze gate above, and that is the point:
    // `mig_frozen` is written BEFORE the mint + upload, so gating these would make
    // the export impossible. They are safe to leave open because a transfer inbox
    // belongs to no contact — no counter, no epoch, no ratchet chain, nothing the
    // new phone inherits. The same exemption covers the two EXISTING primitives the
    // transport reuses ([mintInbox] for the transfer inbox — note the PAIRING mint
    // [mintInboxPair] IS gated — and [deleteInbox] for destroying it) and
    // [rotateOwnedInboxReadCap], which is the NEW phone's post-import Securing step
    // and never runs on a frozen vault (the control sweep reaches it only through
    // the session layer's already-frozen-gated provider).
    //
    // All of them are `internal`; the [MoveTransport] implementation on top is
    // [RelayMoveTransport] (RelayMoveTransport.kt).
    // -----------------------------------------------------------------------

    /**
     * One relay answer for a move-transport call. [code] is the HTTP status, or
     * `-1` when the request threw / never got a response / was refused locally
     * before any I/O. [pending] is the `/peek` count when readable; [blobs] the
     * decoded bodies of a drain.
     */
    internal class MoveRelayResult(
        val code: Int,
        val pending: Int? = null,
        val blobs: List<ByteArray> = emptyList(),
    )

    /**
     * `POST /inbox/{id}?ttl=…` with `X-No-Push: 1` — one sealed migration chunk
     * into the transfer inbox, under the write cap the mint returned.
     *
     * Push is suppressed unconditionally: a transfer inbox has no registered
     * token (it was minted seconds ago and never handed to [PushRegistration]),
     * and the header keeps it that way even if a future relay changes defaults.
     *
     * Returns the HTTP code, or -1 when the POST never got a response. Uses
     * [postWithTransientRetry] like every other send, so a dropped Tor
     * round-trip retries the SAME bytes rather than failing the whole export.
     * That can leave a BYTE-IDENTICAL duplicate blob in the inbox when the relay
     * stored a copy whose response was lost — harmless by construction: the
     * importer de-duplicates identical blobs before unsealing (two distinct
     * chunks can never be byte-identical; each carries its own index in the AAD
     * and its own random nonce).
     */
    internal fun postMoveChunk(
        inboxId: String,
        writeCap: String,
        chunk: ByteArray,
        ttlSeconds: Long,
    ): Int {
        if (!isValidInboxId(inboxId) || !capValidForHeader(writeCap)) {
            platformLogWarn(LOG_TAG, "move upload: malformed inbox/cap — refused")
            return -1
        }
        // Refuse locally what the relay would refuse anyway (`blob.size >
        // maxBlobBytes` ⇒ 413), so an oversize chunk fails BEFORE half an export
        // is on the wire. Note the relay's comparison is strictly greater-than,
        // so a chunk of exactly [MOVE_MAX_BLOB_BYTES] is accepted.
        if (chunk.isEmpty() || chunk.size > MOVE_MAX_BLOB_BYTES) {
            platformLogWarn(LOG_TAG, "move upload: chunk size ${chunk.size} out of range — refused")
            return -1
        }
        val url = validatedInboxUrl(inboxId, ttlSeconds = ttlSeconds)
        val result = postWithTransientRetry(
            url, chunk, sendHeaders(writeCap, noPush = true), "move",
        )
        return result?.code ?: -1
    }

    /**
     * `GET /inbox/{id}/peek` on the transfer inbox — NON-destructive, so the old
     * phone can ask "has the new phone drained it yet?" without destroying the
     * bundle it is asking about. Same request [peekOnce] makes; the difference is
     * that the code comes back (see the section header).
     */
    internal fun peekMoveInbox(inboxId: String, readCap: String): MoveRelayResult {
        if (!isValidInboxId(inboxId) || !capValidForHeader(readCap)) {
            platformLogWarn(LOG_TAG, "move peek: malformed inbox/cap — refused")
            return MoveRelayResult(-1)
        }
        val result = try {
            httpClient.get(validatedInboxUrl(inboxId, "/peek"), headers = mapOf(READ_CAP_HEADER to readCap))
        } catch (e: Exception) {
            platformLogWarn(LOG_TAG, "move peek threw: ${e::class.simpleName}")
            return MoveRelayResult(-1)
        }
        if (!result.isSuccess || result.body == null) return MoveRelayResult(result.code)
        // Depth-1, stack-safe parse of a raw relay response — never a regex (the
        // Kotlin/Native rule every other relay-response parse in this file follows).
        // Guarded like the other relay-body parses; a refusal reads as "the
        // relay answered, depth unknown", which is what a missing field already meant.
        return MoveRelayResult(result.code, parseRelayJsonOrNull(result.body)?.get("pending")?.text?.toIntOrNull())
    }

    /**
     * `GET /inbox/{id}` on the transfer inbox — the DESTRUCTIVE drain, returning
     * the raw blobs with NO envelope parsing, NO decryption and NO counter/epoch
     * checks: a migration chunk is not a message envelope, it is sealed by
     * [MigrationSeal] and is opened one layer up.
     *
     * Bounded like every other relay array parse: at most [MoveConstants.MAX_CHUNKS]
     * blobs are decoded (the relay itself caps an inbox at 200), and a single
     * undecodable base64 entry is skipped rather than aborting the drain — a
     * missing chunk surfaces as an unseal failure, which is the honest outcome.
     */
    internal fun drainMoveInbox(inboxId: String, readCap: String): MoveRelayResult {
        if (!isValidInboxId(inboxId) || !capValidForHeader(readCap)) {
            platformLogWarn(LOG_TAG, "move drain: malformed inbox/cap — refused")
            return MoveRelayResult(-1)
        }
        val result = try {
            httpClient.get(validatedInboxUrl(inboxId), headers = mapOf(READ_CAP_HEADER to readCap))
        } catch (e: Exception) {
            platformLogWarn(LOG_TAG, "move drain threw: ${e::class.simpleName}")
            return MoveRelayResult(-1)
        }
        if (!result.isSuccess || result.body == null) return MoveRelayResult(result.code)
        val encoded = try {
            parseJsonStringArray(result.body, "blobs")
        } catch (_: Exception) {
            platformLogWarn(LOG_TAG, "move drain: malformed body")
            return MoveRelayResult(result.code)
        }
        if (encoded.size > MoveConstants.MAX_CHUNKS) {
            platformLogWarn(
                LOG_TAG,
                "move drain: ${encoded.size} blobs exceeds cap ${MoveConstants.MAX_CHUNKS} — processing the first ${MoveConstants.MAX_CHUNKS}",
            )
        }
        val blobs = encoded.take(MoveConstants.MAX_CHUNKS).mapNotNull {
            try {
                decodeBase64(it)
            } catch (_: Exception) {
                platformLogWarn(LOG_TAG, "move drain: skipping malformed base64 blob")
                null
            }
        }
        return MoveRelayResult(result.code, blobs = blobs)
    }

    /**
     * Rotates the READ (owner) capability of an inbox THIS device owns, addressed
     * by inbox id rather than by (contact, direction) — what the new phone's
     * post-import "Securing" step needs (docs/device-move.md D4), where the caller
     * holds imported inbox ROWS and not a contact walk.
     *
     * It deliberately delegates to the crash-safe [rotateReadCap] path rather
     * than issuing a bare `PUT /inbox/{id}/read-capability`: the durable
     * `cap-pend/…` marker + `/peek` reconcile is what guarantees the union
     * {record cap, pending marker} always contains whatever cap the relay holds.
     * A raw PUT whose response is lost would leave the relay holding a cap this
     * device never stored — the inbox unreachable, that contact needing a re-pair.
     * Rotating during a move must never be able to do that.
     *
     * Refuses (returns null, changes nothing) unless ALL of:
     *  - the id names a row in this vault whose direction is an OWNED read
     *    direction ([OWNED_READ_DIRECTIONS]) — never an outbound row, whose `cap`
     *    is the PEER's write cap;
     *  - [expectedReadCap] equals that row's stored cap, so a caller working from
     *    a stale snapshot cannot rotate with a cap the vault has since replaced;
     *  - the row is the OPERATIONAL one for its (contact, direction)
     *    ([selectOperationalInbox]); a superseded row (an older inbox the peer
     *    announced away from) is skipped, because the rotation commit only ever writes
     *    onto the operational row and would refuse the write anyway.
     *
     * Returns the newly committed read cap on a proven rotation, else null. Null
     * is never fatal to the caller: the pending-rotation retry re-tries it later.
     */
    internal fun rotateOwnedInboxReadCap(inboxId: String, expectedReadCap: String): String? {
        val rec = try {
            databaseManager.getInboxId(inboxId)
        } catch (e: Exception) {
            platformLogWarn(LOG_TAG, "move rotate: inbox read failed: ${e::class.simpleName}")
            null
        } ?: return null
        if (rec.direction !in OWNED_READ_DIRECTIONS) {
            platformLogWarn(LOG_TAG, "move rotate: ${rec.direction} is not an owned read direction — refused")
            return null
        }
        if (rec.cap.isNullOrEmpty() || rec.cap != expectedReadCap) {
            platformLogWarn(LOG_TAG, "move rotate: stored cap does not match the caller's — refused")
            return null
        }
        val operational = try {
            databaseManager.getInboxIdForContact(rec.contactId, rec.direction)
        } catch (_: Exception) { null }
        if (operational == null || operational.inboxId != rec.inboxId) {
            platformLogWarn(LOG_TAG, "move rotate: superseded inbox row — skipped")
            return null
        }
        val outcome = rotateReadCap(rec.contactId, rec.direction)
        if (outcome != CapRotationOutcome.ROTATED) {
            platformLogWarn(LOG_TAG, "move rotate: outcome=$outcome")
            return null
        }
        return try {
            databaseManager.getInboxId(inboxId)?.cap
        } catch (_: Exception) { null }
    }

    // -----------------------------------------------------------------------
    // Envelope helpers — the static envelope's app-layer anti-replay (counter +
    // epoch) riding on top of the capability transport
    // -----------------------------------------------------------------------

    // Thin wrappers kept for existing call sites/tests; the implementations
    // are top-level so GroupManager can build control bodies with the exact
    // same escaping rules.
    internal fun jsonEscape(s: String): String = jsonEscapeString(s)

    /** What a receive path surfaces for an envelope that passed all its checks. The
     *  defaults are [ReceivedMessage]'s own (control items carry no counter, no gap
     *  and no UI id). The text is display-capped here, once, for every path. */
    private fun Envelope.toReceived(counter: Long = 0, sequenceGap: Boolean = false, dedupeId: String = ""): ReceivedMessage =
        ReceivedMessage(
            text = capMessageForDisplay(text), timestamp = timestamp, counter = counter,
            sequenceGap = sequenceGap, groupId = groupId, membershipHash = membershipHash,
            controlKind = controlKind, controlBody = controlBody, dedupeId = dedupeId,
        )

    internal class Envelope(
        val epoch: String?,
        val counter: Long?,
        val timestamp: Long,
        val text: String,
        val groupId: String? = null,
        val membershipHash: String? = null,
        val controlKind: String? = null,
        val controlBody: String? = null,
        /** Channel-binding tag ("m"/"c"/"g"), null on legacy senders. */
        val channel: String? = null,
        /** The destination inbox id the sender POSTed to, sealed INSIDE
         *  the AEAD. On receive it must equal the inbox we polled, else the relay
         *  cross-spliced the blob between this pairing's inboxes (e.g. reflected our
         *  own outbound blob onto our inbound inbox). Null on legacy/pre-binding
         *  senders — enforcement is gated on [inboxBoundSeenKey], mirroring "ch". */
        val destInbox: String? = null,
        /** The peer's [CTL_RATCHET_CAP_FIELD] advert, verbatim (null = absent). */
        val ctlRatchetCap: String? = null,
        /** The peer's [CTL_RATCHET_WATERMARK_FIELD], verbatim (null = absent).
         *  Only ever HONOURED off a ratchet-decrypted envelope; see [parseCtlWatermark]. */
        val ctlRatchetWatermark: String? = null,
    )

    /**
     * Parses the JSON envelope `{"e":"<epoch>","c":<n>,"t":<ms>,"m":"<text>"}`
     * plus the optional group fields `"g"` (groupId), `"h"` (membership hash),
     * `"k"`/`"b"` (control kind + escaped-JSON-string body), and the bindings /
     * adverts `"ch"` (channel tag), `"di"` (destination inbox), `"cr"`/`"crw"`
     * (control-ratchet cap + watermark).
     * Returns null for anything that is not a brace-delimited envelope (a
     * legacy plaintext message) — the caller drops those (hard
     * policy). [Envelope.epoch]/[Envelope.counter] are null if the field is
     * absent (an old timestamp-only envelope), which the caller also drops.
     */
    internal fun parseEnvelope(raw: String): Envelope? {
        if (!raw.startsWith("{")) return null
        // Refuse an over-long body outright. This is BELT — the scanner
        // enforces the identical bound as its own first statement (and returns the
        // same empty map), and the `obj.isEmpty()` hard-drop below already turns
        // that into a null. It is kept explicit anyway so this hard-drop does not
        // depend on either of those two staying as they are: the empty-map branch
        // is exactly the one that used to mean "legacy plaintext blob, surface the
        // raw JSON as the bubble text". No legitimate envelope is affected —
        // padMessage refuses anything over MAX_PADDED_PAYLOAD_BYTES (131 068 B),
        // and a String's char count never exceeds its UTF-8 byte count, so the real
        // ceiling is 8x below this bound.
        if (raw.length > MAX_PARSE_OBJECT_CHARS) return null
        return try {
            // Depth-1 parse: only TOP-LEVEL keys are read. A sender (a malicious
            // paired peer crafts its own plaintext) therefore cannot smuggle a
            // "c"/"t"/"e" token inside a string value or nested object to be
            // mistaken for the real field — closes the positional-first
            // poisoning of the counter/timestamp.
            val obj = parseTopLevelJson(raw)
            // Second gate: raw starts with "{" (checked above) yet yielded
            // no keys — either malformed JSON or a body the scanner refused for
            // exceeding MAX_PARSE_OBJECT_KEYS. Neither is a message; falling
            // through would echo the raw JSON as the bubble text. Hard-drop.
            if (obj.isEmpty()) return null
            fun str(key: String) = obj[key]?.takeIf { it.isString }?.text
            fun long(key: String) = obj[key]?.takeIf { !it.isString }?.text?.toLongOrNull()
            val e = str("e")
            val c = long("c")
            val t = long("t") ?: 0L
            // A blob that parsed as a JSON envelope yet carries no "m" must NOT
            // have its whole JSON (inbox ids/caps, control/routing fields)
            // surfaced as a chat bubble — default to empty instead of echoing
            // raw. (The empty-map case is hard-dropped above.)
            val m = str("m") ?: ""
            Envelope(
                epoch = e, counter = c, timestamp = t, text = m,
                groupId = str("g"), membershipHash = str("h"),
                controlKind = str("k"), controlBody = str("b"),
                channel = str("ch"),
                destInbox = str("di"),
                ctlRatchetCap = str(CTL_RATCHET_CAP_FIELD),
                ctlRatchetWatermark = str(CTL_RATCHET_WATERMARK_FIELD),
            )
        } catch (_: Exception) {
            null
        }
    }

    internal fun jsonUnescape(s: String): String = jsonUnescapeString(s)

    /**
     * Short, deterministic tag identifying the current shared-secret epoch.
     * Both peers derive it from the same secret, so a re-pair (new secret)
     * yields a new epoch on both sides and the counter space resets cleanly
     * without the receiver false-rejecting fresh low counters. It lives
     * inside the GCM ciphertext, so it leaks nothing to the relay.
     */
    private fun messageEpoch(sharedSecret: ByteArray): String =
        bytesToHex(sha256(sharedSecret + "msg-epoch".encodeToByteArray()).copyOfRange(0, 6))

    companion object {
        // Relay reachability probe: fresh onion streams can miss rendezvous under
        // concurrent load, so try twice before reporting the relay unreachable.
        internal const val RELAY_HEALTH_ATTEMPTS    = 2

        /**
         * STEADY-STATE per-attempt transport budget for the health probe —
         * deliberately NOT the [DEFAULT_RELAY_HTTP_TIMEOUT_SECONDS] (60 s) that
         * message traffic uses.
         *
         * The probe is a cheap GET whose only job is "did a round-trip to the onion
         * complete?". Inheriting the 60 s message budget made a COLD Tor session
         * spend 2 × 60 s per cycle: Tor logs `Bootstrapped 100%` and publishes a
         * SOCKS port after building *a* circuit, but the hidden-service descriptor
         * fetch + rendezvous with the relay's onion has not happened yet, so the
         * first probes legitimately fail — and each one blocked the full minute.
         * The jittered 8–12 s cadence collapsed to one probe PAIR per ~2 minutes,
         * the 3-miss hysteresis could never clear, and the user sat on "Connecting
         * to the relay…" for many minutes while the app made almost no attempts.
         *
         * Each attempt opens a FRESH stream that Tor may attach to a different
         * circuit, so failing fast and re-probing is exactly how this recovers —
         * a short budget makes the loop rotate streams instead of blocking.
         *
         * Sibling of [WARM_PROBE_TIMEOUT_SECONDS] (12 s, the mint warm-gate's GET
         * against this same endpoint): same request, same
         * rationale. A touch shorter here because this probe REPEATS on an 8–12 s
         * loop, so one false miss costs a single hysteresis tick and self-corrects,
         * whereas the mint gate is a one-shot decision in front of a PoW grind.
         *
         * STEADY STATE ONLY — see [relayProbeTimeoutSeconds]. Applying this budget
         * from the very first probe overshot: a COLD Tor's first descriptor fetch +
         * rendezvous routinely needs longer than 10 s, and every attempt opens a
         * FRESH stream with no carry-over, so NO attempt could ever accumulate
         * enough time to finish the first rendezvous and the app could sit
         * unreachable indefinitely after a cold start. The cold budget is
         * [HEALTH_HTTP_TIMEOUT_SECONDS].
         */
        internal const val RELAY_HEALTH_TIMEOUT_SECONDS = 10

        /**
         * Transport budget for EVERY reachability GET issued while this transport
         * has never completed an onion round-trip ([hasCompletedRelayRoundTrip] ==
         * false) — a cold start, or a freshly (re)wired transport after a Tor
         * restart. THE REACHABILITY GET AND NOTHING ELSE: sends, polls, peeks and
         * cap rotations keep [DEFAULT_RELAY_HTTP_TIMEOUT_SECONDS] (60 s), the mint
         * handshake keeps [MINT_HTTP_TIMEOUT_SECONDS] (25 s), a cold send keeps
         * [SEND_COLD_TIMEOUT_SECONDS] (30 s).
         *
         * Tor reaches `Bootstrapped 100%` in ~7 s; the FIRST GET to the .onion then
         * still has to do the whole rendezvous (descriptor fetch, intro circuit,
         * rendezvous circuit). When one introduction point is dead that attempt
         * simply hangs, and the budget it was given IS the cost of discovering it:
         * at the inherited 60 s an App Store reviewer sat on "Connecting to
         * Relay… 95%" past the minute mark and rejected the build.
         *
         * Two opposing failure directions bracket this number:
         *  - too LONG and one dead introduction point owns the screen for its whole
         *    budget before anything rotates onto a fresh stream;
         *  - too SHORT and NO attempt can ever complete — each attempt opens a
         *    FRESH stream and carries no progress over, so a budget under the real
         *    cold-rendezvous cost (empirically > 10 s, commit b309a44) means a cold
         *    start never finishes at all.
         *
         * 20 s clears that floor with headroom, and is paired with the IMMEDIATE
         * retry ([relayHealthDelayMs]): a failed cold cycle no longer falls into the
         * 8–12 s steady-state sleep, so the cold schedule is attempt → attempt →
         * ~1–2 s → … i.e. ~3 fresh streams per minute instead of 2 per ~52 s.
         * Tor keeps whatever descriptor work an abandoned attempt completed, so the
         * attempts after the first usually resolve far inside the budget.
         *
         * Deliberately NO LONGER pinned to [SEND_COLD_TIMEOUT_SECONDS] (30 s) even
         * though both cover the same rendezvous: a cold SEND is a one-shot the user
         * is waiting on, bounded by [SEND_TRANSIENT_BUDGET_MS] (90 s) and worth only
         * three rotations, so it cannot afford to spend one on a budget that is too
         * tight. The probe is a LOOP that re-fires ~every 2 s until it succeeds, so
         * a single missed attempt costs it almost nothing. Never lower this below
         * [WARM_PROBE_TIMEOUT_SECONDS] — that is the floor below which a GET against
         * this endpoint is not worth making.
         */
        internal const val HEALTH_HTTP_TIMEOUT_SECONDS = 20

        /**
         * Per-attempt transport budget for [isRelayReachable]. Pure so it can be
         * unit-tested without a transport.
         *
         * @param roundTripCompleted [hasCompletedRelayRoundTrip] — has ANY relay
         *   request on this transport ever gotten a real HTTP response?
         */
        internal fun relayProbeTimeoutSeconds(roundTripCompleted: Boolean): Int =
            if (roundTripCompleted) RELAY_HEALTH_TIMEOUT_SECONDS else HEALTH_HTTP_TIMEOUT_SECONDS

        /**
         * Health-loop cadence, decided in commonMain by [relayHealthDelayMs] so both
         * platform loops (Android `RunViewModel.startRelayCheck`, iOS
         * `AppState.startRelayCheck`) schedule identically.
         *
         * STEADY STATE = the long-standing jittered 8–12 s heartbeat (a fixed
         * period would be a traffic-analysis beacon for the relay / guard node).
         *
         * COLD = until the FIRST completed round-trip on this transport, a failed
         * probe cycle is retried after only [RELAY_HEALTH_FAST_RETRY_BASE_MS] +
         * jitter (1–2 s) instead of sleeping the full heartbeat. The whole cold-start
         * cost is "how many fresh streams can we try", and an 8–12 s sleep between
         * cycles bought nothing: the probe already failed, Tor is not going to fix a
         * dead introduction point while we idle.
         *
         * [RELAY_HEALTH_FAST_RETRY_MAX] bounds the burst. A transport that fails
         * INSTANTLY (SOCKS refused, mock relay down in an emulator build) would
         * otherwise spin this loop at ~1 request/s forever, flooding the 2000-entry
         * LogBuffer that the diagnostics live in and burning battery for nothing. 12
         * cycles is ≥ 4 minutes of fast retrying when the attempts actually cost
         * their budget (the real cold-start case, which succeeds in the first few),
         * and ~18 s of burst in the instant-failure case before falling back to the
         * 8–12 s heartbeat — which still recovers, just at the old pace. A genuine
         * (re)connect mints a NEW MessageManager on both platforms, so the window
         * re-arms exactly when "after a (re)connect" says it should.
         */
        internal const val RELAY_HEALTH_BASE_MS = 8_000L
        internal const val RELAY_HEALTH_JITTER_MS = 4_000
        internal const val RELAY_HEALTH_FAST_RETRY_BASE_MS = 1_000L
        internal const val RELAY_HEALTH_FAST_RETRY_JITTER_MS = 1_000
        internal const val RELAY_HEALTH_FAST_RETRY_MAX = 12

        /** @see RELAY_HEALTH_FAST_RETRY_MAX. Pure: unit-tested without a transport. */
        internal fun useFastRelayHealthRetry(roundTripCompleted: Boolean, fastRetriesUsed: Int): Boolean =
            !roundTripCompleted && fastRetriesUsed < RELAY_HEALTH_FAST_RETRY_MAX

        /** Pure half of [relayHealthDelayMs]; [jitterRoll] is the drawn jitter (ms). */
        internal fun relayHealthDelayMsFor(fast: Boolean, jitterRoll: Int): Long =
            if (fast) RELAY_HEALTH_FAST_RETRY_BASE_MS + jitterRoll
            else RELAY_HEALTH_BASE_MS + jitterRoll

        // -------------------------------------------------------------------
        // COLD-TRANSPORT NEWNYM RUNG. Decided HERE so both platform ladders decide identically:
        // Android RunViewModel.maybeFireEarlyNewnym, iOS AppState.maybeFireEarlyNewnym
        // (through IosAppController.earlyNewnymDue).
        //
        // THE PHASE THIS TARGETS — INTRODUCTION, not bootstrap and not circuit
        // build. The measured signature of the remaining tail is: HS descriptor
        // received in ~5 s, intro (or rendezvous) circuit built in 5–15 s, then
        // an introduction point that never completes. Recovery came either when
        // Tor abandoned that intro point ITSELF, 60–75 s later, or from a
        // `SIGNAL NEWNYM` — which purges the client's HS state (descriptor,
        // intro/rendezvous circuits) and completed in < 5 s where it was
        // observed. Everything in between is 20 s probes burning fresh STREAMS
        // against the same wedged circuit: rotating a stream rotates neither the
        // circuit nor the descriptor, which is why the probe loop alone cannot
        // recover this class.
        //
        // NEWNYM leaves the entry guards alone (never touch guards) and is
        // stock Tor "New Identity" — no new vocabulary, no new wire text; the
        // existing ConnectionLog.Code.NEWNYM covers it.
        // -------------------------------------------------------------------

        /**
         * Consecutive FULL-BUDGET probe timeouts required before the cold rung
         * may fire. Two, because a cold cycle is [RELAY_HEALTH_ATTEMPTS] = 2
         * attempts, and one lone timeout is also what a slow-but-alive
         * rendezvous looks like — the second one is the evidence that the
         * attempts are not making progress on a FRESH stream each time.
         *
         * Only a timeout that consumed (almost) its whole budget counts (see
         * [isFullBudgetProbeTimeout]). A probe that fails FAST is a broken
         * transport (SOCKS refused, no route), which NEWNYM cannot fix, so it
         * breaks the run instead of advancing it.
         */
        internal const val EARLY_NEWNYM_MIN_TIMEOUTS = 2

        /**
         * Earliest the cold rung may fire, in ms from the CONNECT ANCHOR (the
         * post-unlock anchor `secs` is measured from — Android
         * `RunViewModel.connectStartElapsedMs`, iOS `AppState.connectStartUptime`).
         *
         * Why 35 s and not sooner: the descriptor lands in ~5 s and a healthy
         * intro+rendezvous completes within ~30 s of it, so before ~35 s a
         * NEWNYM would throw away work that was about to succeed and would
         * re-pay the descriptor fetch for nothing. Why not later: past ~45 s the
         * intro point is wedged and the only two outcomes left are Tor's own
         * 60–75 s abandon or this rung — waiting longer just hands the user the
         * expensive path. Paired with [EARLY_NEWNYM_MIN_TIMEOUTS], the first
         * fire lands at ~40 s (two 20 s cold attempts).
         */
        internal const val EARLY_NEWNYM_FIRST_MS = 35_000L

        /**
         * Earliest the SECOND (and last) cold-rung fire may happen, same anchor.
         * ~80 s leaves the first NEWNYM a full cold cycle plus change (2 × 20 s
         * attempts + the 1–2 s fast retry) to prove itself before another one is
         * spent, and still lands well before the heavy rungs — Android's
         * `RELAY_SELF_HEAL_RESTART_MS` (100 s) Tor restart, iOS's stalled UI.
         */
        internal const val EARLY_NEWNYM_SECOND_MS = 80_000L

        /**
         * Hard cap of NEWNYMs per SESSION (not per transport), counted across the
         * cold rung and the warm-up rotation together: two.
         * More would be introduction-point hammering — each NEWNYM makes the
         * client re-fetch the descriptor and re-introduce, and a service that is
         * genuinely unreachable does not become reachable by being asked faster.
         * Two fires cover "this intro point is dead" and "so was the next one";
         * after that the existing heavier rungs own the problem.
         *
         * PUBLIC (unlike its siblings) because both platform ladders render it
         * in the shared connection-log phrase `(NEWNYM n/max)`, and androidApp is
         * a different Gradle module that cannot see `internal`.
         */
        const val EARLY_NEWNYM_MAX_FIRES = 2

        /**
         * Slack allowed when classifying a failed probe as a FULL-BUDGET
         * timeout: the transport returns a few ms before the deadline it was
         * given. Same 250 ms the PROBE_TIMEOUT connection-log line has always
         * used — this only names it.
         */
        internal const val PROBE_TIMEOUT_SLACK_MS = 250L

        /**
         * Did a failed probe consume (almost) its whole budget? Pure so the
         * PROBE_TIMEOUT classification — which is what feeds the cold rung's
         * counter — is unit-testable without a clock.
         */
        internal fun isFullBudgetProbeTimeout(elapsedMs: Long, timeoutSeconds: Int): Boolean =
            elapsedMs >= timeoutSeconds * 1_000L - PROBE_TIMEOUT_SLACK_MS

        /**
         * THE cold-transport NEWNYM decision, shared by both platforms.
         *
         * @param coldTransport `!hasCompletedRelayRoundTrip()` — true only while
         *   NO relay round trip has completed this session. Once the relay has
         *   answered once, this rung is done forever: a later stall belongs to
         *   the budgeted WARM rung ([shouldFireWarmNewnym], its exact complement)
         *   and the heavier ladders behind it.
         * @param consecutiveFullBudgetTimeouts see [EARLY_NEWNYM_MIN_TIMEOUTS].
         * @param msSinceConnectAnchor ms since the connect anchor. The rung NEVER
         *   moves that anchor: `secs` must keep measuring launch → first answer,
         *   so a self-heal inside the wait stays inside the number it improves.
         * @param newnymsFiredThisSession the SHARED per-session NEWNYM count
         *   (this rung + the warm-up rotation) — what the CAP
         *   [EARLY_NEWNYM_MAX_FIRES] is checked against.
         * @param coldRungFiresThisSession how many times THIS (cold) rung itself
         *   has fired this session — what picks the FLOOR (35 s for its first
         *   fire, 80 s for its second). Separate from the cap since 2026-10-09:
         *   a warm-up rotation used to count as "the first fire", so the cold
         *   rung's only remaining fire waited for the 80 s floor and the session
         *   had no NEWNYM rung between the warm-up's ~25 s and 80 s (device
         *   runs on 2026-10-08: Android cycle 5, A20e cycle 4). The warm-up NEWNYM
         *   still resets the evidence run ([noteEarlyNewnymFired]), so the cold
         *   fire after it still needs two FRESH full-budget timeouts. Defaults to
         *   [newnymsFiredThisSession] (the old single-counter behaviour).
         */
        internal fun shouldFireEarlyNewnym(
            coldTransport: Boolean,
            consecutiveFullBudgetTimeouts: Int,
            msSinceConnectAnchor: Long,
            newnymsFiredThisSession: Int,
            coldRungFiresThisSession: Int = newnymsFiredThisSession,
        ): Boolean {
            if (!coldTransport) return false
            if (newnymsFiredThisSession < 0 || newnymsFiredThisSession >= EARLY_NEWNYM_MAX_FIRES) return false
            // A corrupt cold-rung counter fails CLOSED like the shared one.
            if (coldRungFiresThisSession < 0 || coldRungFiresThisSession > newnymsFiredThisSession) return false
            if (consecutiveFullBudgetTimeouts < EARLY_NEWNYM_MIN_TIMEOUTS) return false
            // A negative elapsed cannot happen on either platform's monotonic
            // clock; fail CLOSED if one ever appears.
            val floorMs = if (coldRungFiresThisSession == 0) EARLY_NEWNYM_FIRST_MS else EARLY_NEWNYM_SECOND_MS
            return msSinceConnectAnchor >= floorMs
        }

        /**
         * THE WARM-UP ROTATION GATE, shared by both platforms (Android
         * `RunViewModel.fireWarmupNewnym`, iOS `AppState.rotateAndRetryWarmup`
         * via `IosAppController.warmupNewnymAllowed`). Asked only AFTER
         * [RelayWarmup.shouldRotateAndRetry] said the warm-up burned its whole
         * budget; this decides whether the session may still spend a NEWNYM on it.
         *
         * LOCK STATE IS DELIBERATELY NOT AN INPUT (2026-10-06). The gate used to be
         * "still locked", which on iOS (unlock at ~t5) meant the rotation almost
         * never ran: the stuck warm-up and the session's stuck first probe sit on
         * the SAME wedged HS circuits, so refusing at unlock only handed the rescue
         * to [shouldFireEarlyNewnym] at ~t45–50 (2 × 20 s probe timeouts + the
         * 35 s floor). Prod iOS: in 20 of 27 rescues the relay answered ≤ 5 s
         * after the NEWNYM. What actually makes a rotation churn is a session that
         * has ALREADY reached the relay — so that is the gate:
         *
         * @param transportRoundTripCompleted the current transport's
         *   [hasCompletedRelayRoundTrip] (probe, mint warm-gate, peek / batch-peek
         *   prime all latch it); false when no transport exists yet (pre-unlock).
         * @param relayAnsweredThisSession the platform's set-once session latch:
         *   the relay has answered at least once this session (reachable state or
         *   handshake ever seen), surviving a transport re-wire that would reset
         *   the per-transport latch above.
         * @param newnymsFiredThisSession the SAME per-session counter
         *   [shouldFireEarlyNewnym] reads (`earlyNewnymsFired` on both platforms),
         *   so the warm-up rotation and the cold rung together never exceed
         *   [EARLY_NEWNYM_MAX_FIRES].
         *
         * Pure; unit-tested in WarmupNewnymGateTest.
         */
        fun shouldFireWarmupNewnym(
            transportRoundTripCompleted: Boolean,
            relayAnsweredThisSession: Boolean,
            newnymsFiredThisSession: Int,
        ): Boolean {
            if (transportRoundTripCompleted || relayAnsweredThisSession) return false
            return newnymsFiredThisSession in 0 until EARLY_NEWNYM_MAX_FIRES
        }

        // -------------------------------------------------------------------
        // WARM-TRANSPORT NEWNYM RUNG (2026-10-07). Decided HERE so both platform
        // ladders decide identically: Android RunViewModel.maybeFireWarmNewnym,
        // iOS AppState.maybeFireWarmNewnym (through IosAppController.warmNewnymDue).
        //
        // THE GAP IT CLOSES. The cold rung above retires for good at the first
        // relay answer, so a session that HAD answered and then went dark (the
        // onion half wedged mid-session: the probes time out at their full
        // budget, Tor itself stays at 100 %) had only the heavy ladders left,
        // and both are slow by construction on a WARM transport:
        //  - Android: 3 counted misses flip `isRelayReachable` (one per warm
        //    cycle = 2 × 10 s attempts + the 8–12 s heartbeat ≈ 30 s, so the
        //    flip lands ~60–90 s into the outage), and only THEN does
        //    startRelayStallWatch wait RELAY_SELF_HEAL_RESTART_MS (100 s) before
        //    its first NEWNYM — measured 2026-10-07 on an A13: first probe
        //    timeout 14:38:5x, first NEWNYM 14:41:16 (~140 s);
        //  - iOS: the sustained rung needs 64 s of COUNTED misses measured from
        //    the first counted miss (the end of the first failed cycle), so it
        //    fires at a counted miss ~90 s after it on the 30 s warm cadence —
        //    ~110 s into the outage.
        // Real users sit on a dark contact list / disabled relay rows for that
        // whole span. The phase is the same one the cold rung targets: the HS
        // client state (descriptor / introduction / rendezvous circuits) is
        // wedged and rotating STREAMS rotates none of it; `SIGNAL NEWNYM` purges
        // it. The evidence is the same too — consecutive FULL-BUDGET probe
        // timeouts ([isFullBudgetProbeTimeout]); a fast failure is a broken
        // transport NEWNYM cannot fix and breaks the run.
        //
        // ANONYMITY COST (why it is budgeted at all). NEWNYM never touches the
        // entry guards — the guard set, and so the first hop every
        // circuit uses, is unchanged. What each fire DOES cost: the client
        // re-fetches the relay's descriptor (one more HSDir sees a fetch for the
        // service's blinded key in that time period), builds fresh introduction
        // and rendezvous circuits (more middle relays and one more introduction
        // point see a client of this service), and its guard sees a burst of
        // circuit builds. Each is a small, ordinary Tor client behaviour; the
        // risk is in REPETITION — a client that rotates every 40 s for hours is
        // a distinctive, linkable pattern and hammers introduction points. Hence
        // two caps: per dark run (a stall), and per rolling hour (so a long
        // session with repeated outages stays at a handful). Past them the
        // heavier ladders — Android's NEWNYM-then-restart stall watch, iOS's
        // sustained rung / `.stalled` + manual Reconnect — remain the backstop,
        // unchanged.
        //
        // Same wire vocabulary: ConnectionLog.Code.NEWNYM, phrase
        // `(NEWNYM n/max, warm)` (identical on both platforms).
        // -------------------------------------------------------------------

        /**
         * Consecutive full-budget probe timeouts before the FIRST warm fire of a
         * dark run. Three, because a warm cycle is [RELAY_HEALTH_ATTEMPTS] = 2
         * attempts: two timeouts are one failed cycle — which is also what a
         * single slow rendezvous re-establishment looks like — the third is a
         * fresh stream in a NEW cycle still timing out.
         */
        internal const val WARM_NEWNYM_MIN_TIMEOUTS = 3

        /**
         * And the dark run must span at least this long, measured from the START
         * of its first timed-out attempt. On the background heartbeat three
         * timeouts already span ≥ 38 s (2 × 10 s + 8 s sleep + 10 s); the floor
         * matters for iOS's conversation loops, which re-probe back to back —
         * three 10 s timeouts then span ~30 s, minus the transport's own return
         * slack ([PROBE_TIMEOUT_SLACK_MS] per attempt), hence 28 s and not 30.
         */
        internal const val WARM_NEWNYM_MIN_DARK_MS = 28_000L

        /** FRESH full-budget timeouts (the run is cleared at every fire) needed
         *  before a REPEAT fire: one whole cycle after the NEWNYM that failed on
         *  both attempts. */
        internal const val WARM_NEWNYM_REPEAT_MIN_TIMEOUTS = 2

        /** Earliest repeat fire, ms after the previous warm fire of the same
         *  dark run. A NEWNYM that helps recovers in < 5 s where it was observed;
         *  40 s is a full warm cycle plus change for it to prove itself. */
        const val WARM_NEWNYM_REPEAT_MS = 40_000L

        /** Warm fires per dark run (a run ends at the next probe that answers).
         *  Two cover "this introduction point is wedged" and "so was the next";
         *  public because both platforms render it in `(NEWNYM n/max, warm)`. */
        const val WARM_NEWNYM_MAX_PER_RUN = 2

        /** Warm fires per rolling [WARM_NEWNYM_WINDOW_MS] across ALL dark runs —
         *  the long-session budget (see ANONYMITY COST above): three full dark
         *  runs an hour, then only the heavy ladders until the window slides. */
        const val WARM_NEWNYM_MAX_PER_WINDOW = 6
        const val WARM_NEWNYM_WINDOW_MS = 3_600_000L

        /**
         * THE warm-transport NEWNYM decision, shared by both platforms.
         *
         * @param warmTransport [hasCompletedRelayRoundTrip] — the exact
         *   complement of [shouldFireEarlyNewnym]'s `coldTransport`, so the two
         *   rungs partition every transport and never both apply. A transport
         *   re-wired by a Tor restart starts cold again and belongs to the cold
         *   rung (and the heavy ladders).
         * @param consecutiveFullBudgetTimeouts the current run (cleared by a fire).
         * @param darkForMs ms since the start of the dark run's first timed-out
         *   attempt (monotonic). Negative fails closed.
         * @param msSinceLastFireThisRun ms since this run's previous warm fire;
         *   ignored for the first fire. Negative fails closed.
         * @param firesThisRun / [firesInWindow] the two budgets; a negative
         *   (corrupt) counter fails closed, like the other NEWNYM gates.
         *
         * Pure; unit-tested in WarmNewnymRungTest.
         */
        internal fun shouldFireWarmNewnym(
            warmTransport: Boolean,
            consecutiveFullBudgetTimeouts: Int,
            darkForMs: Long,
            msSinceLastFireThisRun: Long,
            firesThisRun: Int,
            firesInWindow: Int,
        ): Boolean {
            if (!warmTransport) return false
            if (firesThisRun !in 0 until WARM_NEWNYM_MAX_PER_RUN) return false
            if (firesInWindow !in 0 until WARM_NEWNYM_MAX_PER_WINDOW) return false
            return if (firesThisRun == 0) {
                consecutiveFullBudgetTimeouts >= WARM_NEWNYM_MIN_TIMEOUTS &&
                    darkForMs >= WARM_NEWNYM_MIN_DARK_MS
            } else {
                consecutiveFullBudgetTimeouts >= WARM_NEWNYM_REPEAT_MIN_TIMEOUTS &&
                    msSinceLastFireThisRun >= WARM_NEWNYM_REPEAT_MS
            }
        }

        /** Process-wide monotonic origin for the warm rung's clock — one origin
         *  for every transport, so a [WarmNewnymLedger] that outlives a
         *  MessageManager keeps comparable timestamps. */
        private val WARM_RUNG_CLOCK_ORIGIN = TimeSource.Monotonic.markNow()

        internal fun warmRungNowMs(): Long = WARM_RUNG_CLOCK_ORIGIN.elapsedNow().inWholeMilliseconds

        // DESCRIPTOR-FETCH re-requests: since 2026-10-12 the earlier bounded
        // HSDir hedge in DescriptorHedge.kt (1 s bare HSFETCH, ≤ 2 in flight,
        // one never-replenished budget per session) replaces the 4 s watchdog
        // and its per-NEWNYM DescriptorRefetchLedger that lived here.

        // -------------------------------------------------------------------
        // NEWNYM ABORTS THE IN-FLIGHT PROBE (2026-10-08). After an app-fired
        // `SIGNAL NEWNYM`, a request already in flight rides a circuit Tor just
        // retired: field connect 1 (prod 2026-10-08) lost 17 s with the health
        // probe sitting out its 20 s budget while the warm-up's GET on the fresh
        // circuits answered 2.5 s after the NEWNYM. [noteNewCircuitRequested]
        // aborts the opted-in requests (probe `GET /`, batch `POST /peek`) and the
        // probe re-runs the attempt AT ONCE; the aborted attempt is booked as
        // neither a timeout nor a success, so it moves no NEWNYM rung.
        // -------------------------------------------------------------------

        /**
         * Immediate re-probes one [isRelayReachable] call may spend on attempts a
         * NEWNYM abandoned, on top of the [RELAY_HEALTH_ATTEMPTS] it normally
         * makes. Two: NEWNYMs are spaced by tens of seconds on every rung, so a
         * third abandon inside one call means something other than a NEWNYM is
         * bumping the epoch — the attempt is then consumed (still unbooked).
         */
        internal const val PROBE_NEWNYM_REPROBE_MAX = 2

        /** The panel line of a probe attempt abandoned by a NEWNYM or by a relay
         *  address switch ([noteRelayAddressSwitched]) — fixed text + numbers,
         *  uncoded (never part of the connect telemetry). */
        internal fun abandonedProbePhrase(probeNo: Int, elapsedMs: Long, addressSwitched: Boolean): String =
            if (addressSwitched) "probe #$probeNo: abandoned for a faster relay address in ${formatSeconds(elapsedMs)} s - re-probing"
            else "probe #$probeNo: abandoned after NEWNYM in ${formatSeconds(elapsedMs)} s - re-probing"

        /**
         * Pure classification of one probe attempt — the seam that keeps an
         * abandoned attempt out of the NEWNYM rungs' evidence.
         *
         * @param answered the relay produced an HTTP status (`code > 0`). An answer
         *   wins even across a NEWNYM: the relay was reached.
         * @param newnymDuringAttempt an app-fired NEWNYM was accepted after this
         *   attempt started ([noteNewCircuitRequested] bumped the epoch). Then the
         *   failure — fast (the transport aborted the stream) or full-budget (it
         *   could not, and the stale result arrived late) — is the NEWNYM's doing,
         *   not evidence about the circuits the next attempt will use.
         */
        internal fun classifyProbeAttempt(
            answered: Boolean,
            newnymDuringAttempt: Boolean,
            elapsedMs: Long,
            timeoutSeconds: Int,
            firstByteTimedOut: Boolean = false,
        ): ProbeAttemptOutcome = when {
            answered -> ProbeAttemptOutcome.ANSWERED
            newnymDuringAttempt -> ProbeAttemptOutcome.ABANDONED_BY_NEWNYM
            isFullBudgetProbeTimeout(elapsedMs, timeoutSeconds) -> ProbeAttemptOutcome.TIMEOUT
            // A connected stream that never produced a byte is the SAME wedge
            // a full-budget timeout proves — it just stopped waiting earlier.
            firstByteTimedOut -> ProbeAttemptOutcome.TIMEOUT
            else -> ProbeAttemptOutcome.FAILED_FAST
        }

        /**
         * FIRST-BYTE BUDGET (2026-10-09) for the COLD health probe only: once its
         * stream has connected through Tor, the relay's answer starts within ~1 s on
         * a healthy circuit (0.7–1.3 s measured on prod). Device-run iOS cycle 8: probe
         * #1's stream connected in 0.35 s and then sat out the whole 20 s budget.
         * Abandoning it at 8 s and booking it as a full-budget timeout (it is the
         * same evidence) feeds the cold NEWNYM rung 12 s sooner per attempt. The
         * overall [HEALTH_HTTP_TIMEOUT_SECONDS] budget is unchanged — it still
         * bounds the descriptor/intro/rendezvous phases BEFORE the stream connects.
         * Never applied once the transport has answered (the warm budget is 10 s).
         */
        internal const val PROBE_FIRST_BYTE_TIMEOUT_SECONDS = 8

        /** The first-byte budget the probe passes: [PROBE_FIRST_BYTE_TIMEOUT_SECONDS]
         *  while cold, none once the transport has answered. */
        internal fun probeFirstByteTimeoutSeconds(roundTripCompleted: Boolean): Int =
            if (roundTripCompleted) 0 else PROBE_FIRST_BYTE_TIMEOUT_SECONDS

        /**
         * Per-ATTEMPT transport budget for a message-send POST while this transport
         * has never completed an onion round-trip ([hasCompletedRelayRoundTrip] ==
         * false) — a cold start, or a freshly (re)wired transport after a Tor
         * restart. Once the latch flips, sends go back to the full
         * [DEFAULT_RELAY_HTTP_TIMEOUT_SECONDS] (60 s).
         *
         * Why shorter helps rather than hurts: every attempt opens a FRESH Tor
         * stream that may be attached to a DIFFERENT circuit, and the whole retry
         * loop is bounded by [SEND_TRANSIENT_BUDGET_MS] (90 s) checked BETWEEN
         * attempts. At 60 s a cold send got two attempts inside that budget and
         * spent ~120 s doing it; at 30 s it gets three, inside 90 s — the loop
         * ROTATES streams instead of blocking on one dead circuit, which is exactly
         * how a cold send recovers. Retries are replay-safe (the same counter bytes
         * are re-POSTed and the receiver's strict-monotonic check drops the
         * duplicate), so more attempts cost nothing but time.
         *
         * 30 s, NEVER LOWER: commit b309a44 is the empirical floor — a COLD Tor's
         * first hidden-service descriptor fetch + rendezvous routinely needs longer
         * than 10 s, and since no attempt carries progress over to the next, a
         * budget under that ceiling means NO attempt can ever finish the first
         * rendezvous and the operation fails indefinitely. Same two-regime shape
         * as the health probe's [HEALTH_HTTP_TIMEOUT_SECONDS], but deliberately a
         * LARGER number: this send is a ONE-SHOT the user is waiting on and gets
         * exactly three rotations inside [SEND_TRANSIENT_BUDGET_MS], whereas the
         * probe is a loop that re-fires every ~2 s and can spend a miss cheaply.
         */
        internal const val SEND_COLD_TIMEOUT_SECONDS = 30

        /**
         * Granularity of the mint's abort-aware backoff ([sleepAbortable]): the
         * longest a signalled abort can go unnoticed inside a blocking sleep.
         */
        internal const val ABORT_SLEEP_CHUNK_MS = 1000L
        private const val CONTENT_TYPE             = "application/octet-stream"
        /** The BATCH `/peek` route is the one relay call whose body is JSON, not a blob. */
        private const val BATCH_PEEK_CONTENT_TYPE  = "application/json"
        private const val READ_CAP_HEADER          = "X-Read-Capability"
        private const val WRITE_CAP_HEADER         = "X-Write-Capability"
        private const val NEW_READ_CAP_HEADER      = "X-New-Read-Capability"
        private const val NEW_WRITE_CAP_HEADER     = "X-New-Write-Capability"
        private const val POW_TOKEN_HEADER         = "X-PoW-Token"
        private const val POW_COUNTER_HEADER       = "X-PoW-Counter"
        // Opt-in push suppression (docs/RELAY_SPEC.md, `X-No-Push`): sender's choice
        // to suppress the relay's contentless wake-push for this one append. Absent =
        // the relay pushes iff the destination inbox has a registered token. Never
        // carries content — only ever "1" or omitted.
        private const val NO_PUSH_HEADER           = "X-No-Push"

        /**
         * Bounded solve→submit cycles per mint. The relay can reject a freshly
         * solved counter (challenge expired / spent / clock skew) with another
         * 400-challenge; we re-solve the fresh challenge a few times, then give
         * up rather than loop forever (a hostile relay could otherwise spin us
         * indefinitely). The initial challenge fetch is not counted here.
         */
        private const val MAX_MINT_SOLVE_ATTEMPTS  = 3

        /**
         * Items the relay accepts in ONE `POST /peek` body. The relay refuses a
         * longer list outright, so [peekInboxesBatch] CHUNKS at this number rather
         * than truncating — a device with more than 64 peekable inboxes still gets
         * an answer for every one of them, in ⌈N/64⌉ round trips instead of N.
         */
        internal const val BATCH_PEEK_MAX_ITEMS = 64

        /**
         * The statuses that mean "stop asking this relay for the batch route", as
         * opposed to "the batch failed". An OLD relay has no `/peek` route at all
         * and answers its default 404 (or 405 for a POST to a GET-only path) —
         * that is the fallback signal. 400 is what a CURRENT relay answers to a
         * body it refuses (malformed JSON, `v` not the number 1, empty/non-array
         * items, a wrong `Content-Type`), i.e. a client-side defect: latching is
         * the fail-safe direction there too, because re-sending a body this relay
         * has already refused cannot start working. 415/501 are the same class of
         * answer from an intermediary. All of them latch [batchPeekUnsupported]
         * and send the caller back to the per-inbox peeks — so an old relay costs
         * exactly ONE wasted round trip per transport, never one per prime.
         *
         * Deliberately NOT here: **429** (rate-limited — "not now", not "no such
         * route") and **413** (over 64 items or over the relay's 16 KiB body
         * ceiling — a chunking bug on our side, and the very next pass may have
         * fewer inboxes). Both are plain failures that fall back for this pass
         * only.
         */
        private val BATCH_PEEK_UNSUPPORTED_CODES = setOf(400, 404, 405, 415, 501)

        /** Double Ratchet text-channel name (per-contact ratchet state is keyed by it). */
        internal const val RATCHET_TEXT_CHANNEL = "text"
        /** Self-describing wire tag: ratchet blobs begin with these 4 bytes so the
         *  receiver routes each blob to the ratchet or the legacy decoder by its
         *  CONTENT, never by its own (possibly out-of-sync) enablement flag. A
         *  legacy blob starts with a random 12-byte IV, so a false match is 2^-32. */
        internal val RATCHET_WIRE_MAGIC = byteArrayOf('R'.code.toByte(), 'A'.code.toByte(), 'T'.code.toByte(), '1'.code.toByte())

        // `_meta` markers. dr-intent: paired under this build (ratchet-capable).
        // dr-rxseen: we've received ≥1 message from the peer (both sides paired).
        // dr-on: SEND ratchet — flips only when intent + both inboxes + rxseen,
        // so the first exchange stays legacy (the unavoidable bootstrap cost) and
        // the two devices converge without a mid-pairing format split.
        internal fun drOnKey(contactId: String) = "dr-on/$contactId"
        internal fun drIntentKey(contactId: String) = "dr-intent/$contactId"
        internal fun drRxSeenKey(contactId: String) = "dr-rxseen/$contactId"
        // RETIRED (2026-11-06): a persisted lifetime count of ratchet messages received
        // from this contact, used only to mint UI dedupe ids. An opened vault image read
        // it as exact per-contact message volume since pairing. Ids now come from the
        // process-wide RAM [RatchetReceiveIds]; nothing writes this key, a legacy value
        // is deleted on the contact's next ratchet text drain, and it stays in
        // [ratchetMetaKeysForContact] so a delete still purges a never-drained one.
        internal fun drRxCounterKey(contactId: String) = "dr-rxc/$contactId"
        // Set once we've seen a channel-tagged ("ch") blob from a peer. From
        // then on we REQUIRE the tag (a null-channel blob is a relay downgrade /
        // cross-splice / pre-tag replay), closing the residual splice window for
        // tag-capable peers while staying lenient toward genuinely-legacy peers.
        internal fun channelTagSeenKey(contactId: String) = "m2-chseen/$contactId"
        // Set once we've seen a destination-inbox-bound ("di") blob from a
        // peer that MATCHED the inbox we polled. From then on we REQUIRE the binding — a
        // di-less blob (or one bearing a di for a DIFFERENT inbox) is a relay cross-inbox
        // reflection/splice (the victim's own outbound blob served back on its inbound
        // inbox), which the separate inbound/outbound counter baselines would otherwise
        // let pass. Distinguishes DIRECTION within a channel, which "ch" cannot. Mirrors
        // m2ChSeen: a genuinely legacy peer never binds, so it never sets the marker and
        // stays accepted.
        internal fun inboxBoundSeenKey(contactId: String) = "ib-bound-seen/$contactId"
        // Set once the peer's ratchet is proven past
        // the BOOTSTRAP window (>= 2 receiving DH steps). From then on we DROP
        // non-magic (legacy static-key) text blobs, restoring downgrade-injection
        // resistance on receive against a sharedSecret thief who lacks the ability
        // to produce genuine ratchet traffic.
        //
        // HONEST SCOPE of this gate: the `>= 2` gate only RAISES THE COST of arming
        // it — it does NOT make arming unforgeable. There is no passive receive-side
        // gate that can, because every receiving DH is computable from observed
        // public keys + sharedSecret. Sticky, mirroring m2-chseen. Do NOT re-describe
        // this as "unforgeable" — it is best-effort downgrade protection.
        internal fun drRecvLockKey(contactId: String) = "dr-rxlock/$contactId"

        /**
         * Count of CONSECUTIVE legacy (static-envelope) sends
         * made while this contact is `dr-on` but the ratchet had no sending chain —
         * i.e. the responder-bootstrap fallthrough in [sendEnvelopeSerialized]. Reset
         * (deleted) by the first ratchet send that actually lands.
         *
         * WHY IT EXISTS. That fallthrough is silent and was uncapped: a relay that
         * drops the initiator's ratchet blobs (they are self-identifying — a constant
         * 4-byte magic — and the responder role is computable from the two inbox ids)
         * pins the responder's whole outbound direction on the NO-forward-secrecy
         * static key, archives it, and decrypts it later from one vault open. The
         * receive-side dr-rxlock cannot help: arming it needs the very ratchet traffic
         * being dropped. So the fallthrough is now COUNTED and readable
         * ([MessageManager.forwardSecrecyStalled]) rather than invisible.
         *
         * SIGNAL UNTIL THE THRESHOLD, THEN A GATE (2026-09-16). It was originally
         * a pure signal because "refusing to send would hand that same relay a way
         * to silence the conversation". That reasoning holds for a TRANSIENT drop and
         * not for the state this counter reaches at
         * [RATCHET_FALLBACK_STALL_THRESHOLD]: a peer-forced both-Bob role collision is
         * permanent and self-reinforcing (neither side can ever produce a ratchet blob,
         * so there is no recovery to wait for), and every send meanwhile is
         * plaintext-equivalent traffic the user believes is ratcheted. Crossing the
         * threshold therefore arms [drRefusedKey] as well — a bounded, loud, fully
         * recoverable refusal (one inbound ratchet blob or a re-pair clears it) in
         * exchange for availability under a hostile relay, which could already
         * blackhole the inbox outright.
         *
         * Holds no key material, but it is per-contact, so it is in
         * [ratchetMetaKeysForContact].
         */
        internal fun drLegacyFallbackKey(contactId: String) = "dr-legacyfb/$contactId"

        /**
         * Consecutive legacy fallbacks past which forward secrecy is treated as
         * STALLED for a contact ([MessageManager.forwardSecrecyStalled]) and a warning
         * is logged once. A healthy responder falls back a handful of times at most —
         * only until its first ratchet receive — so 8 is well clear of the normal
         * bootstrap while still catching a sustained downgrade quickly.
         */
        internal const val RATCHET_FALLBACK_STALL_THRESHOLD = 8

        /** Ceiling for the stored fallback count, so a long stall can't grow the value
         *  without bound (everything above the threshold means the same thing). */
        private const val RATCHET_FALLBACK_COUNT_CAP = 9999

        /**
         * Count of CONSECUTIVE inbound TEXT drains that carried at least one blob and
         * produced NO successfully-decrypted ratchet blob, while this device had
         * already sent [RATCHET_SENDS_BEFORE_UNACKED_EVIDENCE] ratchet blobs the peer
         * has never answered with a decryptable one of its own.
         *
         * WHY IT EXISTS. The ratchet role is a pure function of two inbox ids and the
         * OUTBOUND one is whatever the peer declared, so a peer can force BOTH sides
         * into the same role. [drLegacyFallbackKey] sees only the both-BOB collision
         * (neither side ever holds a sending chain ⇒ every send falls through to the
         * static envelope). In the both-ALICE collision both sides hold sending chains,
         * `tryEncrypt` NEVER returns null, and that counter therefore stays 0 forever
         * while every blob fails the peer's AEAD — a silent, permanent, bidirectional
         * blackout. The only observable is on the RECEIVE side: we emit ratchet blobs
         * and the peer keeps answering with something we cannot decrypt as one.
         *
         * Cleared (deleted) by the first inbound ratchet blob that DECRYPTS, on either
         * channel — that is positive proof the two roles are compatible. Per-contact,
         * so it is in [ratchetMetaKeysForContact] and in `MoveMetaPolicy`.
         */
        internal fun drRatUnackedKey(contactId: String) = "dr-rat-unacked/$contactId"

        /**
         * The durable per-contact REFUSAL latch ("1" = refused). Armed
         * when either detector crosses its threshold ([drLegacyFallbackKey] ≥
         * [RATCHET_FALLBACK_STALL_THRESHOLD], the both-Bob case, or [drRatUnackedKey] ≥
         * [RATCHET_UNACKED_REFUSE_THRESHOLD], the both-Alice case). While it is set,
         * 1:1 and group TEXT for that contact is NOT sent on the static envelope — the
         * send fails visibly instead ([MessageManager.ratchetRefused] tells the UI why).
         *
         * Absent means NOT refused: this is a fail-open marker by construction, so a
         * fresh, legacy or unreadable vault never refuses anything. It is cleared the
         * moment an inbound ratchet blob decrypts, so a relay that stops dropping
         * restores the conversation with no user action, and a re-pair clears it by
         * construction (it is in [ratchetMetaKeysForContact]).
         *
         * It NEVER touches `dr/{id}/text`: a refusal blocks SENDS, it must not wipe or
         * re-init a working ratchet.
         */
        internal fun drRefusedKey(contactId: String) = "dr-refused/$contactId"

        // The `_meta` latches a corrupt-state text-ratchet re-init clears, in this
        // order (the `onCorruptReinit` hook of [ratchetManager]). NEVER [drIntentKey]:
        // it is set only at pairing, so deleting it would revert the contact to the
        // static envelope until a manual re-pair.
        internal fun ratchetReinitResetKeys(contactId: String): List<String> = listOf(
            drRecvLockKey(contactId),
            // The text channels' one-drain grace belongs to the lock being cleared.
            // Left behind, a later re-arm from a TEXT drain (which records no grace)
            // would inherit it and accept one extra legacy drain per text channel.
            drRecvLockGraceKey(contactId),
            // The fresh ratchet restarts its receiving-step ordinal at 0, so the
            // old downgrade-proof step would silence detection until it was passed.
            drCtlCapStepKey(contactId),
            drOnKey(contactId),
            drRxSeenKey(contactId),
            // BOTH downgrade counters, not just one: `dr-legacyfb` left at the threshold
            // keeps ratchetRefused()/forwardSecrecyStalled() true across the re-init and
            // re-arms the latch on the very first fallback after dr-on comes back,
            // instead of re-earning it within 8 sends.
            drLegacyFallbackKey(contactId),
            drRatUnackedKey(contactId),
            drRefusedKey(contactId),
        )

        // --- (2026-10-21) integrity-critical CONTROL kinds ride the ratchet ---
        //
        // The ratchet-sealed announce rule, extended to every control kind that changes WHO we
        // talk to: the referral handshake (offer, accept, the introducer-relayed
        // accept — all [CONTROL_KIND_REFERRAL_ACCEPT]/[CONTROL_KIND_REFERRAL_OFFER])
        // and group MEMBERSHIP control (invite / join / roster — which also carries
        // admin transfer — / leave). With one vault image (sharedSecret, inbox rows,
        // counters) a static-envelope forger could otherwise commit an attacker key as
        // a TRUST_REFERRED_CONFIRMED contact and bind it into a group slot.
        //
        // Unlike the announce, these kinds must interoperate with peers that predate
        // the rule (an old receiver drops any non-announce ratchet blob on its control
        // inbox), so BOTH directions are gated on positive evidence:
        //   SEND   — sealed on the ratchet only once the peer ADVERTISED it accepts
        //            that ([drCtlCapKey], learnt from [CTL_RATCHET_CAP_FIELD]).
        //   RECEIVE— a legacy copy is dropped only once the peer PROVED, inside a
        //            ratchet blob decrypted past the bootstrap window, that it seals
        //            them ([drCtlWatermarkKey], from [CTL_RATCHET_WATERMARK_FIELD]) —
        //            and only above the counter it was at when it committed, so a
        //            genuine pre-commit legacy copy still queued on the relay lands.
        // Chatty control kinds (`act`, screenshot notices) deliberately stay on the
        // static envelope: see `docs/vault-relay-internals.md` (integrity-critical
        // control kinds) for the
        // MAX_SKIP / skipped-key analysis.

        /**
         * Envelope field (both wire formats, every envelope this build sends):
         * `"cr":"1"` = "I accept integrity control kinds sealed by the text ratchet on
         * my control inbox, and I seal mine once you say the same". A JSON STRING,
         * optional, unknown to older parsers (which read fields by name and ignore it).
         */
        internal const val CTL_RATCHET_CAP_FIELD = "cr"

        /**
         * Envelope field, RATCHET envelopes only, and only once we hold the peer's
         * [CTL_RATCHET_CAP_FIELD]: `"crw":"<n>"`, where n is OUR outbound control
         * counter at the moment of this send. It is a COMMITMENT: every integrity
         * control kind we send from here on rides the ratchet (we hold `dr-on` and a
         * sending chain — that is what produced this blob), so no legacy copy of one
         * of those kinds with a control counter above n can come from us.
         */
        internal const val CTL_RATCHET_WATERMARK_FIELD = "crw"

        /**
         * "The peer advertised [CTL_RATCHET_CAP_FIELD]" (`"1"`). SEND-side gate. Sticky
         * until a mature ratchet envelope WITHOUT it withdraws it (a vault
         * moved onto an older install). Learnt from ANY authenticated envelope: a
         * static-key forger who plants it for a peer that has NOT upgraded makes us
         * seal integrity control that peer then drops — a LOSS/DoS (the roster and
         * referral redrives keep failing until the peer upgrades), never an exposure,
         * since everything we send that way is sealed by the ratchet. Named under
         * the `dr-rxseen` prefix on purpose — it travels with a device move through the
         * existing `MoveMetaPolicy` entry, and it MUST: a new phone that lost it would
         * send integrity kinds on the static envelope above a watermark the peer holds,
         * and the peer would (correctly) drop them. In [ratchetMetaKeysForContact].
         */
        internal fun drCtlCapKey(contactId: String) = "dr-rxseen-ctlcap/$contactId"

        /**
         * The LOWEST [CTL_RATCHET_WATERMARK_FIELD] the peer has sent us inside a ratchet
         * blob decrypted while [drRecvLockKey] was already armed (decimal). RECEIVE-side
         * evidence. Absent ⇒ no lock (the un-upgraded-peer / bootstrap default — never
         * a drop). Under the `dr-rxlock` prefix so it travels with a move; in
         * [ratchetMetaKeysForContact].
         */
        internal fun drCtlWatermarkKey(contactId: String) = "dr-rxlock-ctlwm/$contactId"

        /**
         * The text channels (`"m"`, `"g"` tags, comma-separated) still owed
         * the receive lock's one-drain grace because it was armed by a CONTROL drain.
         * Under the `dr-rxlock` prefix (travels with a move); in [ratchetMetaKeysForContact].
         */
        internal fun drRecvLockGraceKey(contactId: String) = "dr-rxlock-grace/$contactId"

        /**
         * Sealed control wires DEFERRED because decrypting them would have
         * destroyed undrained text keys (`<stampMs>:<maxAgeMs>:<base64 wire>` entries). Under the `dr/`
         * prefix (ratchet data — travels with a move alongside the state that opens
         * them); in [ratchetMetaKeysForContact]. Never parsed as a ratchet state: the
         * `RatchetManager` store key is `dr/<id>/<channel>` and no channel is named this.
         */
        internal fun drCtlDeferredKey(contactId: String) = "dr/$contactId/ctl-deferred"

        /** How long a sealed control blob may stay deferred before it is processed
         *  regardless, when unread texts are POSITIVELY waiting behind a backlog skip:
         *  the skipped-key / relay text retention (24 h). */
        internal const val CTL_DEFER_MAX_AGE_MS = DoubleRatchet.SKIPPED_KEY_TTL_MS

        /** The force age for every other deferral (an old-chain flush, or
         *  a peek that could not tell): long enough to cover an open conversation's
         *  next drain, short enough that a dead skipped key never parks a passive
         *  member's invite/roster/referral for a day. */
        internal const val CTL_DEFER_SHORT_AGE_MS = 10L * 60L * 1000L

        /** Only wires up to this size are ever deferred — the 32 KiB
         *  padding bucket plus the ratchet header/AEAD overhead, which covers every
         *  referral leg, invite, leave, the roster of a fully paired 64-member group
         *  ([GroupManager.MAX_GROUP_MEMBERS]) and the join of a user with several
         *  hundred contacts. A larger wire goes through the ordinary decrypt-or-reject.
         *  The store stays bounded by [MAX_DEFERRED_CTL_BYTES] / [MAX_DEFERRED_CTL_STORED]
         *  per contact — that total is what protects the move bundle. */
        internal const val MAX_DEFERRABLE_CTL_WIRE_BYTES = 32 * 1024 + 256

        /** How long a "how many texts are waiting" peek answer is reused while a
         *  deferral is held, so a held deferral does not re-peek every sweep. */
        internal const val UNDRAINED_PEEK_CACHE_MS = 3L * 60L * 1000L

        /** Total deferred wire bytes stored per contact (≤ 64 KiB, so a
         *  move bundle can never be pushed toward its size cap by deferrals). */
        internal const val MAX_DEFERRED_CTL_BYTES = 64 * 1024

        /** Receiving-step ordinal of the newest advert-bearing envelope
         *  decrypted in order — what makes a later cap-less one provably NEWER. Under
         *  `dr-rxseen` (travels with a move); in [ratchetMetaKeysForContact]. */
        internal fun drCtlCapStepKey(contactId: String) = "dr-rxseen-ctlstep/$contactId"

        /** Deferred blobs retried under the guard per drain (newest kept); older ones
         *  are force-processed. */
        internal const val MAX_DEFERRED_CTL_RETRY = 16

        /** Hard bound on stored deferred blobs per contact. */
        internal const val MAX_DEFERRED_CTL_STORED = 32

        /** Group MEMBERSHIP kinds that ride the ratchet. `act`/`screenshot` do not. */
        internal val RATCHET_SEALED_GROUP_CONTROL_KINDS: Set<String> = setOf(
            GroupManager.KIND_INVITE, GroupManager.KIND_JOIN,
            GroupManager.KIND_ROSTER, GroupManager.KIND_LEAVE,
        )

        /**
         * True for the integrity-critical control kinds. [groupScoped] is
         * whether the envelope carries a `"g"`: the same kind string means different
         * things in the two namespaces (`screenshot` exists in both and is chatty in
         * both). [CONTROL_KIND_INBOX] is NOT here — it has its own, older rule.
         */
        internal fun isRatchetSealedControlKind(kind: String?, groupScoped: Boolean): Boolean = when {
            kind == null -> false
            groupScoped -> kind in RATCHET_SEALED_GROUP_CONTROL_KINDS
            else -> kind in DIRECT_REFERRAL_KINDS
        }

        /**
         * Strict decimal parse of a peer-supplied watermark: 1–18 ASCII digits only
         * (never `toLongOrNull` on its own, which also accepts a sign and non-ASCII
         * digits). Anything else is "no watermark" — the fail-open direction.
         */
        internal fun parseCtlWatermark(s: String?): Long? {
            if (s == null || s.isEmpty() || s.length > 18) return null
            for (ch in s) if (ch !in '0'..'9') return null
            return s.toLongOrNull()
        }

        /**
         * The most a LEGACY control-inbox counter may jump past the replay baseline
         * this drain started from. Anything above is dropped WITHOUT advancing the
         * baseline, so one forged blob (counter = Long.MAX_VALUE) can no longer
         * suppress every genuine control message from this peer forever.
         *
         * Sized from how far an honest peer's counter can legitimately run ahead of
         * us: [MoveConstants.COUNTER_JUMP] (10 000) per device move, plus one counter
         * per control append (activity notices are the chatty part — one per group
         * text the peer sends) for as long as we do not drain. Our inbound control
         * inbox is reaped by the relay after 365 idle days, so at 1 000 000 an honest
         * peer would need ~2 700 control appends to us PER DAY for a whole year, or a
         * hundred back-to-back moves, to reach it. Deliberately generous: a cap an
         * honest peer can hit is a permanent channel brick, while a forged jump below
         * it is a bounded known limitation.
         */
        internal const val CTL_COUNTER_MAX_FORWARD_JUMP = 100L * MoveConstants.COUNTER_JUMP

        /** Saturating `base + CTL_COUNTER_MAX_FORWARD_JUMP` (a baseline already pinned
         *  near Long.MAX_VALUE by a pre-fix forgery must not overflow negative). */
        internal fun ctlCounterCeiling(base: Long): Long =
            if (base > Long.MAX_VALUE - CTL_COUNTER_MAX_FORWARD_JUMP) Long.MAX_VALUE
            else base + CTL_COUNTER_MAX_FORWARD_JUMP

        /** Bound on the RAM set of contacts owed a sealed-control catch-up drain. */
        private const val MAX_SEALED_CONTROL_CATCH_UPS = 256

        /**
         * Consecutive unacked inbound drains ([drRatUnackedKey]) past which the
         * downgrade is REFUSED. Deliberately the same number as
         * [RATCHET_FALLBACK_STALL_THRESHOLD] — and deliberately a separate constant,
         * because the two detectors count different events (our sends falling back vs.
         * the peer's receives never carrying a ratchet) and only one of them is also a
         * UI "stalled" threshold.
         *
         * Why 8 and why CONSECUTIVE: a healthy pairing resets both counters on the
         * first decryptable ratchet blob, so reaching 8 means 8 back-to-back rounds
         * with no working ratchet in either direction. That is well clear of the
         * ordinary bootstrap (a responder falls back only until its first ratchet
         * receive) and of a transient relay drop, while still catching a permanent
         * role collision inside one short conversation. Lowering it trades the refusal
         * DoS window (a hostile relay can force a refusal, which it can already
         * do more bluntly by blackholing the inbox) against exposure.
         */
        internal const val RATCHET_UNACKED_REFUSE_THRESHOLD = 8

        /**
         * How many ratchet blobs this device must have sent with no decryptable
         * ratchet answer before an unacked inbound drain counts as EVIDENCE. Read off
         * the ratchet's own sending counter, which resets on every receiving DH step —
         * so it means "sent since the last time the peer's ratchet provably answered".
         *
         * 4 keeps the detector off every honest one-directional burst (send a few
         * messages while the peer is asleep) and off the bootstrap entirely: a device
         * with NO sending chain has sent 0, so the both-Bob collision can never arm
         * this half — that case is [drLegacyFallbackKey]'s, by construction.
         */
        internal const val RATCHET_SENDS_BEFORE_UNACKED_EVIDENCE = 4

        /** Ceiling for the stored unacked count — same rationale as
         *  [RATCHET_FALLBACK_COUNT_CAP]: everything above the threshold means the same. */
        private const val RATCHET_UNACKED_COUNT_CAP = 9999

        /**
         * The IMMUTABLE order half of the v2 ratchet-role rule for one contact —
         * `"1"` iff OUR pairing contribution sorts before the peer's
         * ([ratchetRoleOrderBit]). Written ONCE, inside the same transaction that
         * commits the contact (`PairingVault.savePairedContact` for the QR/paste
         * flow, `ReferralManager.finalizeFromPeerAccept` for the X25519 flow), from
         * values that are fixed at pairing and can never change afterwards.
         *
         * It holds NO key material: the two secret halves themselves are
         * deliberately NOT persisted (the vault already holds the derived
         * `sharedSecret`, which is the thing an attacker needs, and the ONLY fact
         * the role rule consumes from the halves is one bit of ordering). Storing
         * the bit rather than the halves is therefore strictly less material at
         * rest, travels in a move bundle without carrying pairing secrets off the
         * device, and is exactly as immutable.
         *
         * Absent ⇒ the legacy id-order rule ([ratchetSelfIsBob]), unchanged. Every
         * pairing made before this shipped, and every pairing with an old peer, is
         * in that state, so nothing is re-derived and nothing can break.
         * Per-contact, so it is in [ratchetMetaKeysForContact] and in
         * `MoveMetaPolicy`.
         */
        internal fun drRoleOrderKey(contactId: String) = "dr-roleord/$contactId"

        /**
         * What this peer's build was observed to be AT PAIRING —
         * `"1"` = it advertised role rule v2 ([ROLE_RULE_FIELD] = [ROLE_RULE_V2] in its
         * QR payload / referral accept), `"0"` = it did not, absent = never observed.
         *
         * WHY BOTH KEYS ARE REQUIRED. A role rule needs AGREEMENT, not strength: two
         * builds applying different rules to the same pairing land in exactly the
         * both-Bob / both-Alice collision the role binding exists to remove. So the
         * v2 rule is applied only when this reads `"1"` AND [drRoleOrderKey] is
         * present at the moment the role is first computed; anything else — `"0"`,
         * absent, unreadable, malformed — falls back to the id-order rule, which is
         * what the peer will be using. Absence is never an error and never a refusal.
         *
         * **`"0"` is a LATCH, and it is load-bearing.** The order bit is written only
         * by a build that has this change, and that build always learns the peer's
         * version in the SAME step (it must scan the peer's code to get the peer's
         * pairing contribution at all). So "order bit present, peer was v1" is a
         * complete, final observation — and if a later `inbox` announce were allowed
         * to upgrade it, this pairing would move to v2 while the PEER, whose own vault
         * has no order bit (its pairing predates the change), stays on the id rule
         * forever. That is a MIXED-VERSION PAIRING WHOSE OLD SIDE LATER UPGRADES, i.e.
         * an ordinary honest sequence, and it would manufacture the collision. So
         * [notePeerRoleRuleV2] only ever fills an ABSENT value; it never overwrites
         * `"0"`, and nothing downgrades a `"1"`.
         */
        internal fun drPeerRoleRuleV2Key(contactId: String) = "dr-rolerv2/$contactId"

        /**
         * Records the two role-rule inputs for a brand-new pairing.
         * Call from INSIDE the pairing transaction, right beside
         * [markRatchetCapable] — the role inputs and the contact they describe must
         * commit together or not at all.
         *
         * [mine] / [peer] are the two 32-byte pairing-secret halves (QR/paste) or the
         * two ephemeral X25519 PUBLIC keys (referral). Neither is stored; only the
         * one-bit ordering derived from them is. Nothing at all is written when the
         * two are identical (no ordering exists), which leaves the pairing on the
         * id-order rule — the correct, agreeing answer there.
         *
         * The peer-version observation is written EITHER WAY — `"1"` or `"0"` — see
         * [drPeerRoleRuleV2Key] for why the negative case is a latch and not simply an
         * omission.
         */
        internal fun recordRatchetRoleInputs(
            db: VaultDatabase,
            contactId: String,
            mine: ByteArray,
            peer: ByteArray,
            peerRunsRoleRuleV2: Boolean,
        ) {
            val order = ratchetRoleOrderBit(mine, peer) ?: return
            db.putMeta(drRoleOrderKey(contactId), if (order) "1" else "0")
            db.putMeta(drPeerRoleRuleV2Key(contactId), if (peerRunsRoleRuleV2) "1" else "0")
        }

        /**
         * Records the peer's v2 marker seen AFTER pairing (the in-band
         * `inbox` announce). Fills an ABSENT observation ONLY — it never overwrites the
         * `"0"` a pairing recorded, because that `"0"` is a complete observation and
         * upgrading it would split a mixed-version pairing's two devices onto different
         * rules (see [drPeerRoleRuleV2Key]).
         *
         * Idempotent, gated on a read so the steady state costs one lookup and zero
         * writes, and never throws — it runs inside the announce apply, which must not
         * fail over a hint.
         *
         * It cannot re-role an established pairing either: [RatchetManager.loadOrInit]
         * only consults the rule when NO ratchet blob exists, and the blob is persisted
         * by the very first ratchet op.
         *
         * **Honest scope, so nobody later mistakes this for load-bearing:** in today's
         * pairing topology it never changes an outcome. [recordRatchetRoleInputs]
         * writes BOTH keys or neither, so the only pairings whose observation is absent
         * predate the role binding — and those have no order bit, so the v2 rule cannot
         * engage there whatever this records. It is kept because the design asks the
         * announce to carry the marker and because it is the carrier a
         * future flow would need if the order bit were ever written before the peer's
         * version was known. Do not "simplify" it into an unconditional write: that is
         * exactly the mixed-version hazard [drPeerRoleRuleV2Key] describes.
         */
        internal fun notePeerRoleRuleV2(db: VaultDatabase, contactId: String) {
            try {
                if (db.getMeta(drPeerRoleRuleV2Key(contactId)) != null) return
                db.putMeta(drPeerRoleRuleV2Key(contactId), "1")
            } catch (_: Exception) { /* best effort — absent just keeps the id rule */ }
        }

        /**
         * The DURABLE pending-rotation marker for one (contact, direction)
         * INBOUND inbox — `cap-pend/{contactId}/{direction}` holding the CANDIDATE
         * new read capability. It is written BEFORE the rotation PUT leaves the
         * device, so a crash / killed process / lost response can never leave the
         * relay holding a capability this device has no copy of: the union
         * {record.cap, pending} always contains whatever the relay holds. Cleared
         * only when the candidate is proven live (committed onto the record) or
         * proven dead. It holds a LIVE capability, so it is purged with the contact
         * — see [ratchetMetaKeysForContact].
         */
        internal fun capPendingKey(contactId: String, direction: String) =
            "cap-pend/$contactId/$direction"

        /**
         * The DURABLE throttle on the GROUP-inbox backfill for one contact —
         * `grp-ann/{contactId}` holding `"<attempts>|<lastMs>"`.
         *
         * Every pairing made before the third inbox existed has no group inbox, so
         * the backfill is what converges them — and it MINTS (a 20-bit PoW grind +
         * a relay inbox) and ANNOUNCES (a control append). Unbounded, that is a
         * periodic Tor beacon on a permanently inert contact, which is exactly what
         * GroupManager's unresolved-member fast-window bound exists to prevent; so:
         * at most one attempt per
         * [GROUP_BACKFILL_MIN_INTERVAL_MS], at most [GROUP_BACKFILL_MAX_ATTEMPTS]
         * ever.
         *
         * Deliberately spelled `grp-ann/` with a HYPHEN: the `grp_` prefix already
         * in [MoveMetaPolicy] is the GROUP-manager namespace and must not swallow a
         * per-CONTACT key by accident. The key is per contact, so it is in
         * [ratchetMetaKeysForContact] (a re-pair re-arms the budget with the new
         * contact) and, because it is a BOUND rather than a cache, in
         * `MoveMetaPolicy.allowedPrefixes` — see the note there.
         */
        internal fun groupBackfillKey(contactId: String) = "grp-ann/$contactId"

        /**
         * The backfill's two bounds. 24 h apart and at most four attempts, so
         * a pairing whose peer never upgrades costs four appends over four days and
         * then nothing, forever — a permanent, silent fallback to the legacy route:
         * degraded, never broken.
         *
         * **Re-armed by a re-pair (the key dies with the contact) and by
         * CONVERGENCE (the pairing actually gaining its group rows clears it —
         * but only once the record is [GROUP_BACKFILL_MIN_INTERVAL_MS] old, see
         * [maybeBackfillGroupInbox]), and by nothing else.** The design sketch also
         * offered "a new membership event", which is NOT implemented and must not
         * be: a membership event is peer-triggerable (any roster from the admin),
         * so re-arming on one would let a co-member drive one PoW mint per contact
         * per interval indefinitely. The attempt cap is what turns the interval
         * from a rate into a bound — and the 24 h floor on the convergence clear
         * is what keeps the RELAY (which controls 404-vs-200 for our own inbox)
         * from re-arming the self-heal path faster than once a day.
         */
        internal const val GROUP_BACKFILL_MIN_INTERVAL_MS = 24L * 60 * 60 * 1000
        internal const val GROUP_BACKFILL_MAX_ATTEMPTS = 4

        /**
         * The inbound directions whose READ capability THIS device owns. The read
         * cap is the inbox OWNER capability (drain / `DELETE /inbox/{id}` / rotate
         * BOTH caps / push register), and the CONTROL and GROUP inboxes' are exactly
         * as powerful as the text inbox's — so anything that rotates or destroys one
         * must cover all three. Single-sourced here for
         * [MessageManager.resetRelayAccess] and [deleteContactAndPurgeRelay].
         *
         * Adding a direction here does FOUR things at once, and every one of them is
         * mandatory: the `cap-pend/{id}/{direction}` marker joins
         * [ratchetMetaKeysForContact] (its trailing `map`), the relay
         * `DELETE /inbox/{id}` on a contact delete covers it
         * ([deleteContactAndPurgeRelay]), "Reset relay access" rotates its read cap
         * ([MessageManager.resetRelayAccess]) and the device move's post-import D4
         * rotation covers it (`MoveManager`). Leaving the group inbox out would make
         * it the one drain/delete/rotate capability an imaged vault yields FOREVER.
         */
        internal val OWNED_READ_DIRECTIONS = listOf("inbound", DIR_INBOUND_CTL, DIR_INBOUND_GRP)

        /** True iff [blob] is a ratchet wire blob (carries [RATCHET_WIRE_MAGIC]). */
        internal fun isRatchetWire(blob: ByteArray): Boolean =
            blob.size >= RATCHET_WIRE_MAGIC.size &&
                RATCHET_WIRE_MAGIC.indices.all { blob[it] == RATCHET_WIRE_MAGIC[it] }

        /**
         * Marks a freshly-paired contact ratchet-capable. Sets the intent marker
         * (always) directly on the vault — independent of any live MessageManager,
         * so it survives the pairing happening before Tor/messageManager exists.
         * Actual SEND activation (dr-on) is deferred to the poll loop once both
         * inboxes exist and the first inbound message confirms the peer is paired.
         * Call from the platform add-contact flow right after the contact persists.
         */
        fun markRatchetCapable(db: VaultDatabase, contactId: String) {
            try { db.putMeta(drIntentKey(contactId), "1") } catch (_: Throwable) { /* best effort */ }
        }

        /**
         * How many total ATTEMPTS [mintInbox] makes at the whole handshake in the
         * face of TRANSIENT failures — a Tor transport hiccup (POST threw / code
         * <= 0) OR a relay 429 rate-limit. Tor round-trips drop often enough that a single
         * lost one shouldn't fail pairing, and a 429 means "slow down", not "give
         * up": 12 attempts ride out a bad-circuit window or a rate-limit burst,
         * with the backoff scaled per cause (6-12s for a 429 so its short window
         * clears; 1.5-5s for a Tor-drop). Re-grinding PoW across these retries
         * stays bounded by [MINT_TOTAL_POW_BUDGET_MS] (<=20s aggregate), so a
         * hostile relay can't 429-loop us into unbounded PoW — the budget, NOT a
         * terminal 429, is the anti-DoS guarantee. Genuinely terminal (not
         * retried): PoW timeout, hostile difficulty, caller abort, 507 inbox-limit.
         */
        private const val MAX_MINT_TRANSIENT_ATTEMPTS = 12

        /**
         * Aggregate PoW-grind budget for ONE [mintInbox] call, summed across
         * EVERY solvePow it runs (re-solves on a 400 + the solves wasted by
         * transient retries). Without it a hostile relay that 400s and/or drops
         * to force repeated grinds could cost MAX_MINT_TRANSIENT_ATTEMPTS ×
         * MAX_MINT_SOLVE_ATTEMPTS × POW_MAX_SOLVE_MILLIS ≈ 540s of CPU per mint;
         * this caps the SUM (each solve gets min(remaining, per-solve cap), and
         * once exhausted further solves time out immediately → terminal). Only
         * grind time counts — network round-trips and backoff sleeps don't — so
         * an honest mint that re-solves after several dropped round-trips
         * (a few seconds each on a multi-core grind) stays well under it.
         */
        private const val MINT_TOTAL_POW_BUDGET_MS = 20_000L

        /**
         * Per-POST transport budget for the inbox-mint handshake (seconds),
         * shorter than [DEFAULT_RELAY_HTTP_TIMEOUT_SECONDS] (60). A mint round-
         * trip is tiny (empty POST → 400 challenge; local PoW; tiny POST → 201)
         * and finishes in a few seconds over a healthy Tor circuit. On a cold/
         * half-open circuit the POST otherwise blocks the full 60s before the
         * transient-retry loop ([MAX_MINT_TRANSIENT_ATTEMPTS]) can re-fire — and
         * the iOS UI mints the set sequentially ([mintInboxPair]), so three inboxes
         * × 5 retries × 60s dominated the "Setting up inbox…" wait and blew the
         * e2e budget (the cold-Tor mint hang). Cancelling at 25s frees Tor to
         * attach the next attempt's fresh stream to a different circuit far
         * sooner, so an honest mint recovers on an early retry instead of
         * grinding dead 60s circuits; 25s still gives a healthy mint ~5×
         * headroom. Only the mint POSTs use this; send/poll/rotate keep 60s.
         */
        internal const val MINT_HTTP_TIMEOUT_SECONDS = 25

        /**
         * Warm-circuit gate before minting (Tor-resilience hardening). The mint
         * is the most expensive thing we do over Tor — a PoW grind plus two 25s
         * POSTs per inbox, retried up to [MAX_MINT_TRANSIENT_ATTEMPTS] — so firing
         * it BLINDLY into a cold/half-open circuit is what makes a referral accept
         * (which mints a PAIR) spin for many minutes: every POST blocks to its 25s
         * cap, the retry loop re-grinds, and 2 inboxes × 12 retries ≈ the whole
         * [ReferralManager] mint deadline before anything succeeds. A real user on
         * flaky Tor sees the same multi-minute "Connecting…" hang, so this is an
         * app problem, not a test one. [waitForRelayWarm] first proves the relay
         * is reachable with a CHEAP GET (no PoW, no rate-limit cost) on a SHORT
         * budget, and only then spends PoW + fires the mint POSTs — which then
         * reuse the just-warmed circuit (Tor keeps it usable for MaxCircuitDirti-
         * ness, far longer than the two back-to-back mints take). A probe gets
         * [WARM_PROBE_TIMEOUT_SECONDS] (shorter than a mint POST, so a dead circuit
         * is detected and re-probed faster than a wasted mint attempt); the gate
         * probes for at most [WARM_PROBE_MAX_WAIT_MS] then falls through to mint
         * regardless, so it can NEVER be slower than today's blind mint — it only
         * skips ahead when a good circuit appears, and gives up cheaply otherwise.
         */
        internal const val WARM_PROBE_TIMEOUT_SECONDS = 12
        internal const val WARM_PROBE_MAX_WAIT_MS = 90_000L

        /**
         * Control-channel poll cadence. IDLE is the privacy default — a jittered
         * 60–90 s loop with no fixed beacon for a traffic observer. FAST is used
         * ONLY while a group-membership convergence round-trip is in flight (this
         * device sent OR received control traffic within
         * [CONTROL_CONVERGENCE_WINDOW_MS]): a join→roster→resolve chain then
         * settles in seconds instead of paying a full idle interval PER HOP, so
         * member↔member resolution completes even over slow Tor (the cross:multi3
         * "group not fully resolved" hang). The burst tracks real activity that
         * already emits traffic, so it adds no distinguishable idle beacon; when
         * the exchange goes quiet the loop reverts to IDLE. Both platforms decide
         * via [controlPollDelayMs], so the cadence is identical.
         *
         * **FIX 3b (2026-09-16): IDLE was 25–45 s and is now 60–90 s.** On a
         * phone with ~16 contacts a steady-state sweep measured 13.9–15.6 s
         * (16 serial control peeks over one Tor circuit) on a ~34 s cadence —
         * ≈45 % of the whole foreground session spent inside a sweep. The
         * control channel's common case is an EMPTY inbox, and its payloads
         * (invites, rosters, announces, referral handshakes) tolerate far more
         * latency than text: they are durable on the relay for
         * [CONTROL_APPEND_TTL_SECONDS] and are redriven on this very sweep. Only
         * the IDLE half moves; the FAST window a convergence round-trip opens is
         * untouched, so a join→roster→resolve chain still settles in seconds.
         * A slower idle loop is also strictly BETTER for traffic analysis — the
         * same jitter spread over a longer period.
         */
        internal const val CONTROL_POLL_IDLE_BASE_MS = 60_000L
        internal const val CONTROL_POLL_IDLE_JITTER_MS = 30_000
        internal const val CONTROL_POLL_FAST_BASE_MS = 2_500L
        internal const val CONTROL_POLL_FAST_JITTER_MS = 2_500
        internal const val CONTROL_CONVERGENCE_WINDOW_MS = 60_000L

        /**
         * The ABSOLUTE ceiling on one fast EPISODE,
         * re-armable or not — the sibling of `GroupManager.UNRESOLVED_MEMBER_FAST_
         * WINDOW_MS`, same value and the same reasoning: a permanently
         * re-armed 2.5–5 s poll is a fixed Tor beacon (plus battery/data drain),
         * exactly the traffic signature the idle jitter exists to hide, and it
         * simultaneously disables the peek-before-drain for every contact.
         *
         * 10 minutes generously covers a real multi-hop join→roster→resolve
         * round-trip even over slow Tor. A genuine exchange never hits the ceiling
         * anyway, because every hop of it is PROGRESS (this device sends, or the
         * arrival moves group state) and progress re-anchors the episode — only
         * traffic that converges NOTHING can run the clock out. See
         * [isControlConverging].
         */
        internal const val CONTROL_FAST_EPISODE_MAX_MS = 10L * 60 * 1000

        /**
         * How many times a message POST ([sendEnvelope]) re-tries a TRANSPORT
         * drop (the POST threw or returned code <= 0 — a Tor circuit hiccup). A
         * dropped copy would otherwise vanish silently: GroupManager's fan-out
         * treats each member copy as independent and does NOT re-send a failed
         * one, so one bad circuit meant a member never got the message (the
         * cross:multi3 "0/1 received group bubbles" — only the iOS member, whose
         * copy dropped). Re-POSTing is idempotent: the monotonic counter is sealed
         * into the blob and persisted BEFORE the first attempt, so a duplicate
         * that both arrivals produce is rejected by the receiver's strict-
         * monotonic replay check. Only transport drops retry; any real HTTP
         * response (2xx/4xx/5xx) is terminal.
         */
        internal const val SEND_TRANSIENT_ATTEMPTS = 4

        /**
         * Wall-clock budget for the whole transient-retry loop. The loop runs
         * under the per-contact send lock, so its duration is also how long every
         * OTHER send to that contact waits. Checked BETWEEN attempts (an in-flight
         * request is never cut short — its bytes may already be at the relay), so
         * the real bound is this plus one HTTP timeout. Sized to let a slow-but-
         * alive circuit finish a couple of attempts while stopping a wedged one
         * from monopolising the lock for minutes.
         */
        internal const val SEND_TRANSIENT_BUDGET_MS = 90_000L

        /**
         * How close to its stamped `expiresAt` an inbox row must be before a
         * PROVEN-live relay response re-stamps it (see
         * [VaultDatabase.touchInboxExpiry]). Nothing gates on the column any more
         * ([selectOperationalInbox]), so this is data hygiene and is priced
         * accordingly: with a 365-day lifetime and a 30-day renewal window it costs
         * roughly ONE tiny single-column UPDATE per inbox per year — and zero vault
         * writes the rest of the time, because the check is a comparison on a row the
         * caller has already read. A vault that is already past its original stamp
         * repairs itself on the first successful operation after this ships.
         */
        internal const val INBOX_LEASE_RENEW_BEFORE_MS = 30L * 24 * 60 * 60 * 1000

        /**
         * Defense-in-depth cap on blobs processed per poll. The HTTP
         * layer bounds the response body size; this additionally bounds how
         * many blobs we base64-decode + AES-GCM-decrypt per drain so a hostile
         * relay stuffing the (size-capped) body with minimal blobs can't pin
         * the CPU. Legitimate drains are far smaller.
         */
        // Retrieve-ack: blobs past this cap are NOT_PROCESSED (never acked), so the
        // relay hands them back on the next drain instead of the tail being lost.
        internal const val MAX_BLOBS_PER_POLL      = 2048

        /** `GET /inbox/{id}` + this = lease, don't delete (docs/RELAY_SPEC.md). */
        internal const val RETRIEVE_LEASE_QUERY    = "?lease=1"

        // Retrieve-ack wire limits (relay `POST /ack`, docs/RELAY_SPEC.md): ≤ 64
        // items, ≤ 256 ids per item. The relay endpoint itself accepts a 256 KiB
        // body, but the reverse proxy in front of it caps EVERY request body at
        // 128 KiB (413 above that), and that is the limit that applies. The client
        // byte budget is 100 000 bytes — under the proxy's ceiling with margin (an id
        // is 22 chars + quotes + comma); a bigger ack would be refused by the proxy
        // and the blobs would come back as repeats.
        internal const val ACK_BATCH_MAX_ITEMS     = 64
        internal const val ACK_MAX_IDS_PER_ITEM    = 256
        internal const val ACK_BATCH_MAX_BODY_BYTES = 100_000
        private const val ACK_BODY_OVERHEAD_BYTES  = 32
        // Over-estimate of one item's fixed JSON in [ackBody]
        // (`{"id":…,"rc":…,"token":…,"delete":[]}`, quotes and the separating comma
        // = 41 bytes). The values are validated base64url / inbox ids, so
        // `jsonEscapeString` never lengthens them.
        internal const val ACK_ITEM_JSON_OVERHEAD_BYTES = 64
        // Two quotes and a comma per delete id.
        internal const val ACK_ID_JSON_OVERHEAD_BYTES = 3
        private const val ACK_CONTENT_TYPE         = "application/json"
        /** How long after an unconfirmed ack a duplicate is labelled "re-delivery". */
        private const val ACK_REDELIVERY_LABEL_WINDOW_MS = 10 * 60_000L
        private const val MAX_ACK_UNCONFIRMED      = 256

        /** Direct (non-group) control kind: in-band inbox announcement. */
        const val CONTROL_KIND_INBOX = "inbox"

        /** A received control kind longer than this is malformed and dropped (both
         *  receive paths); every real kind is a short fixed word. */
        internal const val MAX_CONTROL_KIND_CHARS = 16

        /** The shortest blob that can be valid AES-GCM: 12-byte IV + 16-byte tag. */
        private const val AES_GCM_MIN_BLOB_BYTES = 12 + 16

        // Randomised waits, as `base + secureRandomInt(spread)` ms (one CSPRNG draw).
        // Mint retry after a 429 / after a transport drop:
        private const val MINT_BACKOFF_RATE_LIMITED_BASE_MS = 6000L
        private const val MINT_BACKOFF_RATE_LIMITED_SPREAD_MS = 6000
        private const val MINT_BACKOFF_TRANSIENT_BASE_MS = 1500L
        private const val MINT_BACKOFF_TRANSIENT_SPREAD_MS = 3500
        // The warm-circuit gate's re-probe interval before a mint:
        private const val WARM_GATE_POLL_BASE_MS = 2000L
        private const val WARM_GATE_POLL_SPREAD_MS = 2000
        // Between transient re-POSTs of the same send bytes:
        private const val SEND_RETRY_BACKOFF_BASE_MS = 1000L
        private const val SEND_RETRY_BACKOFF_SPREAD_MS = 2000
        // Between consecutive relay requests of one sweep / relay purge (100–400 ms),
        // so a burst has no fixed-interval fingerprint:
        internal const val RELAY_REQUEST_JITTER_BASE_MS = 100L
        internal const val RELAY_REQUEST_JITTER_SPREAD_MS = 300

        /** `base + secureRandomInt(spread)` — the one shape every wait above uses. */
        internal fun jitterMs(baseMs: Long, spreadMs: Int): Long = baseMs + secureRandomInt(spreadMs).toLong()

        // Channel-binding tag. Sealed INSIDE the AEAD envelope, it
        // records which of a pairing's inboxes a static-envelope blob was sent
        // for: "m" (main/text), "c" (control) or "g" (group text). The receiver
        // drops a blob whose tag doesn't match the inbox it actually polled, so a
        // malicious relay cannot move an authentic blob from one inbox to another
        // (the channels keep INDEPENDENT counter spaces, so a cross-inbox splice
        // would otherwise pass the per-channel replay check → duplicate delivery
        // / misrouting). Tag is bound to the inbox ACTUALLY used (the RESOLVED
        // channel, not the requested one), since a pre-v7 peer with no control
        // inbox legitimately carries control on the main inbox and a peer with no
        // group inbox legitimately carries group text there.
        // Legacy senders omit it → the check is skipped (graceful).
        const val CHANNEL_TAG_MAIN = "m"
        const val CHANNEL_TAG_CTL = "c"

        /**
         * Channel tag of the third pairwise inbox pair — GROUP text.
         *
         * `"g"` was free: `ch` only ever held `"m"` or `"c"`, and the receive check
         * is an equality against the inbox we actually polled, so an old build can
         * never see a `"g"` blob (it has no group inbox to poll) and a relay
         * splicing a `"g"` blob onto the TEXT inbox is dropped by the rule that
         * already exists. That drop is a genuine new hardening: it is exactly the
         * move that would light a CONTACT unread dot for a group message.
         */
        const val CHANNEL_TAG_GRP = "g"

        // Direct (non-group) referral control kinds (referral.md). Relayed
        // through the introducer; carry only public keys + inbox offers, so the
        // introducer can't derive the introducees' shared key. Routed to
        // ReferralManager by the platform poller.
        const val CONTROL_KIND_REFERRAL_OFFER  = "ref-offer"
        const val CONTROL_KIND_REFERRAL_ACCEPT = "ref-accept"
        val DIRECT_REFERRAL_KINDS = setOf(CONTROL_KIND_REFERRAL_OFFER, CONTROL_KIND_REFERRAL_ACCEPT)

        /**
         * Direct (non-group) EPHEMERAL notice: "I just took a screenshot of this
         * conversation". Body-less — the pairwise channel it decrypted on IS the
         * attribution, exactly like the group [GroupManager.KIND_ACTIVITY] notice
         * it mirrors. Rides the CONTROL channel (so it never lands in the text
         * inbox the background peek sweep counts) and is applied receive-side into
         * an in-RAM pending list; it is NEVER surfaced as a [ReceivedMessage], so a
         * UI that renders nothing for it cannot show an empty bubble.
         *
         * Wire value is <= 16 chars — the control-kind length cap enforced on
         * receive below.
         */
        const val CONTROL_KIND_SCREENSHOT = "screenshot"

        /**
         * The DIRECT (group-less) control kinds a receiver SURFACES or applies past
         * the "unknown direct control" guard. Single allowlist for BOTH receive
         * paths (the legacy static envelope and the ratchet), so the two can never
         * drift. [CONTROL_KIND_INBOX] is deliberately not here: it is handled ahead
         * of this check at both sites because it mutates vault state.
         *
         * FORWARD COMPAT: anything not in here is DROPPED SILENTLY (a warn log, no
         * bubble, no error, no throw). That is what makes adding a kind safe — a
         * build older than the kind classes it as unknown and drops it, which is
         * exactly what an old build does with [CONTROL_KIND_SCREENSHOT].
         */
        internal fun isKnownDirectControlKind(kind: String): Boolean =
            kind in DIRECT_REFERRAL_KINDS || kind == CONTROL_KIND_SCREENSHOT

        /**
         * Ceiling on UNDRAINED direct screenshot notices held in RAM. A paired peer
         * is authenticated but not trusted: without a bound it could park unbounded
         * notices between two drains. Far above any honest use (a notice is a rare,
         * deliberate user action); the excess is dropped, never queued.
         */
        internal const val MAX_PENDING_SCREENSHOT_NOTICES = 32

        /**
         * CONTROL-channel inbox directions (v7). Each pairing now mints a
         * second inbox pair dedicated to control traffic (group invites/
         * rosters/joins/leaves + inbox announces). Unlike text inboxes —
         * drained only while their conversation is open, because unread
         * texts must stay on the relay — control inboxes are safe to drain
         * ANY time, which is what lets the background poller deliver group
         * invites to every member without anyone opening a conversation.
         * Counter spaces are separate per channel (the two are drained on
         * independent schedules; a shared space would false-reject
         * cross-channel reordering as replays).
         */
        const val DIR_OUTBOUND_CTL = "outbound-ctl"
        const val DIR_INBOUND_CTL  = "inbound-ctl"

        /**
         * GROUP-text inbox directions — the THIRD pairwise pair, minted and
         * announced exactly the way the v7 control pair is.
         *
         * [DIR_OUTBOUND_GRP] is the PEER's group inbox (where we POST their group
         * texts, under the write cap they announced); [DIR_INBOUND_GRP] is OURS
         * (where we poll/peek for theirs, under the read cap we minted).
         *
         * **The presence of the `outbound-grp` row IS the capability signal.**
         * There is deliberately no version number on the wire: a peer that never
         * announced a group inbox is, by construction, a peer whose group texts go
         * to the TEXT inbox — today's behaviour, unchanged. Same rule
         * [sendEnvelopeSerialized] has always used for the control pair.
         *
         * Why a separate inbox at all: `/peek` returns a bare count and every
         * routing field (including the groupId) is sealed inside the AEAD, so "is
         * this queued blob a group text?" was knowable only after a decrypt the
         * unread sweep deliberately never performs. With the two kinds on DIFFERENT
         * inboxes the contact dot is correct BY CONSTRUCTION, with no notice and no
         * ordering dependency.
         */
        const val DIR_OUTBOUND_GRP = "outbound-grp"
        const val DIR_INBOUND_GRP  = "inbound-grp"

        /**
         * The relay's own `maxTtlSeconds` (7 days). Only used to CLAMP an
         * outbound `?ttl` so a caller can never widen retention past what the
         * relay would accept anyway (it coerces server-side) and can never put
         * anything but digits in the URL. Not a policy knob — the per-send
         * choice lives at the call site (see [REFERRAL_CONTROL_TTL_SECONDS]).
         */
        internal const val RELAY_MAX_TTL_SECONDS = 604_800L

        /**
         * The ONE retention value every CONTROL append
         * carries — group control (`GroupManager.membershipControlTtl`), the
         * referral handshake ([REFERRAL_CONTROL_TTL_SECONDS]), the inbox announce
         * and the 1:1 screenshot notice alike.
         *
         * It used to be per-KIND, and the `?ttl` is on the request line in the
         * CLEAR: `?ttl=604800` together with `X-No-Push: 1` was unique to a group
         * ROSTER or LEAVE, so a relay could point at one append and say "this is a
         * membership change to this recipient" without decrypting anything — and
         * then swallow exactly those. A single constant applied to every
         * control append removes the ttl from the classifier; the `X-No-Push` bit
         * that remains is inherent (the relay must be told not to wake the device)
         * and its semantics are deliberately UNCHANGED by this.
         *
         * Do not reintroduce a per-kind ttl. The cost of the uniform value is
         * retention, not confidentiality (the body is AEAD-sealed and padded), and
         * the two staleness consequences are handled where they land:
         * [GroupManager.MAX_ACTIVITY_NOTICE_AGE_MS] ignores an activity notice
         * older than the text retention, and a screenshot notice expires on the
         * RECEIVER's clock ([ScreenshotNoticeStore]).
         */
        internal const val CONTROL_APPEND_TTL_SECONDS = RELAY_MAX_TTL_SECONDS

        /**
         * The relay's own `maxBlobBytes` (64 KiB, `Config.maxBlobBytes`). Only used
         * to refuse an oversize "move to new device" chunk LOCALLY, before half an
         * export is on the wire — the relay refuses it too (413), on both a
         * `Content-Length` pre-check and the buffered body, with a strictly
         * greater-than comparison: a blob of EXACTLY this many bytes is accepted.
         * That is what makes [MoveConstants.CHUNK_PLAINTEXT_BYTES] (60 000) safe —
         * its sealed, padded chunk lands in the 64 KiB bucket, at or under this
         * ceiling. Not a policy knob: message traffic is bounded independently by
         * [MAX_PADDED_PAYLOAD_BYTES] and its padding buckets.
         */
        internal const val MOVE_MAX_BLOB_BYTES = 65_536

        /**
         * Rate limit on the "move freeze: refused …" log line (see [moveFrozen]).
         * A frozen phone whose poll loop outlived the platform teardown would
         * otherwise emit one line per contact per cycle into the in-app log
         * buffer; one line a minute is enough to see the gate is holding.
         */
        internal const val FROZEN_GATE_LOG_INTERVAL_MS = 60_000L

        // Cap the rendered length of a received message. The plaintext is already
        // bounded by the padding bucket (~128 KB), but a pathological single huge
        // line is still costly to lay out — truncate for display so an
        // authenticated peer can't lag/OOM the conversation UI on either platform.
        // Applied at the source so both UIs are covered.
        internal const val MAX_DISPLAY_MESSAGE_CHARS = 16_384
        internal fun capMessageForDisplay(text: String): String =
            if (text.length > MAX_DISPLAY_MESSAGE_CHARS)
                text.take(MAX_DISPLAY_MESSAGE_CHARS) + "…" else text
    }
}

/**
 * Rounds a millisecond timestamp down to the nearest minute boundary.
 * Defeats per-device clock-skew fingerprinting: a series of full-resolution
 * timestamps from the same sender forms a stable hardware fingerprint
 * (PETS 2018 / Murdoch 2005) that uniquely identifies the device. The bubble
 * UI only needs minute-level precision.
 */
internal fun roundTimestampToMinute(ms: Long): Long = (ms / 60_000L) * 60_000L

/**
 * True iff [contactId]'s vault state is from before the capability-protocol
 * migration, or is otherwise unusable. The contact is considered stale if
 * the INBOUND row is missing/invalid, or an OUTBOUND row exists but is
 * legacy/cap-less. A contact with a valid inbound and NO outbound row is NOT
 * stale — that is the instant-QR pairing's pending state (we showed our
 * secret-only code; the peer's inbox arrives via the in-band announce); see
 * [contactAwaitingPeerInbox]. Both [MessageManager.sendMessage] and
 * [MessageManager.pollMessages] refuse to act on stale rows; the UI badges
 * them with "tap to re-pair".
 */
fun contactNeedsRepair(vault: VaultDatabase, contactId: String): Boolean {
    val inbound  = vault.getInboxIdForContact(contactId, "inbound")
    val outbound = vault.getInboxIdForContact(contactId, "outbound")
    if (inbound == null) return true
    if (inbound.cap.isNullOrEmpty() || !isValidInboxId(inbound.inboxId)) return true
    if (outbound != null && (outbound.cap.isNullOrEmpty() || !isValidInboxId(outbound.inboxId))) return true
    return false
}

/**
 * True iff [contactId] is healthy but the peer's inbox has not arrived yet
 * (instant-QR pairing, waiting for the in-band announce). We can RECEIVE
 * from them; sending unlocks the moment the announce lands on a poll.
 */
fun contactAwaitingPeerInbox(vault: VaultDatabase, contactId: String): Boolean =
    !contactNeedsRepair(vault, contactId) &&
        vault.getInboxIdForContact(contactId, "outbound") == null

/**
 * True iff [contactId] is fully paired: healthy AND sendable. Group
 * membership requires this — invites/rosters/texts all need the outbound
 * channel.
 */
fun contactFullyPaired(vault: VaultDatabase, contactId: String): Boolean =
    !contactNeedsRepair(vault, contactId) &&
        vault.getInboxIdForContact(contactId, "outbound") != null

/**
 * Delete [contactId] locally AND destroy its two inbound inboxes on the
 * relay, so a user who deletes a contact does not leave live, drainable inboxes
 * (and a live push-registration target) parked on the relay for the inbox TTL.
 *
 * Ordering is the safety property:
 *
 *  1. SNAPSHOT the (inboxId, readCap) pairs first — the caps live in the rows the
 *     delete is about to erase.
 *  2. `vault.deleteContact` — the LOCAL delete is the gate. It is atomic on both
 *     platforms, so a throw means the contact and its inboxes are still fully
 *     intact and must NOT be relay-deleted (that would destroy a live channel the
 *     user still has). Deliberately not a `finally`.
 *  3. Only then, best-effort relay DELETEs, in CSPRNG-shuffled order with 100–400 ms
 *     jitter — the same traffic discipline [MessageManager.peekUnreadCounts] uses,
 *     so the burst isn't a recognisable "contact deleted" fingerprint.
 *
 * Returns whether the LOCAL delete succeeded; the relay cleanup is best-effort and
 * never gates it (the user's delete is never held hostage to Tor). Never throws —
 * it crosses the Swift bridge.
 *
 * [onLocalDeleted] fires the moment step 2 succeeds, BEFORE the relay round-trips,
 * so the UI can drop the row instantly instead of sitting on a wedged circuit.
 * (iOS drops the row optimistically at the tap and passes nothing.)
 */
fun deleteContactAndPurgeRelay(
    vault: VaultDatabase,
    messageManager: MessageManager?,
    contactId: String,
    onLocalDeleted: (() -> Unit)? = null,
): Boolean {
    val targets = mutableListOf<Pair<String, String>>()
    for (direction in MessageManager.OWNED_READ_DIRECTIONS) {
        val rec = try {
            vault.getInboxIdForContact(contactId, direction)
        } catch (_: Exception) { null } ?: continue
        val cap = rec.cap
        if (!cap.isNullOrEmpty() && isValidInboxId(rec.inboxId) && isValidCapability(cap)) {
            targets.add(rec.inboxId to cap)
        }
    }
    try {
        vault.deleteContact(contactId)
    } catch (e: Exception) {
        platformLogWarn(LOG_TAG, "deleteContact failed — skipping relay cleanup: ${e::class.simpleName}")
        return false
    }
    try { onLocalDeleted?.invoke() } catch (_: Exception) { /* UI hook, never fatal */ }
    if (messageManager == null || targets.isEmpty()) return true
    targets.secureShuffle()
    for ((index, target) in targets.withIndex()) {
        if (index > 0) sleepMillis(MessageManager.jitterMs(MessageManager.RELAY_REQUEST_JITTER_BASE_MS, MessageManager.RELAY_REQUEST_JITTER_SPREAD_MS))
        try {
            messageManager.deleteInbox(target.first, target.second)
        } catch (_: Exception) { /* best effort — the orphan simply expires */ }
    }
    return true
}


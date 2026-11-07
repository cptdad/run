package com.vg.run

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

// ---------------------------------------------------------------------------
// RelayMoveTransport — [MoveTransport] over the live [MessageManager]
// (docs/device-move.md: "one dedicated relay inbox, short TTL, one-shot").
//
// Nothing here is new protocol. Every call bottoms out in one of the four
// `internal` move primitives on MessageManager (postMoveChunk / peekMoveInbox /
// drainMoveInbox / rotateOwnedInboxReadCap) or in an EXISTING public one
// (mintInbox, deleteInbox), which in turn go through the same URL builder,
// header validation and transient-retry discipline as message traffic. The one
// thing this layer adds is the FAIL DIRECTION the move state machine needs:
//
//   * a genuine relay 404 is EVIDENCE (the transfer inbox is gone — drained by
//     the new phone, or expired) and is reported as `null` / an empty list;
//   * everything else that is not a success — 429, 5xx, a dropped Tor
//     round-trip, a locally refused malformed id/cap — is NOT evidence and
//     THROWS [MoveTransportException].
//
// Collapsing those two (which peekOnce/pollChannel deliberately do, because for
// message traffic both mean "nothing to do this cycle") would let a Tor hiccup
// on the old phone read as "the new phone has the bundle" and invite the user to
// wipe a phone whose bundle was never delivered. Keep them apart.
//
// Blocking work (PoW grind, Tor round-trips) is moved off the caller's thread
// here rather than in MessageManager, which is deliberately blocking throughout.
// ---------------------------------------------------------------------------

class RelayMoveTransport(
    /**
     * The live relay client this transport wraps. Exposed (module-internal, so it
     * never reaches the Swift export) for ONE caller: [MoveManager] flips its
     * in-class freeze gate — [MessageManager.setMoveFrozen] — the moment
     * `mig_frozen` is written and again after a successful cancel, so the running
     * instance stops (and resumes) contact-facing traffic immediately instead of
     * waiting for its next vault read. The vault row stays the durable authority.
     */
    internal val messageManager: MessageManager,
) : MoveTransport {

    /**
     * Mints the transfer inbox with the ORDINARY pairing mint — the same PoW
     * budget, the same bounded transient retries, the same abort semantics. Only
     * [MintedInbox.main]-shaped material is needed (one inbox, not a pair), so
     * this is `mintInbox`, not `mintInboxPair`: half the PoW and half the relay
     * footprint of a pairing.
     *
     * Runs on [Dispatchers.Default] like [MessageManager.mintInboxPair] — the
     * grind is CPU-bound, not I/O-bound.
     */
    override suspend fun mintTransferInbox(): MintedInbox = withContext(Dispatchers.Default) {
        messageManager.mintInbox() ?: throw MoveTransportException("transfer inbox mint failed")
    }

    override suspend fun postChunk(
        inboxId: String,
        writeCap: String,
        sealedChunk: ByteArray,
        ttlSeconds: Long,
    ) = withContext(ioDispatcher) {
        val code = messageManager.postMoveChunk(inboxId, writeCap, sealedChunk, ttlSeconds)
        // Code only — a relay error BODY is untrusted text and never enters an
        // exception message that could reach a log or the UI.
        if (code !in 200..299) throw MoveTransportException("chunk upload failed (code=$code)")
    }

    override suspend fun peekPending(inboxId: String, readCap: String): Int? = withContext(ioDispatcher) {
        val r = messageManager.peekMoveInbox(inboxId, readCap)
        when {
            r.code == 404 -> null                    // gone: drained, expired, or cap no longer authenticates
            r.code in 200..299 && r.pending != null -> r.pending
            // A 2xx whose body we could not read says NOTHING about the inbox.
            // It must never fall through to the 404 branch's "null" (= "the new
            // phone has it"), so it throws with everything else that is unknown.
            else -> throw MoveTransportException("peek failed (code=${r.code})")
        }
    }

    override suspend fun drain(inboxId: String, readCap: String): List<ByteArray> = withContext(ioDispatcher) {
        val r = messageManager.drainMoveInbox(inboxId, readCap)
        when {
            r.code == 404 -> emptyList()             // nothing there (already drained / expired / wrong cap)
            r.code in 200..299 -> r.blobs
            else -> throw MoveTransportException("drain failed (code=${r.code})")
        }
    }

    /**
     * Best-effort by design, and NON-THROWING (a narrowing of the interface's
     * "throws on I/O failure" that is safe for every caller, all of which treat
     * the delete as hygiene): every caller has already made its decision from a
     * peek/drain, and a lost DELETE costs only an orphan inbox that dies with its
     * 30-minute TTL. Mirrors [MessageManager.deleteInbox]'s no-retry rationale.
     */
    override suspend fun deleteInbox(inboxId: String, readCap: String) {
        withContext(ioDispatcher) {
            try {
                messageManager.deleteInbox(inboxId, readCap)
            } catch (e: Exception) {
                platformLogWarn("RelayMoveTransport", "transfer inbox delete failed: ${e::class.simpleName}")
            }
            Unit
        }
    }

    override suspend fun rotateReadCap(inboxId: String, currentReadCap: String): String =
        withContext(ioDispatcher) {
            messageManager.rotateOwnedInboxReadCap(inboxId, currentReadCap)
                ?: throw MoveTransportException("read-cap rotation not proven")
        }
}

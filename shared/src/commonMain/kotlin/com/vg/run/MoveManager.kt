package com.vg.run

import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.withTimeoutOrNull

// ---------------------------------------------------------------------------
// MoveManager — "Move to new device", the ORCHESTRATION half (docs/device-move.md,
// area 3). The pure codec/sealing half is MigrationBundle.kt and the vault I/O half
// is VaultSnapshotIo.kt; this file owns the state machine, the freeze, the relay
// choreography and the post-import read-cap rotation.
//
// THE ONE INVARIANT THIS FILE EXISTS TO PROTECT: at no point may the user end up
// with two live copies of one identity, and at no point may a failure leave them
// with none.
//
//   * Two live copies is the fork hazard (docs/device-move.md fact 5): two devices
//     holding the same `dr/<id>/text` chain orphan each other's ratchet into
//     `onCorruptReinit`, i.e. a silent drop to the legacy no-forward-secrecy
//     envelope. Receiving advances the chain too, so the old phone must stop
//     POLLING, not merely stop sending. Hence the freeze, and hence the freeze is
//     written BEFORE the session is torn down and before anything is uploaded.
//   * None is the brick. Nothing in this file ever deletes vault state: the old
//     phone keeps its vault, frozen, until the USER wipes it (D9). Every failure
//     path leaves the vault frozen and intact — never half-erased, never
//     "recovered" by deleting the thing that failed.
//
// SECOND-ORDER RULES, each one load-bearing:
//
//  • The freeze flag is written before any teardown or relay call (only the bounded
//    push unregistration precedes it) and cleared LAST. `mig_frozen` is set before
//    push unregistration's effects can matter, before the session teardown and
//    before any relay call; a cancel clears `mig_handle` first and `mig_frozen`
//    last, so any interruption leaves the SAFE state (frozen) rather than a phone
//    that resumed polling with a live bundle on the relay.
//  • A failure NEVER unfreezes. `Failed` keeps the vault frozen on purpose: the
//    user retries (re-issue) or wipes. Auto-unfreezing on a failed upload is how
//    you get two live copies when the upload actually landed.
//  • `Moved` is DERIVED, never persisted, and it is a HINT, not proof. It is
//    inferred from `peek == 0` or a 404, and a 404 is also what an EXPIRED
//    transfer inbox answers (30-minute TTL). So `Moved` must only ever gate an
//    OFFER to wipe, never a wipe: the UI copy must tell the user to confirm the
//    new phone shows their contacts first. Nothing here wipes anything.
//  • The one-time code is RAM-only, by design (docs/device-move.md 2d). It lives
//    exactly as long as the `Ready` state and is never written to the vault, so a
//    process death costs a re-issue (fresh inbox, fresh code, fresh bundleId) and
//    never leaves a decryptable bundle behind a value an image could recover.
//  • Import is drain-then-commit with everything in RAM. The relay drain is
//    DESTRUCTIVE, so nothing is written until the whole bundle is authenticated
//    and parsed; if the process dies before the commit the bundle is gone, and the
//    recovery is the old phone re-issuing — which is exactly why the old phone
//    keeps its vault (see above).
// ---------------------------------------------------------------------------

/**
 * The old-phone/new-phone move state machine ([MoveManagerApi]).
 *
 * @param vault  the OPEN vault, or null when locked. Read on every call — the
 *   manager holds no vault reference of its own, so a lock/teardown between two
 *   calls degrades to `NOT_UNLOCKED` instead of writing through a dead handle.
 * @param session  the platform session seam ([MoveSessionControl]).
 * @param platformTag  [MigrationBundle.FROM_ANDROID] or [MigrationBundle.FROM_IOS].
 *   Validated at the TOP of an export, before anything is frozen, so a wiring
 *   mistake can never freeze a phone it then cannot export from.
 * @param nowMs  clock seam (bundle `created` stamp only — nothing here makes a
 *   time-based decision, so a wrong clock cannot cause a wipe or a state change).
 */
class MoveManager(
    private val vault: () -> VaultDatabase?,
    private val session: MoveSessionControl,
    private val platformTag: String,
    /**
     * Fresh-credential gate. FAIL-CLOSED: [beginExport] is
     * refused unless a verification was granted on it within
     * [MoveExportAuthGate.FRESH_WINDOW_MS] (single use). The default is a fresh
     * ENFORCING gate, so a construction site that forgets to wire one refuses
     * every export. Production passes its own (so the prompt can grant it);
     * unit tests pass an explicit pre-granted gate.
     */
    val exportAuthGate: MoveExportAuthGate = MoveExportAuthGate(),
    private val nowMs: () -> Long = { currentTimeMillis() },
) : MoveManagerApi {

    companion object {
        private const val TAG = "MoveManager"

        /**
         * `_meta` key (the `mig_` namespace, so [MoveMetaPolicy] already denies it
         * from every export) holding the comma-separated inbox ids whose post-import
         * read-cap rotation has NOT landed yet. Written in full right after the import
         * commits (before the first rotation) and pruned per success, so an
         * interrupted securing pass leaves its tail here. Retried by the control sweep
         * ([retryPendingMoveRotations]). Hardening of D4, never a correctness
         * requirement of the import, so it is bounded and a failed write is only
         * logged.
         *
         * NOT per-contact/per-group state: no residue classifier may match it, and
         * `wipeAllTables` is what erases it (like every other `mig_*` key).
         */
        const val META_ROTATE_PENDING = "mig_rotate_pending"

        /** Bound on [META_ROTATE_PENDING] so a pathological vault cannot grow one unbounded `_meta` row. */
        internal const val MAX_ROTATE_PENDING = 256

        /**
         * Ceiling on the best-effort push unregistration (docs/device-move.md 2a:
         * "wait ≤ 30 s"). It only cuts at a SUSPENSION POINT — the platform's
         * implementation must therefore do its relay I/O on a background dispatcher
         * and be cancellable; a fully blocking implementation would run to its own
         * completion. Either way the result is ignored: an un-evicted push token on
         * the old phone is a metadata leak the new phone closes when it rotates the
         * read caps (D4) and the wipe closes for good.
         */
        internal const val PUSH_UNREGISTER_TIMEOUT_MS = 30_000L

        /** `mig_handle` = `inboxId|readCap|bundleId|chunkCount`. */
        internal fun encodeStoredHandle(inboxId: String, readCap: String, bundleId: String, chunkCount: Int): String =
            "$inboxId|$readCap|$bundleId|$chunkCount"

        /**
         * Strict decode of [MoveMetaKeys.HANDLE]. Every field is shape-validated with
         * the SAME primitives the relay call sites use ([isValidInboxId],
         * [PairingPayload.isValidCap], [MoveHandleCodec.isValidBundleId]), so a
         * corrupted row can never put a control character into an HTTP header or make
         * a URL builder throw. Returns null on anything unreadable — a missing handle
         * is "nothing to peek/cancel", never an error and never a wipe input.
         */
        internal fun decodeStoredHandle(raw: String?): StoredMoveHandle? {
            val parts = (raw ?: return null).split('|')
            if (parts.size != 4) return null
            val (inboxId, readCap, bundleId) = parts
            val count = parts[3].toIntOrNull() ?: return null
            if (!isValidInboxId(inboxId)) return null
            if (!PairingPayload.isValidCap(readCap)) return null
            if (!MoveHandleCodec.isValidBundleId(bundleId)) return null
            if (count < 1 || count > MoveConstants.MAX_CHUNKS) return null
            return StoredMoveHandle(inboxId, readCap, bundleId, count)
        }
    }

    /** The persisted half of a handle — everything except the RAM-only code. */
    internal class StoredMoveHandle(
        val inboxId: String,
        val readCap: String,
        val bundleId: String,
        val chunkCount: Int,
    )

    private val _exportState = MutableStateFlow<MoveExportState>(MoveExportState.Idle)
    override val exportState: StateFlow<MoveExportState> get() = _exportState

    /**
     * The current state as a plain value. `StateFlow` is in the contract, but the
     * project rule is that no coroutines type crosses into Swift — the iOS layer
     * polls this the same way it polls `MessageManager.newerRelayVersion()`.
     */
    fun exportStateNow(): MoveExportState = _exportState.value

    // One move operation at a time. Not a lock held across suspension points (that
    // deadlocks on both actuals' blocking SyncLock) — a flag, so a second tap is
    // dropped with a log rather than queued behind a Tor round-trip.
    private val opLock = SyncLock()
    private var opInFlight = false

    init {
        refreshFrozenState()
    }

    /**
     * Recomputes the initial state from the vault. Idempotent, and only ever moves
     * `Idle → FrozenNoCode`: a platform that builds the manager BEFORE the vault
     * opens (the natural wiring on both platforms) calls this once after unlock so
     * a frozen phone does not present itself as a fresh one. Never downgrades a
     * live state — an in-flight or finished export owns the state from then on.
     */
    fun refreshFrozenState() {
        if (_exportState.value != MoveExportState.Idle) return
        val db = vault() ?: return
        // FrozenNoCode covers BOTH shapes of a frozen vault: with a handle (a bundle
        // is on the relay but its code died with the process) and without one (the
        // freeze landed, the mint/upload did not). Both offer the same two ways out
        // — re-issue or wipe — and `reissueExport` handles the missing handle.
        if (isMoveFrozen(db)) _exportState.value = MoveExportState.FrozenNoCode
    }

    /**
     * Drops the RAM-only one-time code by collapsing `Ready` to `FrozenNoCode`, and
     * a half-run `Preparing` to `Idle` (see the branch comment).
     * Parity with `MessageManager.scrubInMemory` / `GroupManager.scrubInMemory`:
     * called from the platform lock/background teardown, so the Base32 code does not
     * outlive the foreground session that displayed it. (Kotlin strings cannot be
     * zeroed; dropping the reference is what every other in-RAM secret here does.)
     * The vault stays frozen; the user re-issues on the next unlock.
     *
     * Both platforms CANCEL the export/import job immediately before calling this;
     * the two halves ship together, and neither is sufficient alone.
     */
    fun scrubInMemory() {
        exportAuthGate.clear()
        when (_exportState.value) {
            is MoveExportState.Ready -> _exportState.value = MoveExportState.FrozenNoCode
            // The platform CANCELS the export job on the
            // same lock/wipe that calls this, and coroutine cancellation is
            // cooperative — so a half-run export leaves `Preparing` standing. Both
            // UIs render `Preparing` as a bare status line with no buttons under
            // it, and [refreshFrozenState] only ever moves `Idle -> FrozenNoCode`,
            // so that spinner would never resolve for the life of the manager (on
            // Android an in-process re-auth lock keeps the very same instance).
            // `Idle` is the honest resting state: it claims nothing about whether
            // the freeze landed, and the next unlock re-derives that from
            // `mig_frozen` — the durable authority — instead of from a cancelled
            // operation's last published step. `Ready` keeps its FrozenNoCode
            // collapse: there the freeze and the upload are both PROVEN, so only
            // the RAM-only code is lost.
            is MoveExportState.Preparing -> _exportState.value = MoveExportState.Idle
            else -> Unit
        }
    }

    // -----------------------------------------------------------------------
    // Frozen state
    // -----------------------------------------------------------------------

    override fun isFrozen(): Boolean {
        val db = vault() ?: return false
        return isMoveFrozen(db)
    }


    // -----------------------------------------------------------------------
    // Old phone — export
    // -----------------------------------------------------------------------

    override suspend fun beginExport() = runExport(reissue = false)

    override suspend fun reissueExport() = runExport(reissue = true)

    /**
     * Steps a–d of docs/device-move.md §Protocol. [reissue] differs in ONE way: it
     * proceeds from an already-`Ready` transfer (the "Show again" button), where
     * [beginExport] is a deliberate no-op. Both re-run the whole sequence, because a
     * re-issue usually happens in a NEW process where the session is live again and
     * the push registration may have been re-made, and both discard whatever transfer
     * was outstanding before minting a new one.
     *
     * Ordering is the design, so read it as a sequence and not as steps:
     *
     *  1. validate the platform tag — the ONLY thing that can abort before the
     *     freeze, because a bad tag would freeze a phone whose bundle can never
     *     encode;
     *  2. best-effort push unregistration (bounded, failures ignored) — while the
     *     read caps are still ours and before the session goes away;
     *  3. **`mig_frozen` = 1, before any teardown or relay call**. From here this device never
     *     polls or sends again, whatever else fails;
     *  4. TAKE THE TRANSPORT REFERENCE, then quiesce. See [takeTransport] for why
     *     that order and not the reverse;
     *  5. mint → build+seal → upload → persist the handle → `Ready`.
     *
     * Every failure after step 3 lands on `Failed` with the vault STILL FROZEN and
     * intact, and destroys the half-filled transfer inbox best-effort.
     */
    private suspend fun runExport(reissue: Boolean) {
        if (!beginOp()) {
            platformLogWarn(TAG, "export ignored — a move operation is already running")
            return
        }
        try {
            val db = vault()
            if (db == null) {
                fail(MoveError.NOT_UNLOCKED, retryable = false, why = "no open vault")
                return
            }
            if (platformTag != MigrationBundle.FROM_ANDROID && platformTag != MigrationBundle.FROM_IOS) {
                // Wiring bug, caught BEFORE the freeze: the bundle codec would refuse
                // this tag, so freezing first would strand the user on a frozen phone
                // that can never produce a bundle.
                fail(MoveError.UPLOAD_FAILED, retryable = false, why = "invalid platform tag")
                return
            }
            if (!reissue && _exportState.value is MoveExportState.Ready) {
                // A second tap on "Continue". The bundle is already up and the QR is on
                // screen; re-running would mint a second inbox and orphan the first.
                // "Show again" is [reissueExport], which discards it properly.
                platformLog(TAG, "export ignored — a transfer is already Ready")
                return
            }
            // Fresh-credential gate: checked AFTER the cheap
            // no-op above (a stray second tap must not spend the token) and BEFORE
            // anything is unregistered, frozen or uploaded. It binds EVERY export,
            // re-issue included: a re-issue on a frozen phone ("Show again" /
            // Retry) mints a new transfer inbox, uploads a new full-vault bundle and
            // shows a fresh code, so it is as sensitive as the first export. An
            // exemption there would let whoever holds the unlocked frozen phone
            // export the vault without the credential.
            if (!exportAuthGate.consume()) {
                fail(MoveError.NOT_UNLOCKED, retryable = false, why = "export refused — no fresh credential verification")
                return
            }
            // Whatever is outstanding is about to be superseded, so it is discarded on
            // BOTH paths (a retry after a failure, not only an explicit re-issue) —
            // otherwise a re-run leaves a live bundle on the relay with no handle to
            // delete it by. Captured BEFORE the state moves so the RAM handle of a
            // still-Ready transfer is used when the persisted one is missing.
            val previous = currentHandle()

            _exportState.value = MoveExportState.Preparing(MoveExportStep.UNREGISTER_PUSH)
            unregisterPushBestEffort()

            _exportState.value = MoveExportState.Preparing(MoveExportStep.FREEZE)
            try {
                db.putMeta(MoveMetaKeys.FROZEN, "1")
            } catch (e: Throwable) {
                // Nothing has been uploaded and nothing has been torn down, so this is
                // the one failure that leaves the device exactly as it was.
                fail(MoveError.NOT_UNLOCKED, retryable = true, why = "freeze write failed: ${e::class.simpleName}")
                return
            }

            val transport = takeTransport()
            // The freeze is durable now; make it EFFECTIVE on the live relay client
            // in the same breath, before anything else runs. `quiesce` stops the poll
            // loops but deliberately keeps the MessageManager alive (the transfer
            // inbox needs Tor + the HTTP client), and both platforms' 1:1 conversation
            // paths hold that object directly — so without this a conversation screen
            // could still send and advance the sending ratchet chain between here and
            // the wipe. See MessageManager's freeze-gate section.
            applyTransportFreeze(transport, true)
            quiesceQuietly()
            val relay = transport ?: session.transport()
            if (relay == null) {
                fail(MoveError.RELAY_UNREACHABLE, retryable = true, why = "no transport")
                return
            }
            // Covers the case the line above cannot: no transport existed yet at
            // freeze time (Tor still coming up) and one appeared across the quiesce.
            // Idempotent — it only assigns a Boolean field.
            applyTransportFreeze(relay, true)

            if (previous != null) discardPreviousTransfer(db, relay, previous)

            _exportState.value = MoveExportState.Preparing(MoveExportStep.MINT)
            val minted = try {
                relay.mintTransferInbox()
            } catch (e: Exception) {
                rethrowIfCancelled()
                fail(MoveError.MINT_FAILED, retryable = true, why = "mint failed: ${e::class.simpleName}")
                return
            }

            _exportState.value = MoveExportState.Preparing(MoveExportStep.UPLOAD)
            uploadBundle(db, relay, minted)
        } finally {
            endOp()
        }
    }

    /** Builds, seals and uploads the bundle into the freshly [minted] transfer inbox. */
    private suspend fun uploadBundle(db: VaultDatabase, relay: MoveTransport, minted: MintedInbox) {
        val bundleId = MoveHandleCodec.newBundleId()
        var code: ByteArray? = null
        var plaintext: ByteArray? = null
        var chunks: List<ByteArray>? = null
        try {
            val snapshot = try {
                VaultSnapshotIo.export(db)
            } catch (e: Throwable) {
                deleteTransferInbox(relay, minted.inboxId, minted.readCapability)
                fail(MoveError.UPLOAD_FAILED, retryable = true, why = "snapshot export failed: ${e::class.simpleName}")
                return
            }

            plaintext = try {
                MigrationBundleCodec.encode(
                    MigrationBundle(
                        schema = MigrationBundleCodec.CURRENT_SCHEMA,
                        from = platformTag,
                        createdMs = nowMs(),
                        bundleId = bundleId,
                        snapshot = snapshot,
                    )
                )
            } catch (e: Exception) {
                deleteTransferInbox(relay, minted.inboxId, minted.readCapability)
                fail(MoveError.UPLOAD_FAILED, retryable = false, why = "bundle encode failed: ${e::class.simpleName}")
                return
            }

            code = MigrationSeal.newCode()
            chunks = try {
                MigrationSeal.seal(plaintext, code, minted.inboxId, bundleId)
            } catch (e: MigrationSeal.TooLargeException) {
                deleteTransferInbox(relay, minted.inboxId, minted.readCapability)
                fail(MoveError.TOO_LARGE, retryable = false, why = "bundle too large: ${e::class.simpleName}")
                return
            } catch (e: Exception) {
                deleteTransferInbox(relay, minted.inboxId, minted.readCapability)
                fail(MoveError.UPLOAD_FAILED, retryable = false, why = "seal failed: ${e::class.simpleName}")
                return
            }

            for ((index, chunk) in chunks.withIndex()) {
                try {
                    relay.postChunk(
                        minted.inboxId, minted.writeCapability, chunk, MoveConstants.TRANSFER_TTL_SECONDS,
                    )
                } catch (e: Exception) {
                    rethrowIfCancelled()
                    // A half-filled inbox is destroyed rather than left for its TTL: it
                    // holds real (sealed) vault material, and the next attempt mints a
                    // fresh inbox under a fresh code anyway.
                    deleteTransferInbox(relay, minted.inboxId, minted.readCapability)
                    fail(
                        MoveError.UPLOAD_FAILED, retryable = true,
                        why = "chunk ${index + 1}/${chunks.size} failed: ${e::class.simpleName}",
                    )
                    return
                }
            }

            // Persist the handle so a re-launch can still peek/cancel/delete this
            // inbox. Deliberately NON-FATAL: the live `Ready` state carries the full
            // handle in RAM, so this session is complete either way, and the worst
            // case of a lost write is an orphan inbox that dies with its 30-minute
            // TTL while the user re-issues.
            try {
                db.putMeta(
                    MoveMetaKeys.HANDLE,
                    encodeStoredHandle(minted.inboxId, minted.readCapability, bundleId, chunks.size),
                )
            } catch (e: Throwable) {
                platformLogWarn(TAG, "transfer handle persist failed (continuing): ${e::class.simpleName}")
            }

            // The session may have been LOCKED or WIPED
            // while this upload ran. The platform cancels the export job there, but
            // cancellation is cooperative and a blocking POST cannot be cut
            // mid-flight, so this point IS reachable after the platform's scrub has
            // already run. `Ready` is the one state that carries the one-time code,
            // and code + read cap together are a full vault-export credential — it
            // must never be published into a StateFlow that outlives the session.
            // Nothing is lost by refusing: the bundle is on the relay and its handle
            // is in `_meta`, so the phone stays frozen and the next unlock offers
            // "show again" / peek / cancel, exactly as after a process death.
            if (vault() == null) {
                platformLogWarn(TAG, "transfer uploaded but the session is gone — not publishing the code")
                _exportState.value = MoveExportState.FrozenNoCode
                return
            }

            val handle = MoveHandle(
                inboxId = minted.inboxId,
                readCap = minted.readCapability,
                code = MigrationSeal.encodeCode(code),
                bundleId = bundleId,
            )
            platformLog(TAG, "transfer ready: chunks=${chunks.size}")
            _exportState.value = MoveExportState.Ready(handle, chunks.size)
        } finally {
            // The code and the serialized bundle are the two pieces of key/plaintext
            // material this function creates. The SNAPSHOT's shared secrets are
            // deliberately NOT wiped: they are rows read out of the live vault, and a
            // future actual that returned a cached record would have its in-RAM copy
            // zeroed by that "hygiene" — a much worse failure than their lifetime here.
            code?.secureWipe()
            plaintext?.secureWipe()
            chunks?.forEach { it.secureWipe() }
        }
    }

    /**
     * Supersede prelude: forget the outstanding transfer, then destroy it. Runs on
     * every export that finds one — an explicit re-issue AND a retry after a failure.
     *
     * The `_meta` clear comes FIRST and the relay DELETE second, on purpose. The
     * reverse order has a real failure mode: a deleted inbox whose handle survives
     * makes the next `peek` answer 404, which this state machine reads as "the new
     * phone drained it" — a false `Moved`, i.e. an invitation to wipe a phone whose
     * bundle nobody ever received. A surviving inbox with no handle is merely an
     * orphan that expires.
     */
    private suspend fun discardPreviousTransfer(
        db: VaultDatabase,
        relay: MoveTransport,
        stored: StoredMoveHandle,
    ) {
        try {
            db.deleteMeta(MoveMetaKeys.HANDLE)
        } catch (e: Throwable) {
            platformLogWarn(TAG, "re-issue: handle clear failed: ${e::class.simpleName}")
            return   // do NOT delete the inbox while its handle is still recorded
        }
        deleteTransferInbox(relay, stored.inboxId, stored.readCap)
    }

    // -----------------------------------------------------------------------
    // Old phone — waiting, cancelling
    // -----------------------------------------------------------------------

    override suspend fun refreshTransferState() {
        val state = _exportState.value
        if (state !is MoveExportState.Ready && state !is MoveExportState.FrozenNoCode) return
        val handle = currentHandle() ?: return
        val relay = session.transport() ?: return
        val pending = try {
            relay.peekPending(handle.inboxId, handle.readCap)
        } catch (e: Exception) {
            // NOT evidence. A Tor drop / 429 must never read as "the new phone has it".
            platformLogWarn(TAG, "transfer peek failed (state unchanged): ${e::class.simpleName}")
            return
        }
        if (pending == null || pending == 0) {
            platformLog(TAG, "transfer drained (pending=$pending) — Moved")
            _exportState.value = MoveExportState.Moved
        }
    }

    /**
     * Cancels an outstanding transfer and unfreezes — but only against POSITIVE
     * proof that the new phone has not drained the bundle.
     *
     * The proof is `peek >= chunkCount`: a relay drain is all-or-nothing, so a full
     * queue means nobody has read it. `>=` rather than `==` because an upload whose
     * response was lost can leave one byte-identical duplicate blob.
     *
     * Everything else refuses and leaves the state alone, including an unreachable
     * relay — "I could not check" must not unfreeze, because a device that resumes
     * polling while the new phone also has the identity is exactly the two-live-copies
     * fork this feature is built to avoid. The escape hatches from a refused cancel
     * are re-issue and wipe, both always available.
     */
    override suspend fun cancelExport(): Boolean {
        if (!beginOp()) {
            platformLogWarn(TAG, "cancel ignored — a move operation is already running")
            return false
        }
        try {
            val db = vault() ?: return false
            val handle = currentHandle()
            if (handle == null) {
                // Frozen with nothing on the relay (the freeze landed, the upload did
                // not). There is no bundle anyone could have drained, so there is
                // nothing to prove: unfreeze.
                if (!isMoveFrozen(db)) return false
                platformLog(TAG, "cancel: frozen with no outstanding transfer — unfreezing")
                return unfreeze(db)
            }
            val relay = session.transport()
            if (relay == null) {
                platformLogWarn(TAG, "cancel refused — no transport to prove the bundle is undrained")
                return false
            }
            val pending = try {
                relay.peekPending(handle.inboxId, handle.readCap)
            } catch (e: Exception) {
                platformLogWarn(TAG, "cancel refused — peek failed: ${e::class.simpleName}")
                return false
            }
            if (pending == null || pending == 0) {
                platformLog(TAG, "cancel refused — the bundle is already drained/gone")
                _exportState.value = MoveExportState.Moved
                return false
            }
            if (pending < handle.chunkCount) {
                platformLogWarn(
                    TAG,
                    "cancel refused — only $pending of ${handle.chunkCount} chunks are still queued",
                )
                return false
            }
            deleteTransferInbox(relay, handle.inboxId, handle.readCap)
            return unfreeze(db)
        } finally {
            endOp()
        }
    }

    /**
     * Clears the move state and restarts the session. `mig_handle` goes first and
     * `mig_frozen` LAST: an interruption in between leaves the phone frozen with no
     * handle (a re-issue away from usable), never resumed-with-a-live-bundle.
     */
    private suspend fun unfreeze(db: VaultDatabase): Boolean {
        try {
            db.deleteMeta(MoveMetaKeys.HANDLE)
            db.deleteMeta(MoveMetaKeys.FROZEN)
        } catch (e: Throwable) {
            platformLogWarn(TAG, "unfreeze: meta clear failed: ${e::class.simpleName}")
            return false
        }
        _exportState.value = MoveExportState.Idle
        // Mirror of the freeze: the vault no longer says frozen, so clear the live
        // relay client's cached copy BEFORE the session restarts its loops. A
        // platform whose `resume()` builds a FRESH MessageManager needs nothing here
        // (it reads the cleared vault row itself); one that reuses the existing
        // instance would otherwise stay gated for the rest of the session.
        applyTransportFreeze(takeTransport(), false)
        try {
            session.resume()
        } catch (e: Exception) {
            // The vault is already unfrozen and consistent; a failed resume is a
            // session-layer problem the next unlock fixes.
            platformLogWarn(TAG, "session resume failed: ${e::class.simpleName}")
        }
        return true
    }

    // -----------------------------------------------------------------------
    // New phone — import
    // -----------------------------------------------------------------------

    /**
     * Fetch → import → secure, on a freshly provisioned and unlocked vault
     * (docs/device-move.md §Protocol, phone B).
     *
     * The drain is DESTRUCTIVE, so the whole bundle is authenticated, parsed and
     * validated in RAM before a single row is written, and the import itself is one
     * [VaultSnapshotIo.import] transaction that writes [MoveMetaKeys.IMPORTED] last.
     * A crash before that point loses the bundle (the old phone re-issues); a crash
     * after it leaves a complete vault.
     *
     * `SECURING` is best-effort by construction: a rotation failure is recorded for
     * the control sweep to retry and NEVER fails the import — the user has their
     * identity at that point, and refusing it over a hardening step would be the
     * worse outcome by far.
     */
    override suspend fun importFromHandle(
        handle: MoveHandle,
        onProgress: (MoveImportStep) -> Unit,
    ): MoveImportResult {
        if (!beginOp()) {
            platformLogWarn(TAG, "import ignored — a move operation is already running")
            return MoveImportResult.Failure(MoveError.IMPORT_FAILED)
        }
        try {
            val db = vault() ?: return MoveImportResult.Failure(MoveError.NOT_UNLOCKED)
            // Guard FIRST: importing twice would re-apply the +10 000 counter jump and
            // overwrite ratchet state this device has since advanced.
            val alreadyImported = try {
                db.getMeta(MoveMetaKeys.IMPORTED)
            } catch (e: Throwable) {
                platformLogWarn(TAG, "import guard read failed: ${e::class.simpleName}")
                return MoveImportResult.Failure(MoveError.IMPORT_FAILED)
            }
            if (!alreadyImported.isNullOrEmpty()) {
                platformLogWarn(TAG, "import refused — this vault already carries an imported bundle")
                return MoveImportResult.Failure(MoveError.ALREADY_IMPORTED)
            }
            val relay = session.transport()
                ?: return MoveImportResult.Failure(MoveError.RELAY_UNREACHABLE)

            onProgress(MoveImportStep.FETCHING)
            var code: ByteArray? = null
            var plaintext: ByteArray? = null
            var blobs: List<ByteArray> = emptyList()
            try {
                blobs = try {
                    relay.drain(handle.inboxId, handle.readCap)
                } catch (e: Exception) {
                    // BEFORE the commit a cancel (lock / wipe) ENDS the import: nothing
                    // has been written and `mig_imported` is unset, so there is no
                    // result to report. The caller's `finally`s still run.
                    rethrowIfCancelled()
                    platformLogWarn(TAG, "transfer drain failed: ${e::class.simpleName}")
                    return MoveImportResult.Failure(MoveError.RELAY_UNREACHABLE)
                }
                // De-duplicate BYTE-IDENTICAL blobs: an upload whose response was lost
                // is re-POSTed verbatim by the transient retry, so the relay can hold
                // one extra copy of a chunk. Two DISTINCT chunks can never be
                // byte-identical (each carries its own index in the AAD and its own
                // random GCM nonce), so this can only ever remove a true duplicate.
                val unique = dedupeBlobs(blobs)
                if (unique.isEmpty()) {
                    platformLogWarn(TAG, "transfer inbox is empty — bundle gone")
                    return MoveImportResult.Failure(MoveError.BUNDLE_GONE)
                }
                // Structural checks BEFORE the unseal, so the (indistinguishable)
                // authentication failure below can be reported as the code being wrong.
                if (unique.size > MoveConstants.MAX_CHUNKS ||
                    unique.any { it.size != unique[0].size }
                ) {
                    platformLogWarn(TAG, "transfer chunks are structurally invalid")
                    return MoveImportResult.Failure(MoveError.BUNDLE_CORRUPT)
                }

                code = MigrationSeal.decodeCode(handle.code)
                    ?: return MoveImportResult.Failure(MoveError.BAD_CODE)

                plaintext = try {
                    MigrationSeal.open(unique, code, handle.inboxId, handle.bundleId)
                } catch (e: MigrationSeal.SealException) {
                    // Wrong code, tampered chunk, foreign bundle and a truncated set are
                    // cryptographically indistinguishable here (that is the AEAD doing
                    // its job). Reported as BAD_CODE because that is the one cause the
                    // user can act on; the remedy for the others (re-issue on the old
                    // phone) is offered by the same screen.
                    platformLogWarn(TAG, "transfer unseal failed: ${e::class.simpleName}")
                    return MoveImportResult.Failure(MoveError.BAD_CODE)
                } catch (e: Exception) {
                    platformLogWarn(TAG, "transfer unseal errored: ${e::class.simpleName}")
                    return MoveImportResult.Failure(MoveError.BUNDLE_CORRUPT)
                }

                val bundle = try {
                    MigrationBundleCodec.decode(plaintext)
                } catch (e: Exception) {
                    platformLogWarn(TAG, "bundle decode failed: ${e::class.simpleName}")
                    return MoveImportResult.Failure(MoveError.BUNDLE_CORRUPT)
                }
                if (bundle.bundleId != handle.bundleId) {
                    // Belt and braces — the bundleId is already AAD-bound, so this can
                    // only fire on a bundle sealed against a different id than it carries.
                    platformLogWarn(TAG, "bundle id does not match the handle")
                    return MoveImportResult.Failure(MoveError.BUNDLE_CORRUPT)
                }
                if (bundle.schema > MigrationBundleCodec.CURRENT_SCHEMA) {
                    platformLogWarn(
                        TAG,
                        "bundle schema ${bundle.schema} is newer than this build's ${MigrationBundleCodec.CURRENT_SCHEMA}",
                    )
                    return MoveImportResult.Failure(MoveError.SCHEMA_TOO_NEW)
                }

                onProgress(MoveImportStep.IMPORTING)
                try {
                    VaultSnapshotIo.import(db, bundle.snapshot, MoveConstants.COUNTER_JUMP, bundle.bundleId)
                } catch (e: Throwable) {
                    platformLogError(TAG, "import transaction failed: ${e::class.simpleName}")
                    return MoveImportResult.Failure(MoveError.IMPORT_FAILED)
                }

                // The rotation obligation is made durable IMMEDIATELY after the
                // commit, before any network call, so nothing below can lose it.
                val seed = seedRotatePending(db, bundle.snapshot)

                // The bundle is committed: the relay copy is now pure liability.
                deleteTransferInbox(relay, handle.inboxId, handle.readCap)

                onProgress(MoveImportStep.SECURING)
                rotateImportedReadCaps(db, relay, seed)

                platformLog(
                    TAG,
                    "import complete: ${bundle.snapshot.contacts.size} contacts, ${bundle.snapshot.groups.size} groups (from ${bundle.from})",
                )
                return MoveImportResult.Success(
                    contacts = bundle.snapshot.contacts.size,
                    groups = bundle.snapshot.groups.size,
                )
            } finally {
                code?.secureWipe()
                plaintext?.secureWipe()
                blobs.forEach { it.secureWipe() }
            }
        } finally {
            endOp()
        }
    }

    /**
     * Rotate the READ (owner) capability of every inbound / inbound-ctl inbox
     * this device just imported, so a copy of the old phone's vault cannot drain,
     * delete, re-key or push-register on them. Peers are untouched (their WRITE
     * caps are unaffected), so there is no announce and no ratchet step.
     *
     * TWO exclusions, both deliberate:
     *
     *  - **outbound rows** — their `cap` is the PEER's write capability, not ours;
     *  - **inboxes referenced by a `ref_*` record.** A pending referral handshake
     *    embeds a freshly minted inbox PAIR (ids AND caps) inside its `_meta` value,
     *    and finalizing it writes those rows into `inbox_ids` verbatim. Rotating one
     *    now would leave the record holding a dead cap that the finalize then writes
     *    back OVER the rotated one — an inbox the new phone can no longer read. The
     *    match is deliberately crude and conservative: any `ref_`-prefixed `_meta`
     *    VALUE that CONTAINS the 32-character inbox id as a substring protects it.
     *    It over-matches at worst (a skipped rotation, which the wipe of the old
     *    phone covers anyway) and it needs no knowledge of the referral record
     *    layout, so a future field carrying an inbox id is covered automatically.
     *
     * Failures are never fatal. The whole to-rotate list was already written to
     * [META_ROTATE_PENDING] by [seedRotatePending]; each entry is pruned only once
     * its rotation lands, so whatever is left is retried by the control sweep
     * ([retryPendingMoveRotations]).
     */
    private suspend fun rotateImportedReadCaps(
        db: VaultDatabase,
        relay: MoveTransport,
        seed: RotateSeed,
    ) {
        if (!seed.referralScanOk) {
            // The referral scan failed. Fail toward NOT rotating: a rotation we
            // cannot prove is safe (it might belong to a pending referral) is worse
            // than one we defer. The UNFILTERED list is already durable, and
            // [retryPendingMoveRotations] re-runs the same referral filter before
            // it rotates anything, so nothing is lost and nothing unsafe is rotated.
            platformLogWarn(TAG, "securing: deferred — the referral scan failed")
            return
        }
        val remaining = seed.ids.toMutableList()
        var rotated = 0
        for (inboxId in seed.ids) {
            // Read the LIVE row rather than trusting the snapshot: the import has
            // landed, and the cap that must authenticate the rotation is whatever the
            // vault holds now.
            val live = try {
                db.getInboxId(inboxId)
            } catch (e: Throwable) {
                // Ambiguous (a lock can close the vault under this loop): the entry
                // STAYS listed for the control sweep.
                platformLogWarn(TAG, "securing: inbox read failed: ${e::class.simpleName}")
                continue
            }
            val cap = live?.cap
            if (live == null || cap.isNullOrEmpty()) {
                // No row or no cap: nothing to rotate, now or later.
                remaining.remove(inboxId)
                writeRotatePending(db, remaining)
                continue
            }
            val newCap = try {
                relay.rotateReadCap(live.inboxId, cap)
            } catch (e: Exception) {
                // NOT rethrown on a cancel: the import has committed, so a cancellation
                // here defers the rest to the control sweep (the tail stays listed in
                // `mig_rotate_pending`) and the import still returns Success.
                platformLogWarn(TAG, "securing: rotation failed: ${e::class.simpleName}")
                continue
            }
            persistRotatedCap(db, live.inboxId, newCap)
            rotated++
            // Pruned per success, so a process death mid-loop leaves exactly the
            // un-rotated tail listed (a re-rotation of an entry whose prune did not
            // land is harmless: it only rotates a cap this device already owns).
            remaining.remove(inboxId)
            writeRotatePending(db, remaining)
        }
        platformLog(TAG, "securing: rotated $rotated read cap(s), ${remaining.size} deferred")
    }

    private class RotateSeed(val ids: List<String>, val referralScanOk: Boolean)

    // Writes the COMPLETE to-rotate list into [META_ROTATE_PENDING] BEFORE the first
    // rotation, so no interruption (a failed referral scan, a vault closed by a lock
    // mid-loop, a process death during the minutes of Tor round trips) can lose the
    // rotation obligation: whatever is not pruned on success stays listed for the
    // control sweep ([retryPendingMoveRotations]).
    //
    // The list is every imported inbox this device OWNS the read side of
    // ([MessageManager.OWNED_READ_DIRECTIONS]) minus the referral-referenced ones.
    // When the referral scan fails the list is written UNFILTERED and nothing is
    // rotated now; the sweep applies the same filter before any rotation.
    private fun seedRotatePending(db: VaultDatabase, snapshot: VaultSnapshot): RotateSeed {
        val protectedIds = referralReferencedInboxIds(db)
        val ids = mutableListOf<String>()
        for (record in snapshot.inboxes) {
            if (record.direction !in MessageManager.OWNED_READ_DIRECTIONS) continue
            if (!isValidInboxId(record.inboxId)) continue
            if (record.inboxId in ids) continue
            if (protectedIds != null && record.inboxId in protectedIds) {
                platformLog(TAG, "securing: a referral-referenced inbox is not rotated")
                continue
            }
            ids.add(record.inboxId)
        }
        writeRotatePending(db, ids)
        return RotateSeed(ids, referralScanOk = protectedIds != null)
    }

    // -----------------------------------------------------------------------
    // Internals
    // -----------------------------------------------------------------------

    private fun beginOp(): Boolean = opLock.withLock {
        if (opInFlight) false else { opInFlight = true; true }
    }

    private fun endOp() = opLock.withLock { opInFlight = false }

    /**
     * Called first in a broad `catch` around a suspend call: rethrows when THIS
     * coroutine was cancelled (the platform cancels the move job on lock /
     * background / wipe), so a cancel ends the operation instead of being reported
     * as a retryable failure and running on. A CancellationException that is not
     * ours (an inner timeout, with this job still active) falls through and is
     * handled as the ordinary failure it always was.
     *
     * The EXPORT calls it everywhere. The IMPORT rethrows BEFORE its commit only
     * (the transfer drain): after the commit the identity and the pending rotations
     * are saved, so a cancel there is swallowed and the import still returns
     * Success. The cancel and refresh paths still map a cancel to their no-op
     * result (both fail toward "state unchanged").
     */
    private suspend fun rethrowIfCancelled() = currentCoroutineContext().ensureActive()

    private fun fail(error: MoveError, retryable: Boolean, why: String) {
        // The vault stays frozen on every one of these paths — see the file header.
        platformLogWarn(TAG, "export failed ($error, retryable=$retryable): $why")
        _exportState.value = MoveExportState.Failed(error, retryable)
    }

    private suspend fun unregisterPushBestEffort() {
        try {
            val done = withTimeoutOrNull(PUSH_UNREGISTER_TIMEOUT_MS) {
                session.unregisterPushBestEffort()
                true
            }
            if (done == null) platformLogWarn(TAG, "push unregistration timed out — continuing")
        } catch (e: Exception) {
            // A cancel here must END the export: swallowing it would go on to
            // write `mig_frozen` for a session the user has already locked.
            rethrowIfCancelled()
            platformLogWarn(TAG, "push unregistration failed — continuing: ${e::class.simpleName}")
        }
    }

    /**
     * Takes the transport reference BEFORE [MoveSessionControl.quiesce], and this
     * ordering is a contract, not a convenience.
     *
     * `quiesce()` is defined as "stop every poll loop and DROP the MessageManager so
     * no ratchet step can happen afterwards" — and a platform that literally drops
     * its `messageManager` reference makes `session.transport()` answer null from
     * then on. Holding the reference across the quiesce works under BOTH readings:
     * a platform that keeps its transport alive still answers, and one that drops it
     * cannot strand the export. The object stays usable because a MessageManager is
     * a stateless-ish relay client over the Tor SOCKS port.
     *
     * What quiesce must therefore NOT do — and what the platform implementations
     * have to honour: it must not stop Tor and must not close the HTTP client. It
     * stops the CONTACT-FACING use (poll loops, sends, the control sweep); the
     * transfer inbox belongs to no contact and touches no ratchet, so nothing about
     * keeping it alive can advance a chain.
     *
     * Since the freeze gate moved INSIDE MessageManager ([applyTransportFreeze] /
     * [MessageManager.setMoveFrozen]), quiesce is no longer the thing that makes
     * that true: a kept-alive MessageManager refuses every contact-facing send,
     * poll and peek on its own. Quiesce is now purely about stopping the loops that
     * would otherwise spin against a gate.
     *
     * (`session.transport()` is re-tried after the quiesce for the case where Tor
     * had not come up yet at this point.)
     */
    private fun takeTransport(): MoveTransport? = try {
        session.transport()
    } catch (e: Exception) {
        platformLogWarn(TAG, "transport lookup failed: ${e::class.simpleName}")
        null
    }

    /**
     * Pushes the freeze decision into the LIVE relay client so
     * [MessageManager]'s in-class gate takes effect at once rather than at its
     * next vault read.
     *
     * It is an ACCELERATOR, never the authority: `mig_frozen` in the vault is what
     * a relaunch, a Tor-reconnect rebuild and every other reader consult, and the
     * MessageManager reads it itself on first use. So a null transport, or a
     * [MoveTransport] that is not a [RelayMoveTransport] (the commonTest doubles),
     * is simply skipped — there is no MessageManager to gate and nothing is lost.
     */
    private fun applyTransportFreeze(transport: MoveTransport?, frozen: Boolean) {
        (transport as? RelayMoveTransport)?.messageManager?.setMoveFrozen(frozen)
    }

    private suspend fun quiesceQuietly() {
        try {
            session.quiesce()
        } catch (e: Exception) {
            rethrowIfCancelled()
            // Already frozen: the durable half of the teardown has landed, and the
            // SessionManagers freeze gate stops polling regardless of this call.
            platformLogWarn(TAG, "session quiesce failed (vault is frozen regardless): ${e::class.simpleName}")
        }
    }

    /** The live handle: the RAM one while `Ready`, else the persisted one. */
    private fun currentHandle(): StoredMoveHandle? {
        val state = _exportState.value
        if (state is MoveExportState.Ready) {
            return StoredMoveHandle(
                state.handle.inboxId, state.handle.readCap, state.handle.bundleId, state.chunkCount,
            )
        }
        val db = vault() ?: return null
        return decodeStoredHandle(readMetaOrNull(db, MoveMetaKeys.HANDLE))
    }

    private suspend fun deleteTransferInbox(relay: MoveTransport, inboxId: String, readCap: String) {
        try {
            relay.deleteInbox(inboxId, readCap)
        } catch (e: Exception) {
            // Best effort by design: the inbox expires with its 30-minute TTL, and the
            // one-time code that could open it is RAM-only.
            platformLogWarn(TAG, "transfer inbox delete failed: ${e::class.simpleName}")
        }
    }

    private fun persistRotatedCap(db: VaultDatabase, inboxId: String, newCap: String) {
        // The production transport (RelayMoveTransport → the read-cap rotate) has already
        // committed this cap onto the row, so the common case is a no-op read. The
        // write is here so the manager is correct against ANY MoveTransport, and it
        // re-reads live to avoid resurrecting a row deleted meanwhile.
        try {
            val live = db.getInboxId(inboxId) ?: return
            if (live.cap == newCap) return
            db.insertInboxId(live.copy(cap = newCap))
        } catch (e: Throwable) {
            platformLogWarn(TAG, "securing: cap persist failed: ${e::class.simpleName}")
        }
    }

    private fun writeRotatePending(db: VaultDatabase, ids: List<String>) {
        try {
            if (ids.isEmpty()) db.deleteMeta(META_ROTATE_PENDING)
            else db.putMeta(META_ROTATE_PENDING, ids.take(MAX_ROTATE_PENDING).joinToString(","))
        } catch (e: Throwable) {
            platformLogWarn(TAG, "securing: pending-rotation list write failed: ${e::class.simpleName}")
        }
    }

    private fun readMetaOrNull(db: VaultDatabase, key: String): String? = try {
        db.getMeta(key)
    } catch (e: Throwable) {
        platformLogWarn(TAG, "meta read failed for $key: ${e::class.simpleName}")
        null
    }

    private fun dedupeBlobs(blobs: List<ByteArray>): List<ByteArray> {
        val out = ArrayList<ByteArray>(blobs.size)
        for (b in blobs) {
            if (out.none { it.size == b.size && it.contentEquals(b) }) out.add(b)
        }
        return out
    }
}

/**
 * The single cheap "is this device the OLD phone of a move?" probe, shared by
 * [MoveManager.isFrozen] and the session gate in SessionManagers.kt.
 *
 * FAILS TOWARD FROZEN on a read error. The two wrong answers are not symmetric: a
 * false "not frozen" resumes polling on a device whose identity may already live on
 * another phone (the ratchet fork this whole feature is designed to prevent), while
 * a false "frozen" merely pauses this poll cycle and self-heals on the next call.
 * The same direction, and for the same reason, as `isConfigured()`'s fail-toward-true.
 */
internal fun isMoveFrozen(db: VaultDatabase): Boolean = try {
    db.getMeta(MoveMetaKeys.FROZEN) == "1"
} catch (e: Throwable) {
    // A closed vault (session teardown — the composition can still ask once more
    // after lockSession closed it) is not a fault; still frozen, just quiet.
    if (db.isOpen) platformLogWarn("MoveManager", "frozen probe failed — treating as frozen: ${e::class.simpleName}")
    true
}

// See [MoveManager]'s `rotateImportedReadCaps` — a conservative substring match over
// every `ref_*` `_meta` VALUE. Returns null when the scan could not be completed,
// which every caller reads as "rotate nothing this pass". Shared by the import pass
// and [retryPendingMoveRotations], so a listed inbox is filtered identically on both.
internal fun referralReferencedInboxIds(db: VaultDatabase): Set<String>? {
    val values = mutableListOf<String>()
    try {
        for (key in db.metaKeys()) {
            if (!key.startsWith(ReferralMetaKeys.PREFIX)) continue
            db.getMeta(key)?.let { values.add(it) }
        }
    } catch (e: Throwable) {
        platformLogWarn("MoveManager", "securing: referral scan failed: ${e::class.simpleName}")
        return null
    }
    if (values.isEmpty()) return emptySet()
    val inboxes = try {
        db.getAllInboxIds()
    } catch (e: Throwable) {
        platformLogWarn("MoveManager", "securing: inbox enumeration failed: ${e::class.simpleName}")
        return null
    }
    val out = mutableSetOf<String>()
    for (record in inboxes) {
        if (values.any { it.contains(record.inboxId) }) out.add(record.inboxId)
    }
    return out
}

/**
 * Control-sweep retry of the post-import read-cap rotations that did not land
 * ([MoveManager.META_ROTATE_PENDING]). Cheap-gated: one `_meta` read in the steady
 * state, zero network calls, and it returns immediately without a transport.
 *
 * The list may have been written UNFILTERED (the import's referral scan failed), so
 * the same [referralReferencedInboxIds] filter runs here before any rotation: a
 * referral-referenced entry is dropped (never rotated, exactly as at import), and a
 * failed scan rotates NOTHING and leaves the list untouched for the next sweep.
 *
 * Blocking (vault + relay I/O) — it rides the control sweep, which already runs on a
 * background dispatcher with a live transport. Never throws: this is hardening, and
 * an exception escaping here would break the sweep that carries the referral redrives
 * and the group-membership redrive with it.
 */
internal fun retryPendingMoveRotations(vault: VaultDatabase, messageManager: MessageManager?) {
    val raw = try {
        vault.getMeta(MoveManager.META_ROTATE_PENDING)
    } catch (_: Throwable) { null }
    if (raw.isNullOrEmpty()) return
    val mm = messageManager ?: return
    val protectedIds = referralReferencedInboxIds(vault) ?: return   // fail toward NOT rotating
    val remaining = mutableListOf<String>()
    for (inboxId in raw.split(',')) {
        if (inboxId.isEmpty()) continue
        if (!isValidInboxId(inboxId)) continue          // drop unusable entries
        if (inboxId in protectedIds) continue           // referral-referenced — never rotated
        val cap = try {
            vault.getInboxId(inboxId)?.cap
        } catch (_: Throwable) {
            // Ambiguous read (vault closing): keep the entry for a later sweep.
            if (remaining.size < MoveManager.MAX_ROTATE_PENDING) remaining.add(inboxId)
            continue
        }
        if (cap.isNullOrEmpty()) continue               // row gone (contact deleted) — nothing to rotate
        val rotated = try {
            mm.rotateOwnedInboxReadCap(inboxId, cap)
        } catch (e: Exception) {
            platformLogWarn("MoveManager", "pending rotation threw: ${e::class.simpleName}")
            null
        }
        if (rotated == null && remaining.size < MoveManager.MAX_ROTATE_PENDING) remaining.add(inboxId)
    }
    try {
        if (remaining.isEmpty()) vault.deleteMeta(MoveManager.META_ROTATE_PENDING)
        else vault.putMeta(MoveManager.META_ROTATE_PENDING, remaining.joinToString(","))
    } catch (e: Throwable) {
        platformLogWarn("MoveManager", "pending-rotation list update failed: ${e::class.simpleName}")
    }
}

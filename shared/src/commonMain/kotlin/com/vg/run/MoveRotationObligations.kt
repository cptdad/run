package com.vg.run

import kotlinx.coroutines.delay

// ---------------------------------------------------------------------------
// MoveRotationObligations — the NEW phone's post-import read-cap rotation
// obligations (docs/device-move.md D4, docs/vault-relay-internals.md §Move).
//
// The read capability is the inbox OWNER capability (drain, delete, rotate,
// push). After a move the old phone's vault still holds every one of them, so the
// new phone rotates each owned inbox's read cap through the existing crash-safe
// `rotateReadCap` / `cap-pend` / peek-reconcile path
// ([MessageManager.rotateOwnedInboxReadCap], unchanged here). This file owns WHICH
// inboxes are owed a rotation and how that obligation survives every interruption:
//
//  1. The obligation set is a PURE function of the imported snapshot
//     ([moveRotationObligations]) and is written INSIDE the import transaction,
//     before `mig_imported` ([VaultSnapshotIo.import]). Reopening the store
//     therefore shows either no committed import, or a committed import with every
//     obligation. A failed obligation write rolls the whole import back.
//  2. No cap on the list: the set is bounded by the bundle. The background pass after
//     the import works through the whole list in batches ([IMPORT_BUDGET]), trying each
//     entry once; the control sweep is bounded ([SWEEP_BUDGET] rotations,
//     [MAX_CLASSIFY_PER_PASS] entries looked at). An entry whose rotation was not
//     confirmed goes to the BACK, so a failing head can never starve the tail.
//  2b. An export takes the pass slot before it freezes ([claimForExport]) and every
//     pass re-checks that request and the freeze before EACH rotation, so no rotation
//     is ever in flight across the freeze and the export snapshot.
//  3. Every list mutation is a short re-read-modify-write under [listLock]
//     (never held across relay I/O), and at most one pass runs per process
//     ([tryBeginPass]), so the import's own pass and the control sweep can never
//     write a stale copy over each other.
//  4. Exclusions are explicit verdicts ([MoveRotationVerdict]) counted per kind, and
//     an entry is DROPPED only on positive evidence: an absent row needs an open,
//     answering vault, so a lock (iOS reads a closed vault as "no rows") can never
//     silently delete an obligation.
//  5. A phone that imported on an OLDER build (obligations written after the
//     commit, truncated at 256, referral inboxes never listed) gets ONE re-rotation
//     of every owned inbox ([maybeReseedPreFixImport]): marker-gated, written in one
//     transaction, drained by the same bounded sweep. Nothing records "done": the
//     move is secured only when the marker is present AND the list is empty
//     ([moveSecuringState]).
// ---------------------------------------------------------------------------

/** What one listed entry is, decided from the live vault at pass time. */
internal enum class MoveRotationVerdict {
    /** An owned, operational row with a cap: rotate it. */
    ROTATE,
    /** Named by a live `ref_*` record (a referral still pending): kept, rotated after finalize. */
    DEFER_REFERRAL,
    /** A read was ambiguous (vault closing, read error): kept, retried later. */
    KEEP_UNKNOWN,
    /** Not an inbox id at all (a corrupt entry). */
    DROP_INVALID,
    /** No row, positively (open, answering vault): the contact was deleted, or a referral expired before finalize. */
    DROP_NO_ROW,
    /** The row is not one of ours to rotate (an outbound row holds the PEER's write cap). */
    DROP_NOT_OWNED,
    /** The row has no cap: there is nothing an old copy could hold. */
    DROP_NO_CAP,
    /**
     * A superseded owned row (an older inbox of the same contact and direction). The
     * rotation path can only rotate the operational row, so this is a documented
     * exclusion, not a failure.
     */
    DROP_SUPERSEDED,
}

/** Counts for one pass — numbers only, for the log line and the tests. */
internal class MoveRotationPassReport {
    /** True when the pass did nothing at all (another pass running, list or referral scan unreadable). */
    var skipped = false
    var attempted = 0
    var rotated = 0
    var failed = 0
    var deferredReferral = 0
    var keptUnknown = 0
    val dropped = mutableMapOf<MoveRotationVerdict, Int>()
    fun droppedTotal(): Int = dropped.values.sum()
}

/** One entry the pass will spend a rotation on, with the cap read from the live row. */
internal class MoveRotationCandidate(val inboxId: String, val cap: String)

internal object MoveRotation {
    private const val TAG = "MoveRotation"

    /** [MoveMetaKeys.ROTATE_VERSION] value meaning "the list holds the complete set". */
    const val VERSION = "2"

    /**
     * Batch size of the background pass right after the import. That pass loops batch
     * after batch until only unconfirmed / deferred entries remain (each entry tried
     * once per pass); only the control sweep is held to [SWEEP_BUDGET].
     */
    const val IMPORT_BUDGET = 16

    /** Rotations one control sweep may spend (the sweep also carries the redrives). */
    const val SWEEP_BUDGET = 4

    /** Entries one pass looks at, so classification work is bounded too. */
    const val MAX_CLASSIFY_PER_PASS = 64

    // Held only for a re-read + one write, never across relay I/O or a pass, and
    // never nested (the iOS actual is a non-reentrant NSLock).
    private val listLock = SyncLock()

    private val passLock = SyncLock()
    private var passInFlight = false
    private var stopRequests = 0

    /** At most one pass per process; a second caller skips. */
    fun tryBeginPass(): Boolean = passLock.withLock {
        if (passInFlight) false else { passInFlight = true; true }
    }

    fun endPass() = passLock.withLock { passInFlight = false }

    /** True while an export is waiting for the pass slot: a running pass stops before its next rotation. */
    fun stopRequested(): Boolean = passLock.withLock { stopRequests > 0 }

    /** Re-checked before EVERY rotation: an export asked for the slot, or the vault is frozen (fails toward frozen). */
    fun mustStop(db: VaultDatabase): Boolean = stopRequested() || isMoveFrozen(db)

    /**
     * For [MoveManager]'s export, BEFORE it writes `mig_frozen`: asks any running pass
     * to stop at its next rotation boundary, waits for the rotation in flight to finish
     * (a blocking relay call cannot be cut), and then HOLDS the pass slot. The caller
     * writes the freeze and only then calls [endPass]. Every later pass re-checks the
     * freeze before each rotation, so from the moment this returns true no read-cap
     * rotation can be in flight across the freeze or the snapshot that follows it — a
     * rotation landing between the snapshot's reads would ship a cap the relay no
     * longer honours. False after [maxWaitMs]: nothing was claimed and the caller must
     * not freeze.
     */
    suspend fun claimForExport(maxWaitMs: Long = EXPORT_CLAIM_MAX_WAIT_MS): Boolean {
        passLock.withLock { stopRequests++ }
        try {
            var waited = 0L
            while (true) {
                if (tryBeginPass()) return true
                if (waited >= maxWaitMs) return false
                delay(EXPORT_CLAIM_POLL_MS)
                waited += EXPORT_CLAIM_POLL_MS
            }
        } finally {
            passLock.withLock { stopRequests-- }
        }
    }

    /** One rotation is a handful of relay calls; this bounds the export's wait for it. */
    const val EXPORT_CLAIM_MAX_WAIT_MS = 300_000L
    private const val EXPORT_CLAIM_POLL_MS = 100L

    // -----------------------------------------------------------------------
    // List codec — the grammar older builds wrote (comma-separated inbox ids).
    // -----------------------------------------------------------------------

    fun encode(ids: List<String>): String = ids.joinToString(",")

    /** Order-preserving, de-duplicated; anything that is not an inbox id is skipped. */
    fun decode(raw: String?): List<String> {
        if (raw.isNullOrEmpty()) return emptyList()
        val out = LinkedHashSet<String>()
        for (part in raw.split(',')) if (isValidInboxId(part)) out.add(part)
        return out.toList()
    }

    /**
     * The raw entries in stored order, invalid ones included (so a pass can account
     * for them). Null when the read threw.
     */
    private fun readRaw(db: VaultDatabase): List<String>? = try {
        val raw = db.getMeta(MoveMetaKeys.ROTATE_PENDING)
        if (raw.isNullOrEmpty()) emptyList() else raw.split(',').filter { it.isNotEmpty() }.distinct()
    } catch (e: Throwable) {
        platformLogWarn(TAG, "pending list read failed: ${e::class.simpleName}")
        null
    }

    /**
     * Re-reads the stored list under [listLock], applies [change] to the FRESH copy
     * and writes it back (deleting the key when empty). Entries another writer added
     * or removed in between are therefore preserved. False when the read or the
     * write failed — the stored list is then unchanged.
     */
    private fun mutate(db: VaultDatabase, change: (MutableList<String>) -> Unit): Boolean = listLock.withLock {
        val current = readRaw(db) ?: return@withLock false
        val next = current.toMutableList()
        change(next)
        if (next == current) return@withLock true
        try {
            if (next.isEmpty()) db.deleteMeta(MoveMetaKeys.ROTATE_PENDING)
            else db.putMeta(MoveMetaKeys.ROTATE_PENDING, encode(next))
            true
        } catch (e: Throwable) {
            platformLogWarn(TAG, "pending list write failed: ${e::class.simpleName}")
            false
        }
    }

    /** A confirmed rotation (or a legitimate exclusion): the entry leaves the list. */
    fun settleConfirmed(db: VaultDatabase, inboxId: String) {
        mutate(db) { list -> list.remove(inboxId) }
    }

    /** Not confirmed: the entry goes to the back so the rest of the list gets its turn. */
    fun settleFailed(db: VaultDatabase, inboxId: String) {
        mutate(db) { list -> if (list.remove(inboxId)) list.add(inboxId) }
    }

    // -----------------------------------------------------------------------
    // Classification
    // -----------------------------------------------------------------------

    /**
     * Candidate ids that appear as a substring of any `ref_*` `_meta` VALUE. Crude
     * and conservative on purpose (no knowledge of the record layouts, so a future
     * field carrying an inbox id is covered): it over-matches at worst, which only
     * DEFERS a rotation. Deliberately NOT intersected with `inbox_ids`: a pending
     * introduction's minted inboxes have no row until finalize, and they are exactly
     * the ones that must wait. Null when the scan could not be completed — callers
     * then rotate nothing this pass.
     */
    fun referralReferencedIds(db: VaultDatabase, candidates: Collection<String>): Set<String>? {
        if (candidates.isEmpty()) return emptySet()
        val values = mutableListOf<String>()
        try {
            for (key in db.metaKeys()) {
                if (!key.startsWith(ReferralMetaKeys.PREFIX)) continue
                db.getMeta(key)?.let { values.add(it) }
            }
        } catch (e: Throwable) {
            platformLogWarn(TAG, "referral scan failed: ${e::class.simpleName}")
            return null
        }
        if (values.isEmpty()) return emptySet()
        return candidates.filterTo(mutableSetOf()) { id -> values.any { it.contains(id) } }
    }

    /**
     * The verdict for one entry, from the LIVE vault. Positive evidence only for a
     * drop: an absent row counts as absent only when a second read agrees, the vault
     * is still open AND it still answers `mig_imported` (the iOS bridge answers an
     * empty result for a query error, and a closed iOS vault reads as "no rows").
     */
    fun classify(db: VaultDatabase, inboxId: String, referenced: Set<String>): Pair<MoveRotationVerdict, String?> {
        if (!isValidInboxId(inboxId)) return MoveRotationVerdict.DROP_INVALID to null
        if (inboxId in referenced) return MoveRotationVerdict.DEFER_REFERRAL to null
        val rec = try {
            db.getInboxId(inboxId)
        } catch (_: Throwable) {
            return MoveRotationVerdict.KEEP_UNKNOWN to null
        }
        if (rec == null) {
            return if (absenceProven(db, inboxId)) MoveRotationVerdict.DROP_NO_ROW to null
            else MoveRotationVerdict.KEEP_UNKNOWN to null
        }
        if (rec.direction !in MessageManager.OWNED_READ_DIRECTIONS) return MoveRotationVerdict.DROP_NOT_OWNED to null
        val cap = rec.cap
        if (cap.isNullOrEmpty()) return MoveRotationVerdict.DROP_NO_CAP to null
        val operational = try {
            // The operational lookup can answer EMPTY on an iOS query error; then
            // derive the same choice from the full row set (the shared chooser both
            // actuals use), so a transient miss is not a permanent "unknown".
            db.getInboxIdForContact(rec.contactId, rec.direction)
                ?: selectOperationalInbox(
                    db.getAllInboxIds().filter { it.contactId == rec.contactId && it.direction == rec.direction },
                )
        } catch (_: Throwable) {
            return MoveRotationVerdict.KEEP_UNKNOWN to null
        } ?: return MoveRotationVerdict.KEEP_UNKNOWN to null
        if (operational.inboxId != rec.inboxId) return MoveRotationVerdict.DROP_SUPERSEDED to null
        return MoveRotationVerdict.ROTATE to cap
    }

    /**
     * Absent only with a witness from ANOTHER query: the full row set answers and does
     * not contain the id (an error confined to the primary-key lookup cannot fake
     * that), or — for a vault with no inbox row at all — the contact table answers
     * empty too. Plus an open vault that still answers `mig_imported`.
     */
    private fun absenceProven(db: VaultDatabase, inboxId: String): Boolean = try {
        db.isOpen &&
            db.getInboxId(inboxId) == null &&
            !db.getMeta(MoveMetaKeys.IMPORTED).isNullOrEmpty() &&
            db.getAllInboxIds().let { all ->
                if (all.isNotEmpty()) all.none { it.inboxId == inboxId } else db.getAllContacts().isEmpty()
            } &&
            db.isOpen
    } catch (_: Throwable) {
        false
    }

    // -----------------------------------------------------------------------
    // One bounded pass, split into a blocking PLAN and per-entry SETTLE calls so
    // the blocking control sweep and the suspending import-side pass share them.
    // -----------------------------------------------------------------------

    /**
     * Looks at no more than [MAX_CLASSIFY_PER_PASS] entries from the head of the list
     * and returns at most [budget] rotation candidates. Drops are removed and
     * deferred / ambiguous entries are moved to the back in ONE locked mutation, so
     * they cost no network call and never block the head. Returns an empty list
     * (with [MoveRotationPassReport.skipped]) when the list or the referral scan is
     * unreadable — nothing is mutated then.
     */
    fun plan(db: VaultDatabase, budget: Int, report: MoveRotationPassReport): List<MoveRotationCandidate> {
        val raw = readRaw(db)
        if (raw == null) {
            report.skipped = true
            return emptyList()
        }
        if (raw.isEmpty()) return emptyList()
        val window = raw.take(MAX_CLASSIFY_PER_PASS)
        val referenced = referralReferencedIds(db, window)
        if (referenced == null) {
            // Fail toward NOT rotating: a rotation we cannot prove is safe (it might
            // belong to a pending referral) is worse than one we defer. Nothing lost.
            report.skipped = true
            return emptyList()
        }
        val candidates = mutableListOf<MoveRotationCandidate>()
        val drop = mutableSetOf<String>()
        val toBack = mutableListOf<String>()
        for (id in window) {
            if (candidates.size >= budget) break
            val (verdict, cap) = classify(db, id, referenced)
            when (verdict) {
                MoveRotationVerdict.ROTATE -> candidates.add(MoveRotationCandidate(id, cap!!))
                MoveRotationVerdict.DEFER_REFERRAL -> { report.deferredReferral++; toBack.add(id) }
                MoveRotationVerdict.KEEP_UNKNOWN -> { report.keptUnknown++; toBack.add(id) }
                else -> {
                    report.dropped[verdict] = (report.dropped[verdict] ?: 0) + 1
                    drop.add(id)
                }
            }
        }
        if (drop.isNotEmpty() || toBack.isNotEmpty()) {
            mutate(db) { list ->
                list.removeAll { it in drop }
                for (id in toBack) if (list.remove(id)) list.add(id)
            }
        }
        return candidates
    }

    /**
     * The blocking pass the control sweep runs: plan, then one rotation per
     * candidate through [rotate] (null or a throw = not confirmed), each settled
     * on its own. Skips when another pass is already running.
     */
    fun runPassBlocking(
        db: VaultDatabase,
        budget: Int,
        rotate: (inboxId: String, cap: String) -> String?,
    ): MoveRotationPassReport {
        val report = MoveRotationPassReport()
        if (!tryBeginPass()) {
            report.skipped = true
            return report
        }
        try {
            for (c in plan(db, budget, report)) {
                if (mustStop(db)) break
                report.attempted++
                val newCap = try {
                    rotate(c.inboxId, c.cap)
                } catch (e: Exception) {
                    platformLogWarn(TAG, "rotation threw: ${e::class.simpleName}")
                    null
                }
                if (newCap.isNullOrEmpty()) {
                    report.failed++
                    settleFailed(db, c.inboxId)
                } else {
                    report.rotated++
                    settleConfirmed(db, c.inboxId)
                }
            }
        } finally {
            endPass()
        }
        logReport("sweep", report)
        return report
    }

    fun logReport(where: String, r: MoveRotationPassReport) {
        if (r.skipped && r.attempted == 0) return
        if (r.attempted == 0 && r.deferredReferral == 0 && r.keptUnknown == 0 && r.droppedTotal() == 0) return
        platformLog(
            TAG,
            "$where pass: rotated ${r.rotated}, not confirmed ${r.failed}, referral-deferred ${r.deferredReferral}, " +
                "unknown ${r.keptUnknown}, excluded ${r.droppedTotal()}",
        )
    }

    // -----------------------------------------------------------------------
    // Phones that imported on an older build
    // -----------------------------------------------------------------------

    /**
     * One-time re-rotation for a vault that carries `mig_imported` but no
     * [MoveMetaKeys.ROTATE_VERSION] — i.e. it imported on a build that wrote its
     * obligations after the commit (lost on an interruption) and truncated them at
     * 256, and never listed the inboxes a pending referral had minted. Writes, in ONE
     * transaction, list := (whatever the old build left listed) ∪ every owned inbox
     * row ∪ the inboxes named by live `ref_p` records, plus the marker. Every owned
     * inbox is re-rotated, including ones the old build already rotated: their
     * rotation cannot be told apart from one that was lost, and a second rotation of
     * a cap this device owns is harmless (the crash-safe path).
     *
     * Idempotent (the marker gates it, re-checked inside the transaction), survives
     * process death (nothing is written until the transaction commits; the next
     * sweep simply tries again), and on ANY ambiguous read it does nothing this
     * sweep. Returns true when it seeded.
     */
    fun maybeReseedPreFixImport(db: VaultDatabase): Boolean {
        try {
            if (db.getMeta(MoveMetaKeys.IMPORTED).isNullOrEmpty()) return false
            if (!db.getMeta(MoveMetaKeys.ROTATE_VERSION).isNullOrEmpty()) return false
            if (!db.isOpen) return false
            // The marker makes this ONE-time, so every input must be believable: on iOS
            // a query error answers EMPTY (not a throw). Any inconsistency defers to the
            // next sweep, never seeds a short list for good.
            val keys = db.metaKeys()
            if (MoveMetaKeys.IMPORTED !in keys) return false               // the key scan did not really answer
            val legacy = readRaw(db) ?: return false
            if (legacy.isEmpty() && MoveMetaKeys.ROTATE_PENDING in keys) return false   // the list exists but read empty
            fun ownedRows() = db.getAllInboxIds()
                .filter { it.direction in MessageManager.OWNED_READ_DIRECTIONS && isValidInboxId(it.inboxId) }
                .map { it.inboxId }
            val owned = ownedRows()
            if (ownedRows() != owned) return false                         // two reads must agree
            if (owned.isEmpty() && db.getAllContacts().isNotEmpty()) return false   // contacts but no row: not believable
            val referral = referralAcceptMintedIds(db, keys) ?: return false
            if (!db.isOpen) return false
            val ids = LinkedHashSet<String>()
            ids.addAll(legacy.filter { isValidInboxId(it) })
            ids.addAll(owned)
            ids.addAll(referral)
            var seeded = false
            listLock.withLock {
                db.withTransaction {
                    if (!db.getMeta(MoveMetaKeys.ROTATE_VERSION).isNullOrEmpty()) return@withTransaction
                    if (ids.isEmpty()) db.deleteMeta(MoveMetaKeys.ROTATE_PENDING)
                    else db.putMeta(MoveMetaKeys.ROTATE_PENDING, encode(ids.toList()))
                    db.putMeta(MoveMetaKeys.ROTATE_VERSION, VERSION)
                    seeded = true
                }
            }
            if (seeded) platformLog(TAG, "one-time re-rotation seeded for a move imported on an older build: ${ids.size} entries")
            return seeded
        } catch (e: Throwable) {
            platformLogWarn(TAG, "re-rotation seed deferred: ${e::class.simpleName}")
            return false
        }
    }

    /**
     * Inbox ids minted by every live `ref_p` record among [keys]. Null when the scan
     * threw, or a listed record read empty (inconsistent — defer).
     */
    private fun referralAcceptMintedIds(db: VaultDatabase, keys: List<String>): List<String>? = try {
        val out = mutableListOf<String>()
        var consistent = true
        for (key in keys.sorted()) {
            if (!key.startsWith(ReferralMetaKeys.ACCEPT_PREFIX)) continue
            val raw = db.getMeta(key)
            if (raw.isNullOrEmpty()) consistent = false else out.addAll(referralMintedInboxIds(raw))
        }
        if (consistent) out else null
    } catch (e: Throwable) {
        platformLogWarn(TAG, "referral record scan failed: ${e::class.simpleName}")
        null
    }
}

/**
 * The inboxes OUR pending introduction minted, read from a `ref_p` record (main,
 * control and, when present, group). Only the ids are read — never the record's
 * private key. Ids that are not well formed are skipped.
 */
internal fun referralMintedInboxIds(raw: String): List<String> =
    listOf("mi", "ci", "gi").mapNotNull { field ->
        firstStringFieldAnywhere(raw, field)?.takeIf { isValidInboxId(it) }
    }.distinct()

/**
 * The complete, de-duplicated, deterministic obligation set for [snapshot]:
 * every inbox row in an owned read direction ([MessageManager.OWNED_READ_DIRECTIONS] —
 * superseded rows included, they are classified at pass time), then every inbox a
 * pending introduction (`ref_p`) minted, which has no row until that introduction
 * finalizes and is deferred until then. Pure — no vault read, so it cannot fail on
 * a scan.
 */
internal fun moveRotationObligations(snapshot: VaultSnapshot): List<String> {
    val out = LinkedHashSet<String>()
    for (record in snapshot.inboxes) {
        if (record.direction in MessageManager.OWNED_READ_DIRECTIONS && isValidInboxId(record.inboxId)) {
            out.add(record.inboxId)
        }
    }
    for (key in snapshot.meta.keys.sorted()) {
        if (!key.startsWith(ReferralMetaKeys.ACCEPT_PREFIX)) continue
        snapshot.meta[key]?.let { out.addAll(referralMintedInboxIds(it)) }
    }
    return out.toList()
}

/**
 * Where securing stands, from the vault alone. [MoveSecuringState.Complete] needs
 * `mig_imported`, the [MoveMetaKeys.ROTATE_VERSION] marker AND an empty list — a
 * pre-fix import that has not been re-seeded yet is still Pending, never Complete.
 */
internal fun moveSecuringState(db: VaultDatabase): MoveSecuringState = try {
    if (!db.isOpen) {
        MoveSecuringState.Unknown
    } else if (db.getMeta(MoveMetaKeys.IMPORTED).isNullOrEmpty()) {
        MoveSecuringState.NotMoved
    } else {
        val raw = db.getMeta(MoveMetaKeys.ROTATE_PENDING)
        // A missing list counts as "nothing left" only when the key is POSITIVELY
        // absent: the key scan answers (it lists `mig_imported`) and does not list it.
        // On iOS a failed read answers null, which must never read as "revoked".
        val listUnreadable = raw.isNullOrEmpty() && db.metaKeys().let { keys ->
            MoveMetaKeys.IMPORTED !in keys || MoveMetaKeys.ROTATE_PENDING in keys
        }
        val listed = MoveRotation.decode(raw).size
        val marked = !db.getMeta(MoveMetaKeys.ROTATE_VERSION).isNullOrEmpty()
        when {
            !db.isOpen || listUnreadable -> MoveSecuringState.Unknown
            marked && listed == 0 -> MoveSecuringState.Complete
            else -> MoveSecuringState.Pending(listed)
        }
    }
} catch (_: Throwable) {
    MoveSecuringState.Unknown
}

/**
 * The status row both UIs show: PENDING while rotations are owed; DONE only after
 * THIS session saw them pending and then saw them finish (a long-finished move
 * shows nothing); HIDDEN otherwise. An unreadable state keeps the last answer.
 */
internal class MoveSecuringRowLatch {
    private val lock = SyncLock()
    private var sawPending = false
    private var last = MoveSecuringRow.HIDDEN

    fun observe(state: MoveSecuringState): MoveSecuringRow = lock.withLock {
        last = when (state) {
            is MoveSecuringState.Pending -> { sawPending = true; MoveSecuringRow.PENDING }
            MoveSecuringState.Complete -> if (sawPending) MoveSecuringRow.DONE else MoveSecuringRow.HIDDEN
            MoveSecuringState.NotMoved -> MoveSecuringRow.HIDDEN
            MoveSecuringState.Unknown -> last
        }
        last
    }

    fun reset() = lock.withLock {
        sawPending = false
        last = MoveSecuringRow.HIDDEN
    }
}

/**
 * Control-sweep entry point (SessionManagers.kt): first the one-time re-rotation
 * seed for a pre-fix import, then one bounded pass. Cheap-gated: a vault that never
 * moved pays one `_meta` read. Blocking (it rides the sweep's background thread)
 * and never throws — an escape here would break the sweep that carries the
 * referral and membership redrives.
 */
internal fun retryPendingMoveRotations(vault: VaultDatabase, messageManager: MessageManager?) {
    try {
        val imported = try { vault.getMeta(MoveMetaKeys.IMPORTED) } catch (_: Throwable) { null }
        if (imported.isNullOrEmpty()) return
        // The OLD phone of a later move (this vault imported once, then exported):
        // nothing to secure here any more, and nothing may be written while frozen.
        if (isMoveFrozen(vault)) return
        MoveRotation.maybeReseedPreFixImport(vault)
        val mm = messageManager ?: return
        MoveRotation.runPassBlocking(vault, MoveRotation.SWEEP_BUDGET) { id, cap ->
            mm.rotateOwnedInboxReadCap(id, cap)
        }
    } catch (e: Throwable) {
        platformLogWarn("MoveRotation", "pending rotation sweep failed: ${e::class.simpleName}")
    }
}

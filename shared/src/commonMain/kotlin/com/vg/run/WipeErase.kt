package com.vg.run

import kotlin.concurrent.Volatile

// ---------------------------------------------------------------------------
// WipeErase — CHECKED deletion for every wipe path, both platforms (RÚN-02).
//
// A wipe's deletions used to discard their status (iOS SecItemDelete on the device
// key, the Secure Enclave key and the bulk Keychain sweep; Android the Lever B key
// and the Tink master key's Boolean). The app could not tell which critical
// deletions had happened, and a SURVIVING device key was then silently reused by
// the next setup — an archived pre-wipe `vlt_c` / `vlt_rc` stayed decryptable.
//
// Now:
//  - every deletion reports [EraseOutcome] DELETED / ALREADY_ABSENT / UNRESOLVED
//    through an injected [WipeKeyStore] (Swift bridge on iOS, Keystore + files on
//    Android); "absent" is trusted ONLY while protected data is available;
//  - [WipeEraser] attempts every item independently, in crypto-erase-first order,
//    with [WipeEraser.IMMEDIATE_PASSES] immediate passes over what is unresolved;
//  - [WipeEraseLatch] holds the outcome IN RAM ONLY (no on-disk marker: a marker
//    would itself be evidence of use and of a wipe). While it is unresolved nothing
//    may mint a device key, replay the iOS write journal, start a fresh setup or
//    open the old vault ([WipeErasePolicy]);
//  - [WipeEraseRetry] re-attempts ONLY the unresolved items on the platform's
//    triggers (device unlock / app activation / the Retry button);
//  - [FreshProvisionGate] is the cross-launch half: at the start of a fresh setup,
//    BEFORE the first seal (= before any key exists for the new vault), a provably
//    empty install has any leftover device / hardware key deleted, checked.
//
// WHY A RETRY CAN NEVER DELETE A NEWLY PROVISIONED KEY — the ordering, pinned by
// WipeRetryNeverTargetsNewKeyTest:
//  - in-process, a deletion runs only while the latch is unresolved, and an
//    unresolved latch refuses every mint and every provision; so no new key can
//    exist while a retry can still run;
//  - across a relaunch the latch is gone; deletions then run only in
//    [FreshProvisionGate.prepare] (strictly before the provision's first seal) and
//    in the launch-time wipe checks (before setup is reachable at all).
//
// Nothing in this file writes anything anywhere (WipeEraseCheckedSourceTest).
// ---------------------------------------------------------------------------

/** The three outcomes of one deletion. [code] crosses the Swift bridge as an Int. */
enum class EraseOutcome(val code: Int) {
    /** The delete succeeded AND a read-back proved the item gone. */
    DELETED(0),

    /** There was nothing to delete — proven by the read-back. */
    ALREADY_ABSENT(1),

    /** Anything else: a refused delete, an item still visible, a thrown error, a
     *  missing bridge, or an "absent" answer that cannot be trusted right now. */
    UNRESOLVED(2);

    companion object {
        /** Unknown codes are UNRESOLVED — never a success by accident. */
        fun fromCode(code: Int): EraseOutcome = entries.firstOrNull { it.code == code } ?: UNRESOLVED
    }
}

/**
 * One deletion's outcome. [status] is the platform status (OSStatus / errno / a
 * sentinel below), for logs as a NUMBER only — never key material, never a name
 * beyond the item class.
 */
data class EraseResult(val outcome: EraseOutcome, val status: Int) {
    companion object {
        const val STATUS_NONE = 0
        /** The adapter threw. */
        const val STATUS_EXCEPTION = -1
        /** iOS: the Swift bridge holder was not registered — never a silent skip. */
        const val STATUS_NO_BRIDGE = -2
        /** A file still present (or its presence unknowable) after the delete. */
        const val STATUS_STILL_PRESENT = -3
        fun unresolved(status: Int = STATUS_NONE) = EraseResult(EraseOutcome.UNRESOLVED, status)
    }
}

/**
 * The independently owned items of a wipe, in CRYPTO-ERASE-FIRST order: the device
 * key first (it kills every device-key blob, archived copies included), then the
 * hardware (Secure Enclave / auth-bound Keystore) key, then the credential items
 * (`vlt_a` / `vlt_c` / `vlt_rc` / the write journal), the block list, the vault files.
 */
enum class WipeItem { DEVICE_KEY, HARDWARE_KEY, KV_SWEEP, BLOCK_LIST, VAULT_FILES }

/** The injected key-store adapter. Implementations must not write anything. */
interface WipeKeyStore {
    /** iOS: `UIApplication.isProtectedDataAvailable`. Android: always true (see WipeRoutine). */
    fun protectedDataAvailable(): Boolean

    /** Delete [item] and read it back. May throw; [WipeEraser] maps a throw to UNRESOLVED. */
    fun erase(item: WipeItem): EraseResult
}

/** The outcome of the items attempted so far. Immutable. */
class WipeEraseReport(val results: Map<WipeItem, EraseResult>) {

    val unresolved: Set<WipeItem> =
        results.filterValues { it.outcome == EraseOutcome.UNRESOLVED }.keys

    /** Something was attempted and nothing is unresolved. An empty report proves nothing. */
    val complete: Boolean = results.isNotEmpty() && unresolved.isEmpty()

    /** [other]'s results win for the items it carries. */
    fun merge(other: WipeEraseReport): WipeEraseReport = WipeEraseReport(results + other.results)

    /** `ITEM=OUTCOME(status)` in item order — numbers and class names only. */
    fun summary(): String = WipeItem.entries.mapNotNull { item ->
        results[item]?.let { "${item.name}=${it.outcome.name}(${it.status})" }
    }.joinToString(" ")
}

object WipeEraser {

    /** Owner decision D6: three immediate passes, then event-driven retries only. */
    const val IMMEDIATE_PASSES = 3

    /** The two keys, deleted first of all (the platform's "crypto-erase first"). */
    val KEY_ITEMS: List<WipeItem> = listOf(WipeItem.DEVICE_KEY, WipeItem.HARDWARE_KEY)

    /**
     * Attempts every one of [items] once, in the given order, then re-attempts only
     * the still-unresolved ones for up to [passes] passes in total. One item's
     * failure never skips another. Never throws.
     */
    fun run(store: WipeKeyStore, items: List<WipeItem>, passes: Int = IMMEDIATE_PASSES): WipeEraseReport {
        val results = LinkedHashMap<WipeItem, EraseResult>()
        var pending = items
        repeat(maxOf(1, passes)) {
            if (pending.isEmpty()) return@repeat
            for (item in pending) results[item] = attempt(store, item)
            pending = pending.filter { results[it]?.outcome == EraseOutcome.UNRESOLVED }
        }
        return WipeEraseReport(results)
    }

    /** Re-attempts ONLY [prior]'s unresolved items; a complete report makes zero calls. */
    fun retryUnresolved(store: WipeKeyStore, prior: WipeEraseReport, passes: Int = 1): WipeEraseReport {
        val todo = WipeItem.entries.filter { it in prior.unresolved }
        if (todo.isEmpty()) return prior
        return prior.merge(run(store, todo, passes))
    }

    private fun attempt(store: WipeKeyStore, item: WipeItem): EraseResult {
        val before = protectedData(store)
        val r = try {
            store.erase(item)
        } catch (_: Exception) {
            return EraseResult.unresolved(EraseResult.STATUS_EXCEPTION)
        }
        if (r.outcome == EraseOutcome.UNRESOLVED) return r
        if (before && protectedData(store)) return r
        // Protected data unavailable (iOS: a locked keybag) at either end of the
        // call. Whether `SecItemDelete` / the verify probe can still see a
        // passcode-class item then is NOT established (the device procedure
        // measures it), so an "absent" answer may be a lie, and a bulk sweep's
        // "verified empty" may have missed items it could not match. Only a
        // single-item delete that positively SUCCEEDED is kept as evidence.
        val trusted = r.outcome == EraseOutcome.DELETED && item != WipeItem.KV_SWEEP
        return if (trusted) r else EraseResult.unresolved(r.status)
    }

    private fun protectedData(store: WipeKeyStore): Boolean =
        try { store.protectedDataAvailable() } catch (_: Exception) { false }
}

/**
 * The unresolved-erase state, RAM ONLY and process-lifetime — persisting it would be
 * a post-wipe artifact proving use (owner decision D4). Distinct from Android's
 * one-way `ProcessWipeLatch` (never cleared) and from the deniable black cover: this
 * one RESOLVES once every item is proven gone, and only then lets setup proceed.
 *
 * OWNERSHIP (structural, not by convention): [begin] hands the running wipe a
 * token, and only [finish] with THAT token clears the in-flight guard. Everything
 * else — a retry, the fresh-setup purge — records through [recordOutcome], which
 * refuses while a wipe is in flight, so it can never drop the guard of a wipe that
 * is still deleting (a mint mid-wipe). While in flight [unresolved] is true
 * whatever report is on file. All state changes run under one lock; readers on
 * any thread see @Volatile fields.
 */
object WipeEraseLatch {

    private val lock = SyncLock()
    @Volatile private var inFlightToken: Long = NO_TOKEN
    private var lastToken: Long = NO_TOKEN
    @Volatile private var report: WipeEraseReport? = null

    const val NO_TOKEN: Long = 0L

    /** A wipe is running, or the last outcome left something unresolved. */
    val unresolved: Boolean get() = inFlightToken != NO_TOKEN || report?.complete == false

    /** True while a wipe is between [begin] and [finish]. */
    val wipeInFlight: Boolean get() = inFlightToken != NO_TOKEN

    /**
     * Called FIRST by every wipe — before the first delete, so a mint racing it is
     * refused. Returns the wipe's token. A wipe already in flight is JOINED (same
     * token): on iOS the in-session wipe begins in `eraseKeyMaterialFirst` and the
     * controller's `emergencyWipe` continues it; both run on the main thread.
     */
    fun begin(): Long = lock.withLock {
        if (inFlightToken == NO_TOKEN) {
            lastToken += 1
            inFlightToken = lastToken
        }
        inFlightToken
    }

    /** The wipe that owns [token] has its outcome. A stale or foreign token changes nothing. */
    fun finish(token: Long, r: WipeEraseReport): Boolean = lock.withLock {
        if (token == NO_TOKEN || token != inFlightToken) return@withLock false
        report = r
        inFlightToken = NO_TOKEN
        true
    }

    /** A retry's or the fresh-setup purge's outcome. Refused (false) while a wipe is in flight. */
    fun recordOutcome(r: WipeEraseReport): Boolean = lock.withLock {
        if (inFlightToken != NO_TOKEN) return@withLock false
        report = r
        true
    }

    /** The last recorded outcome (null in a fresh process). Logs / the debug probe. */
    fun lastReport(): WipeEraseReport? = report

    /** Tests only: a fresh process. */
    internal fun resetForTest() {
        lock.withLock {
            inFlightToken = NO_TOKEN
            report = null
        }
    }
}

/**
 * Wipe / erase log lines exist in DEBUG builds only. In a release build with Debug
 * mode on, LogBuffer is live and a deniably wiped process is kept alive, so any line
 * naming the wipe or an item class (e.g. that a hardware-bound key was deleted) would
 * itself be the evidence the wipe exists to remove.
 */
internal fun wipeEraseDebugLog(tag: String, message: String) {
    if (isDebugBuild) platformLogWarn(tag, message)
}

object WipeErasePolicy {

    /** No device key may be generated while an erase is unresolved (it would be the
     *  key a pending retry could reach, or a fresh key next to a surviving old one). */
    fun mayMintDeviceKey(): Boolean = !WipeEraseLatch.unresolved

    /** No fresh setup while an erase is unresolved. */
    fun mayProvision(): Boolean = !WipeEraseLatch.unresolved

    /** iOS: no write-journal replay — a surviving journal would re-write credential items. */
    fun mayReplayJournal(): Boolean = !WipeEraseLatch.unresolved

    /** The old vault stays closed (unlock / recovery answer the neutral Error). */
    fun mayOpenVault(): Boolean = !WipeEraseLatch.unresolved

    /**
     * R3 — may the fresh-setup gate delete leftover keys? ONLY on a provably empty
     * install: the credential pair CONFIRMED absent (never the fail-toward-true
     * `isConfigured`), no vault file in ANY directory the vault can live in, and no
     * write journal that could replay credentials. Anything ambiguous: no purge.
     */
    fun residualKeyPurgeAllowed(
        credentialPair: Boolean?,
        vaultFileAbsentAllDirs: Boolean,
        journalConfirmedAbsent: Boolean,
    ): Boolean = credentialPair == false && vaultFileAbsentAllDirs && journalConfirmedAbsent

    /**
     * R2 (owner decision D3) — credentials PROVEN present (both reads succeeded) but
     * no vault file in any directory and no journal: the residue of a wipe that
     * deleted the file but not the keys. Nothing can be opened without the file, so
     * erasing loses nothing; leaving it keeps the device key, the verifier and the
     * recovery blob alive on a phone whose user believes it was wiped. A healthy vault
     * always has its file (the provision creates it before any credential is written).
     */
    fun postWipeResidue(
        credentialPair: Boolean?,
        vaultFileAbsentAllDirs: Boolean,
        journalConfirmedAbsent: Boolean,
    ): Boolean = credentialPair == true && vaultFileAbsentAllDirs && journalConfirmedAbsent

    /**
     * A keystore-alias delete (Android master key / auth-bound key): [everPresent] =
     * any attempt saw the alias, [goneAfter] = the read-back (null = could not read).
     * Only a read-back proving it gone resolves.
     */
    fun aliasDeleteOutcome(everPresent: Boolean, goneAfter: Boolean?): EraseOutcome = when (goneAfter) {
        true -> if (everPresent) EraseOutcome.DELETED else EraseOutcome.ALREADY_ABSENT
        else -> EraseOutcome.UNRESOLVED
    }
}

object WipeEraseRetry {

    /**
     * The event-driven retry (device unlock, app activation, the Retry button):
     * re-attempts only the unresolved items of the last report, once. Does nothing
     * while a wipe is in flight or when nothing is unresolved. When it resolves,
     * [onResolved] must drop every cached copy of the device key (a provider that
     * loaded the surviving old key would otherwise seal the next provision under a
     * key that no longer exists — a brick of the NEW vault).
     *
     * @return true when nothing is (any longer) unresolved.
     */
    fun retryIfPending(store: WipeKeyStore, onResolved: () -> Unit): Boolean {
        if (WipeEraseLatch.wipeInFlight) return false
        val prior = WipeEraseLatch.lastReport() ?: return true
        if (prior.complete) return true
        val next = WipeEraser.retryUnresolved(store, prior)
        // A wipe that began while this pass ran owns the outcome: drop ours.
        if (!WipeEraseLatch.recordOutcome(next)) return false
        if (next.complete) onResolved()
        wipeEraseDebugLog("WipeErase", "retry: ${next.summary()}")
        return next.complete
    }
}

object FreshProvisionGate {

    /**
     * The FIRST step of every fresh setup, BEFORE the first seal (the first point at
     * which a device key can be minted for the new vault):
     *  - refuses while an erase is unresolved;
     *  - on a provably empty install ([WipeErasePolicy.residualKeyPurgeAllowed])
     *    deletes any leftover device / hardware key, checked; refuses if one stays
     *    unresolved — latching (so the retry triggers take over) ONLY when the purge
     *    actually deleted a key, i.e. a leftover provably existed; otherwise it is a
     *    plain retryable setup failure with no erase state at all;
     *  - always ends with [dropCachedKeys], so the provision seals under the key
     *    actually PERSISTED, never a cached copy of one that was just deleted.
     *
     * @return true when the setup may proceed.
     */
    fun prepare(
        store: WipeKeyStore,
        credentialPair: Boolean?,
        vaultFileAbsentAllDirs: Boolean,
        journalConfirmedAbsent: Boolean,
        dropCachedKeys: () -> Unit,
    ): Boolean {
        if (WipeEraseLatch.unresolved) return false
        if (WipeErasePolicy.residualKeyPurgeAllowed(credentialPair, vaultFileAbsentAllDirs, journalConfirmedAbsent)) {
            val purge = WipeEraser.run(store, WipeEraser.KEY_ITEMS)
            dropCachedKeys()
            if (!purge.complete) {
                // Latch ONLY on positive evidence that a leftover key existed (one of
                // the two was actually deleted). On an install that never wiped —
                // every fresh setup runs this purge — a delete that merely could not
                // be confirmed (-34018, a locking keybag) is a plain, retryable setup
                // failure: no erase latch, no erase wording, nothing process-wide.
                if (purge.results.values.any { it.outcome == EraseOutcome.DELETED }) {
                    WipeEraseLatch.recordOutcome(purge)
                }
                wipeEraseDebugLog("WipeErase", "fresh setup refused — leftover key not confirmed gone: ${purge.summary()}")
                return false
            }
            wipeEraseDebugLog("WipeErase", "fresh setup: leftover keys checked: ${purge.summary()}")
            return true
        }
        dropCachedKeys()
        return true
    }
}

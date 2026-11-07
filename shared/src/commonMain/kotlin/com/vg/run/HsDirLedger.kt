package com.vg.run

/**
 * Per-Tor-PROCESS memory of which HSDirs served — or failed to serve — the
 * relay's descriptor, so the descriptor-fetch watchdog's `HSFETCH` can be pinned
 * to the last directory known to work (`HSFETCH <addr> SERVER=$<fp>`).
 *
 * WHY (2026-10-08, prod, app 1.6.38): the two worst connects (Android 110 s,
 * iOS 215 s) both had a SUCCESSFUL descriptor fetch (`HS_DESC RECEIVED` from a
 * healthy HSDir) before a `SIGNAL NEWNYM`; the post-NEWNYM re-fetch then hung on
 * a dead HSDir again, because NEWNYM purges Tor's recently-asked-HSDir memory
 * (`hs_client_purge_state`). Measured from a desktop client: of the onion's 6
 * HSDirs that time period 3 were dead / NOT_FOUND, 1 slow (~25 s) and 2 answered
 * in ~0.5 s — and the set is stable for the whole HS time period. Tor forgets
 * which one worked; this ledger does not. A NEWNYM therefore does NOT clear it
 * (that is the whole point); a new Tor process does ([resetForNewTorProcess] —
 * Android's corrupt-state retry; on iOS tor_main runs once per app process, so
 * the ledger is a process-wide static there). Nothing is persisted.
 *
 * RULES:
 *  - [goodHsDir] = the HSDir of the most recent `RECEIVED` — unless that HSDir is
 *    already in [badHsDirs] (a slow HSDir that eventually answered after it
 *    stalled the watchdog is still not one to pin to);
 *  - [badHsDirs] = every HSDir with a `FAILED` (any reason, NOT_FOUND included)
 *    and every HSDir whose `REQUESTED` was still unanswered when the watchdog
 *    fired ([noteStallFired]). Never chosen;
 *  - [pinnedServerArgument] = `SERVER=$<good>` when a good, non-bad HSDir is
 *    known, else null (the plain `HSFETCH`, Tor picks);
 *  - [dropPin] after Tor answered the pinned `HSFETCH` with 551/552 (the HSDir
 *    left the consensus / is no longer an HSDir).
 *
 * The fingerprints are SENSITIVE for logging: nothing in this class renders one
 * ([toString] is counts-free), and the only fixed phrases the platforms log
 * about it are [PINNED_PHRASE] and [PIN_DROPPED_PHRASE] — no numbers, no ids.
 *
 * THREAD-SAFE: iOS feeds it from Tor's control-socket queue (the raw-650 tap)
 * and reads it on the main actor; Android from the event reader coroutine and
 * the watchdog's IO coroutine.
 */
class HsDirLedger {
    private val lock = SyncLock()
    private var goodHsDir: String? = null
    private val badHsDirs = HashSet<String>()
    /** HSDirs with a `REQUESTED` not yet followed by RECEIVED / FAILED. */
    private val pendingHsDirs = HashSet<String>()

    /** Feed every `HS_DESC` event of the relay's onion ([RelayDescriptorWatchdog.parseEvent]). */
    fun observe(event: RelayDescriptorEvent) {
        val fp = event.hsDirFingerprint ?: return
        lock.withLock {
            when (event.action) {
                RelayDescriptorEvent.Action.REQUESTED -> pendingHsDirs.add(fp)
                RelayDescriptorEvent.Action.RECEIVED -> {
                    pendingHsDirs.remove(fp)
                    if (fp !in badHsDirs) goodHsDir = fp
                }
                RelayDescriptorEvent.Action.FAILED -> {
                    pendingHsDirs.remove(fp)
                    badHsDirs.add(fp)
                    if (goodHsDir == fp) goodHsDir = null
                }
            }
        }
    }

    /**
     * The SECOND descriptor re-request is going out ([DescriptorHedge.Stage.SECOND],
     * ≥ 5 s after the cache miss — the old watchdog's stall point): every HSDir
     * still waiting on a `REQUESTED` is the one that stalled — mark it bad BEFORE choosing the pin, so a pinned
     * HSDir that itself stalled is never chosen again.
     */
    fun noteStallFired() {
        lock.withLock {
            badHsDirs.addAll(pendingHsDirs)
            if (goodHsDir in pendingHsDirs) goodHsDir = null
            pendingHsDirs.clear()
        }
    }

    /**
     * An app-fired NEWNYM was accepted: Tor cancelled the pending descriptor
     * fetches, so the outstanding REQUESTEDs prove nothing any more — forget them
     * (they were neither answered nor stalled past the watchdog). Good and bad
     * HSDirs are KEPT.
     */
    fun noteNewnym() {
        lock.withLock { pendingHsDirs.clear() }
    }

    /** `SERVER=$<fp>` for the pinned re-fetch, or null for the plain one. */
    fun pinnedServerArgument(): String? = lock.withLock {
        goodHsDir?.takeIf { it !in badHsDirs }?.let { "SERVER=\$$it" }
    }

    /** Tor rejected the pinned HSDir (551/552): forget it, never mark it bad. */
    fun dropPin() {
        lock.withLock { goodHsDir = null }
    }

    /** A fresh Tor child: everything this process learnt is about a dead daemon. */
    fun resetForNewTorProcess() {
        lock.withLock {
            goodHsDir = null
            badHsDirs.clear()
            pendingHsDirs.clear()
        }
    }

    override fun toString(): String = "HsDirLedger"

    companion object {
        /** Fixed phrase: a re-fetch went to the last good HSDir. No ids, no numbers. */
        const val PINNED_PHRASE: String = "descriptor refetch pinned to the last good directory"

        /** Fixed phrase: Tor rejected the pin; the re-fetch went out plain. */
        const val PIN_DROPPED_PHRASE: String = "descriptor directory pin dropped"

        /** Writes [PINNED_PHRASE] (platform log + uncoded panel line). */
        fun logPinned() {
            platformLog("TorManager", PINNED_PHRASE)
            ConnectionLog.append(ConnectionLog.Kind.TOR, PINNED_PHRASE)
        }

        /** Writes [PIN_DROPPED_PHRASE] (platform log + uncoded panel line). */
        fun logPinDropped() {
            platformLog("TorManager", PIN_DROPPED_PHRASE)
            ConnectionLog.append(ConnectionLog.Kind.TOR, PIN_DROPPED_PHRASE)
        }
    }
}

/**
 * One [HsDirLedger] PER CONFIGURED ADDRESS of the relay (2026-10-23,
 * [RelayAddressRace]): every address has its own responsible-HSDir set, so a
 * "good" or "bad" HSDir of one address says nothing about another. Same
 * lifetime rules as the single ledger (kept across NEWNYM, reset per Tor
 * process). With one address it is exactly the old single ledger.
 *
 * Fingerprints stay inside the per-slot ledgers; nothing here renders one.
 */
class HsDirLedgerSet(slots: Int) {
    private val ledgers: List<HsDirLedger> = List(slots.coerceAtLeast(1)) { HsDirLedger() }

    /** The ledger of [slot] (index into [RelayAddressRace.urls]); slot 1's for an
     *  out-of-range index. */
    fun forSlot(slot: Int): HsDirLedger = ledgers.getOrNull(slot) ?: ledgers[0]

    /** Feed every `HS_DESC` event of any of the relay's addresses: routed by its slot. */
    fun observe(event: RelayDescriptorEvent) = forSlot(event.slot).observe(event)

    /** The SECOND hedge stage is going out: every address's still-unanswered
     *  REQUESTEDs are stalls (they are all ≥ 4 s old by then). */
    fun noteStallFired() = ledgers.forEach { it.noteStallFired() }

    /** An app-fired NEWNYM was accepted (see [HsDirLedger.noteNewnym]). */
    fun noteNewnym() = ledgers.forEach { it.noteNewnym() }

    /** A fresh Tor child (see [HsDirLedger.resetForNewTorProcess]). */
    fun resetForNewTorProcess() = ledgers.forEach { it.resetForNewTorProcess() }

    override fun toString(): String = "HsDirLedgerSet"
}

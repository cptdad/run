package com.vg.run

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.time.TimeSource

/**
 * SEVERAL ONION ADDRESSES FOR ONE RELAY — the descriptor race (2026-10-23).
 * THE decision, shared by both platforms; the platform TorManagers own only the
 * `HSFETCH` commands on the control COMMAND connection and feed every `HS_DESC`
 * event in ([observe]).
 *
 * WHY. A cold Tor client to the dev relay stalled 50–120 s in the DESCRIPTOR
 * phase: the control-port trace showed `HS_DESC REQUESTED` with no `RECEIVED`
 * for 60–120 s at that onion's current responsible HSDirs, and once `RECEIVED`
 * landed, intro + rendezvous finished in ~1 s. The responsible HSDir set is
 * derived from the onion key and the SRV / time period, so a SECOND address for
 * the same relay backend (the relay app is address-agnostic: capabilities and
 * inboxes never depend on `Host`) lands on an independent HSDir set. Racing
 * the descriptor across the addresses turns "this period's HSDirs for our one
 * onion are bad" from a minute-long stall into a non-event.
 *
 * WHAT. [beginRace] (once per Tor HS state: a Tor process start, or an accepted
 * app-fired NEWNYM — both purge the descriptor cache) hands the platform one
 * bare `HSFETCH <addr>` per configured address, all at once. The FIRST
 * `HS_DESC RECEIVED` of any of them wins ([observe]) and its URL becomes
 * [currentBaseUrl] — `RelayConfig.BASE_URL`, i.e. what `MessageManager`, the
 * warm-up, push registration and telemetry use. A `FAILED` of one address never
 * ends the race; the others keep racing. The winner is STICKY: a later re-race
 * keeps using it until a new `RECEIVED` decides again, so a NEWNYM never sends
 * the session back to a slower slot 1 in the meantime.
 *
 * DEMOTION (2026-11-15). The race decides on the DESCRIPTOR, so an address whose
 * descriptor is fetchable but whose introduction/rendezvous is dead keeps winning
 * — and because the winner is process-wide and sticky, it survived every in-process
 * Tor restart until the app process died (prod incident 2026-11-15: three Tor
 * restarts + NEWNYMs failed, a fresh process worked). [demoteUnansweredWinner] is
 * called where the platform's stall ladder GIVES UP on the current attempt
 * (Android `RunViewModel.restartTor` — the auto restart and the manual Reconnect;
 * iOS `AppState.maybeLatchStalled` and `reconnectRelay`). The rule:
 *  - only with ≥ 2 addresses ([isRacing]); one address = a no-op, exactly as before;
 *  - only when the winner had NO real relay answer since the current Tor HS state
 *    began ([noteRelayAnswered] / [noteTorHsStateReset]) — a winner that answered
 *    on these circuits is not the address's fault;
 *  - never twice without a fresh Tor HS state in between: the slot that inherits
 *    the session must get at least one race/Tor of its own before it can be set aside;
 *  - the demoted slot stops being the session's address AT ONCE (the first
 *    non-demoted slot in list order takes over and the in-flight probe is aborted
 *    through the switch hook), and its `RECEIVED` cannot decide a later race while
 *    a non-demoted address is still in it (not `FAILED`). If every other address
 *    fails, an already-received demoted address wins after all;
 *  - at most N-1 slots are demoted: demoting the last eligible one clears the set
 *    first, so the rule rotates instead of deadlocking;
 *  - LIFETIME: until the first real relay answer anywhere in the process
 *    ([noteRelayAnswered], from `MessageManager`'s round-trip latch and the
 *    warm-up), which clears the whole set; RAM only, so a new process starts clean.
 * One fixed panel line per demotion ([demotedPhrase]: slot NUMBERS only, uncoded).
 *
 * RACE ON THE DESCRIPTOR, NOT ON CONNECTIONS. Only `HSFETCH` is raced — no
 * extra HTTP request, no extra stream, no extra intro/rendezvous circuit. The
 * relay sees nothing new; the HSDirs see one descriptor query per address.
 *
 * ONE ADDRESS = TODAY, EXACTLY. With a single configured address (or a
 * non-onion relay) [isRacing] is false: [beginRace] returns nothing (no extra
 * `HSFETCH`), [observe] feeds every event to the hedge exactly as before and
 * never switches, [currentBaseUrl] is slot 1, and [needsWait] is always false.
 *
 * THE HEDGE ACROSS ADDRESSES ([DescriptorHedge], one per session — its budget
 * of 4 is NOT multiplied by the address count). While a race is OPEN the hedge
 * treats the addresses as ONE logical descriptor: every racing `REQUESTED`
 * counts in flight, the first `RECEIVED` of any address closes the episode. So
 * with ≥ 2 addresses the racing fetches already fill the hedge's in-flight cap
 * (2) and the 1 s hedge is naturally deferred until they age past
 * `HSDESC_PRESUMED_DEAD_MS` (4 s) — the race IS the early overlap; the hedge
 * budget is spent only when every racing fetch looks dead. Each hedge then
 * targets the next still-unresolved address (not `FAILED` in this race), round
 * robin in slot order ([hedgeTargetSlot]); its SECOND stage pins via THAT
 * address's own [HsDirLedger]. Once resolved, only the winner is hedged, and a
 * loser's later `REQUESTED` is not fed to the hedge (it is not the relay's
 * descriptor miss); a loser's outcome is fed only to retire a request the hedge
 * already counted. The 10 s descriptor-stage NEWNYM therefore fires only when NO
 * address produced a descriptor in 10 s.
 *
 * IDENTIFIERS. The addresses are compiled-in config, held here only to be
 * written into `HSFETCH` and compared against the `HS_DESC` HSAddress field.
 * Nothing this class logs carries one: the only lines are [startedPhrase] and
 * [wonPhrase] — fixed text plus the address COUNT and the winning SLOT NUMBER
 * (1..3), uncoded, so they never reach the connect telemetry.
 *
 * THREAD-SAFE: Android feeds it from the event-reader coroutine and the command
 * coroutines; iOS from Tor's control queue and the main actor.
 */
class RelayAddressRace(candidateUrls: List<String>) {

    /** The race's addresses as base URLs, slot 1 first. NEVER log. */
    val urls: List<String>

    /** Per slot: the v3 address in `HSFETCH` / `HS_DESC` form (56 base32 chars,
     *  no `.onion`), or null for a non-onion slot 1. NEVER log. */
    private val slotAddresses: List<String?>

    init {
        val cleaned = candidateUrls.filter { it.isNotEmpty() }
        val first = cleaned.firstOrNull()
        val firstAddress = first?.let { RelayWarmup.v3OnionAddress(it) }
        when {
            first == null -> { urls = emptyList(); slotAddresses = emptyList() }
            // A non-onion relay (debug loopback) has nothing to race: extras are
            // ignored and the flow is the single-address one.
            firstAddress == null -> { urls = listOf(first); slotAddresses = listOf(null) }
            else -> {
                val u = ArrayList<String>()
                val a = ArrayList<String?>()
                u += first
                a += firstAddress
                for (extra in cleaned.drop(1)) {
                    if (u.size >= MAX_ADDRESSES) break
                    // Strict on purpose (the value reaches an authenticated control
                    // socket): anything that is not a clean v3 onion is skipped.
                    val address = RelayWarmup.v3OnionAddress(extra) ?: continue
                    if (a.any { it == address }) continue
                    u += extra
                    a += address
                }
                urls = u
                slotAddresses = a
            }
        }
    }

    /** How many addresses take part (0 = no relay configured). */
    val slotCount: Int get() = urls.size

    /** True only with ≥ 2 onion addresses. False = today's single-address flow. */
    val isRacing: Boolean get() = urls.size >= 2

    /** Every slot's v3 address, slot order (for the circuit watchdog's equality
     *  match). Empty for a non-onion relay. NEVER log. */
    val hsFetchAddresses: List<String> = slotAddresses.filterNotNull()

    /** The `HSFETCH` form of slot [slot]'s address, or null. NEVER log. */
    fun hsFetchAddressAt(slot: Int): String? = slotAddresses.getOrNull(slot)

    /** Slot [slot]'s base URL, or "" when out of range. NEVER log. */
    fun urlAt(slot: Int): String = urls.getOrNull(slot) ?: ""

    // --------------------------------------------------------------- state

    private val lock = SyncLock()

    /** The slot [currentBaseUrl] resolves to. 0 until a race is won; sticky. */
    private var winnerSlot = 0
    /** A race was begun in the current Tor HS state and has had no RECEIVED yet. */
    private var raceOpen = false
    /** [beginRace] already ran for the current Tor HS state. */
    private var begunThisState = false
    /** A race of the current Tor HS state was won. */
    private var resolvedThisState = false
    private val failedThisRace = BooleanArray(urls.size)
    /** Per slot: REQUESTEDs handed to the hedge minus outcomes handed to it. */
    private val fedOutstanding = IntArray(urls.size)
    private var hedgeRotation = 0

    /** Per slot: set aside by [demoteUnansweredWinner] (see the class header). */
    private val demoted = BooleanArray(urls.size)
    /** Per slot: a demoted address's `RECEIVED` was held back in the open race. */
    private val heldReceived = BooleanArray(urls.size)
    /** A real relay answer arrived since the current Tor HS state began. */
    private var answeredThisState = false
    /** The current winner inherited the session from a demotion and has not had a
     *  Tor HS state of its own yet — it cannot be demoted before it has. */
    private var untriedSinceDemotion = false

    /** Bumped whenever a waiter of [awaitWinner] may have to stop waiting. */
    private val settled = MutableStateFlow(0L)

    /** [DescriptorHedge.nowMs] of the latest `HS_DESC RECEIVED` for the session's
     *  address (the winner; slot 1 with one address) in the current Tor HS state,
     *  or null. Guarded by [lock]. Read by the rendezvous hedge. */
    private var winnerDescriptorAtMs: Long? = null

    @kotlin.concurrent.Volatile
    private var switchListener: (() -> Unit)? = null
    private var switchListenerOwner: Any? = null

    /** The slot [currentBaseUrl] resolves to. */
    fun currentSlot(): Int = lock.withLock { winnerSlot }

    /**
     * RENDEZVOUS HEDGE input ([RendezvousHedge]): when the session's address got
     * its descriptor in the current Tor HS state ([DescriptorHedge.nowMs] clock),
     * or null when it has not (yet). Set by [observe] on a `RECEIVED` of the
     * winner (slot 1 with a single address, which is the only one observed);
     * cleared by [noteTorHsStateReset] together with Tor's descriptor cache.
     */
    fun descriptorReceivedAtMs(): Long? = lock.withLock { winnerDescriptorAtMs }

    /**
     * Has the CURRENT Tor HS state's race produced a winner? False before any
     * [beginRace], after a [noteTorHsStateReset], and while a begun race is
     * still open (or every address failed). Always true with a single address
     * (nothing to race — nothing to re-run). Read by the iOS warm return of the
     * bounded Tor keep-alive: a decided race means a descriptor is in Tor's
     * cache and must NOT be refetched; an undecided one is re-run.
     */
    fun decidedThisState(): Boolean = !isRacing || lock.withLock { resolvedThisState }

    /** The session's relay base URL: slot 1 until a race is won, then the winner.
     *  "" when no relay is configured. NEVER log. */
    fun currentBaseUrl(): String = urlAt(currentSlot())

    /**
     * [url] as the session should use it: when [url] is one of this race's
     * addresses, the current winner's URL; anything else unchanged. Lets a holder
     * of a URL captured earlier (e.g. a `MessageManager` constructed before the
     * race resolved) follow the winner without re-construction.
     */
    fun resolve(url: String): String = if (isRacing && url in urls) currentBaseUrl() else url

    /**
     * The session owner's hook for a winner CHANGE: abort the in-flight relay
     * probe that is waiting on the losing address's descriptor
     * (`MessageManager.noteRelayAddressSwitched`). Invoked on the event thread,
     * outside the lock; must not block. One owner at a time — a newer binding
     * replaces an older one, and [unbindSwitchListener] only clears its own.
     */
    fun bindSwitchListener(owner: Any, listener: () -> Unit) {
        lock.withLock {
            switchListenerOwner = owner
            switchListener = listener
        }
    }

    fun unbindSwitchListener(owner: Any) {
        lock.withLock {
            if (switchListenerOwner === owner) {
                switchListenerOwner = null
                switchListener = null
            }
        }
    }

    // --------------------------------------------------------------- input

    /**
     * Starts the race for the current Tor HS state: returns the address of
     * EVERY slot, in slot order, for one bare `HSFETCH` each — or an empty list
     * when there is nothing to race ([isRacing] false) or this HS state was
     * already raced (idempotent until [noteTorHsStateReset]). The caller must
     * have a live control channel BEFORE calling (a begun race with no fetch
     * sent only resolves through Tor's own fetch for the current slot).
     */
    fun beginRace(): List<String> {
        if (!isRacing) return emptyList()
        val begun = lock.withLock {
            if (begunThisState) return@withLock false
            begunThisState = true
            raceOpen = true
            failedThisRace.fill(false)
            heldReceived.fill(false)
            hedgeRotation = 0
            true
        }
        if (!begun) return emptyList()
        line(startedPhrase(urls.size))
        return hsFetchAddresses
    }

    /**
     * The platform's per-event entry: one `HS_DESC` REQUESTED / RECEIVED / FAILED
     * of ANY of this race's addresses ([parseDescriptorEvent]), in Tor's order.
     * Returns whether the event goes on to the session's [DescriptorHedge] (see
     * the class header) and whether it decided the race.
     */
    fun observe(event: RelayDescriptorEvent): Observation {
        val slot = event.slot
        if (slot !in urls.indices) return Observation(feedHedge = false, wonSlot = -1, switched = false)
        var won = -1
        var switched = false
        var wakeWaiters = false
        val receivedAtMs = if (event.action == RelayDescriptorEvent.Action.RECEIVED) DescriptorHedge.nowMs() else 0L
        val feed = lock.withLock {
            if (!isRacing) {
                if (event.action == RelayDescriptorEvent.Action.RECEIVED) winnerDescriptorAtMs = receivedAtMs
                return@withLock true
            }
            when (event.action) {
                RelayDescriptorEvent.Action.REQUESTED -> {
                    val f = raceOpen || slot == winnerSlot
                    if (f) fedOutstanding[slot]++
                    f
                }
                RelayDescriptorEvent.Action.RECEIVED -> {
                    val counted = fedOutstanding[slot] > 0
                    if (counted) fedOutstanding[slot]--
                    if (raceOpen && demoted[slot] && eligibleAlternativeLocked()) {
                        // A demoted address cannot decide while a non-demoted one
                        // is still in this race; remembered in case they all fail.
                        heldReceived[slot] = true
                        counted
                    } else if (raceOpen) {
                        // THE decision: the first descriptor of this race wins.
                        // Always fed — it is what closes the hedge's episode.
                        switched = decideLocked(slot, receivedAtMs)
                        won = slot
                        wakeWaiters = true
                        true
                    } else {
                        // A descriptor for the address the session uses NOW (a later
                        // re-fetch, or Tor's own fetch with no race begun) refreshes
                        // the rendezvous hedge's reference time.
                        if (slot == winnerSlot) winnerDescriptorAtMs = receivedAtMs
                        counted
                    }
                }
                RelayDescriptorEvent.Action.FAILED -> {
                    val counted = fedOutstanding[slot] > 0
                    if (counted) fedOutstanding[slot]--
                    if (raceOpen) {
                        // One address failing never ends the race.
                        failedThisRace[slot] = true
                        if (failedThisRace.all { it }) wakeWaiters = true
                        // Every non-demoted address failed: a demoted one whose
                        // descriptor already arrived is eligible again and wins.
                        if (!eligibleAlternativeLocked()) {
                            val held = urls.indices.firstOrNull { heldReceived[it] && !failedThisRace[it] }
                            if (held != null) {
                                switched = decideLocked(held, DescriptorHedge.nowMs())
                                won = held
                                wakeWaiters = true
                            }
                        }
                    }
                    counted
                }
            }
        }
        if (won >= 0) line(wonPhrase(won + 1, urls.size))
        if (wakeWaiters) settled.update { it + 1 }
        if (switched) {
            try {
                switchListener?.invoke()
            } catch (e: Exception) {
                platformLogWarn("RelayAddressRace", "switch hook threw: ${e::class.simpleName}")
            }
        }
        return Observation(feedHedge = feed, wonSlot = won, switched = switched)
    }

    /**
     * Tor purged its HS client state — an accepted app-fired NEWNYM, or a new Tor
     * process: pending fetches are gone and the descriptor cache with them, so the
     * next [beginRace] races again. The winner is KEPT (sticky) until that race
     * decides.
     */
    fun noteTorHsStateReset() {
        lock.withLock {
            raceOpen = false
            begunThisState = false
            resolvedThisState = false
            failedThisRace.fill(false)
            heldReceived.fill(false)
            fedOutstanding.fill(0)
            hedgeRotation = 0
            winnerDescriptorAtMs = null
            // A fresh HS state: nothing has answered on it yet, and a slot that
            // inherited the session from a demotion now gets its own attempt.
            answeredThisState = false
            untriedSinceDemotion = false
        }
        settled.update { it + 1 }
    }

    // --------------------------------------------------------------- demotion

    /**
     * A REAL relay answer (any HTTP status) arrived on the session's address. Marks
     * the current Tor HS state as answered (its winner can no longer be demoted in
     * it) and clears every demotion — see the class header for the lifetime.
     */
    fun noteRelayAnswered() {
        if (!isRacing) return
        lock.withLock {
            answeredThisState = true
            demoted.fill(false)
            heldReceived.fill(false)
        }
    }

    /**
     * The platform's stall ladder gave up on the current attempt (see the class
     * header for the exact call sites and rule). Sets the current winner aside and
     * moves the session to the first non-demoted slot in list order. Returns the
     * demoted slot INDEX, or -1 when nothing was demoted (one address, the winner
     * answered in this Tor HS state, or it inherited the session from a demotion and
     * has not had a Tor HS state of its own yet).
     */
    fun demoteUnansweredWinner(): Int {
        if (!isRacing) return -1
        var from = -1
        var to = -1
        lock.withLock {
            if (answeredThisState || untriedSinceDemotion) return@withLock
            from = winnerSlot
            // Never all N: demoting the last eligible slot starts the rotation over.
            if (urls.indices.all { it == from || demoted[it] }) demoted.fill(false)
            demoted[from] = true
            heldReceived[from] = false
            to = urls.indices.first { !demoted[it] }
            winnerSlot = to
            untriedSinceDemotion = true
            // The new address's descriptor is not known to be in Tor's cache.
            winnerDescriptorAtMs = null
        }
        if (from < 0) return -1
        line(demotedPhrase(from + 1, to + 1, urls.size))
        settled.update { it + 1 }
        // Same hook as a race switch: abort the probe stuck on the demoted address.
        try {
            switchListener?.invoke()
        } catch (e: Exception) {
            platformLogWarn("RelayAddressRace", "switch hook threw: ${e::class.simpleName}")
        }
        return from
    }

    /** Is [slot] currently set aside? (Tests and the hedge target.) */
    fun isDemoted(slot: Int): Boolean = lock.withLock { demoted.getOrElse(slot) { false } }

    /** Caller holds [lock]. A non-demoted address still in the open race. */
    private fun eligibleAlternativeLocked(): Boolean =
        urls.indices.any { !demoted[it] && !failedThisRace[it] }

    /** Caller holds [lock]. [slot] wins the open race; true = the winner changed. */
    private fun decideLocked(slot: Int, receivedAtMs: Long): Boolean {
        raceOpen = false
        resolvedThisState = true
        val changed = slot != winnerSlot
        winnerSlot = slot
        winnerDescriptorAtMs = receivedAtMs
        return changed
    }

    /**
     * Which slot the next descriptor-hedge `HSFETCH` targets: while a race is
     * open, the next address not yet `FAILED` in it (round robin, slot order; all
     * of them if every one failed); otherwise the current winner (slot 1 for a
     * single address — exactly today's hedge target).
     */
    fun hedgeTargetSlot(): Int = lock.withLock {
        if (!isRacing || !raceOpen) return@withLock winnerSlot
        // A demoted address cannot win while another is in the race: hedge the others.
        val live = urls.indices.filter { !failedThisRace[it] && !demoted[it] }
            .ifEmpty { urls.indices.filter { !failedThisRace[it] } }
            .ifEmpty { urls.indices.toList() }
        live[hedgeRotation++ % live.size]
    }

    /**
     * Parses one raw control-event line against EVERY address of this race
     * ([RelayDescriptorWatchdog.parseEvent]); the returned event carries the
     * matching [RelayDescriptorEvent.slot]. Null for everything else.
     */
    fun parseDescriptorEvent(rawEventLine: String): RelayDescriptorEvent? =
        RelayDescriptorWatchdog.parseEvent(rawEventLine, slotAddresses)

    // --------------------------------------------------------------- waiting

    /**
     * Would a request to [url] made NOW still be waiting on an undecided race?
     * True only for one of this race's addresses while a race BEGUN in the
     * current Tor HS state has not produced a winner and not every address has
     * failed. Always false for a single address.
     */
    fun needsWait(url: String): Boolean = isRacing && url in urls && lock.withLock { waitingLocked() }

    /**
     * Suspends until the current Tor HS state's race is decided (a winner, or
     * every address `FAILED`), at most [maxMs]. Returns the milliseconds actually
     * waited (0 without suspending when [needsWait] is false). Used by the
     * pre-unlock warm-up so its one `GET /` goes to the address whose descriptor
     * is already in Tor's cache instead of queueing on a stalled one.
     */
    suspend fun awaitWinner(url: String, maxMs: Long): Long {
        if (!needsWait(url) || maxMs <= 0) return 0L
        val start = TimeSource.Monotonic.markNow()
        withTimeoutOrNull(maxMs) {
            settled.first { lock.withLock { !waitingLocked() } }
        }
        return start.elapsedNow().inWholeMilliseconds
    }

    /** Caller holds [lock]. Only a race that was actually BEGUN is worth waiting
     *  for: with no control channel nothing was fetched, and the GET must not sit
     *  out [WARMUP_WAIT_MAX_MS] for a decision that cannot come. */
    private fun waitingLocked(): Boolean =
        begunThisState && !resolvedThisState && !(raceOpen && failedThisRace.all { it })

    override fun toString(): String = "RelayAddressRace(${urls.size})"

    /** What [observe] decided for one event. */
    class Observation internal constructor(
        /** Hand the event's action on to the session's [DescriptorHedge]. */
        val feedHedge: Boolean,
        /** The slot this event made the winner, or -1. */
        val wonSlot: Int,
        /** The winner CHANGED (the session's base URL moved). */
        val switched: Boolean,
    ) {
        override fun toString(): String = "Observation($feedHedge, $wonSlot, $switched)"
    }

    companion object {
        /** Up to three comma-separated entries in relayOnionUrl / relayDevOnionUrl. */
        const val MAX_ADDRESSES: Int = 3

        /**
         * Upper bound on how long the pre-unlock warm-up waits for the race
         * before sending its `GET /` anyway (to the current address). Counted
         * INSIDE the warm-up's own 25 s attempt budget, so the full-budget
         * classification is unchanged: a healthy race decides in 0.5–2 s, and a
         * race with no winner after 15 s still leaves the GET
         * [RelayWarmup.RACE_MIN_GET_SECONDS].
         */
        const val WARMUP_WAIT_MAX_MS: Long = 15_000L

        /** `descriptor race started (2 addresses)` — fixed text + the count. */
        fun startedPhrase(addresses: Int): String = "descriptor race started ($addresses addresses)"

        /** `descriptor race won by address 2 of 2` — fixed text + slot number + count. */
        fun wonPhrase(slotNumber: Int, addresses: Int): String =
            "descriptor race won by address $slotNumber of $addresses"

        /** `address 2 of 3 set aside after no answer - using address 1` — fixed
         *  text + slot NUMBERS + the count; uncoded, never an address. */
        fun demotedPhrase(slotNumber: Int, nowSlotNumber: Int, addresses: Int): String =
            "address $slotNumber of $addresses set aside after no answer - using address $nowSlotNumber"

        private fun line(text: String) {
            platformLog("TorManager", text)
            ConnectionLog.append(ConnectionLog.Kind.TOR, text)
        }
    }
}

/**
 * The process-wide race for the relay this binary talks to
 * ([RelayConfig.CANDIDATE_URLS]). Process-wide because it describes Tor's
 * descriptor cache, which outlives a session on Android (the bounded Tor
 * keep-alive hands a warm daemon to the next session) and is per-process on iOS.
 */
object RelayEndpoints {
    private val lazyRace = lazy { RelayAddressRace(RelayConfig.CANDIDATE_URLS) }

    /** The race over [RelayConfig.CANDIDATE_URLS]. */
    val race: RelayAddressRace get() = lazyRace.value

    /**
     * [RelayAddressRace.resolve] when the race exists, else [url] unchanged —
     * never initialises [RelayConfig] itself, so a unit test holding its own URL
     * is untouched.
     */
    fun resolve(url: String): String = if (lazyRace.isInitialized()) lazyRace.value.resolve(url) else url

    /** The race when it exists AND has ≥ 2 addresses, else null. Never
     *  initialises [RelayConfig] (same reason as [resolve]); in production the
     *  race exists from the first `RelayConfig.BASE_URL` read. */
    fun racingOrNull(): RelayAddressRace? =
        if (lazyRace.isInitialized()) lazyRace.value.takeIf { it.isRacing } else null

    /**
     * A real relay answer on [url] ([RelayAddressRace.noteRelayAnswered]) — only
     * when [url] is one of the race's addresses, so a test or a client holding some
     * other URL never touches the process-wide race. Never initialises [RelayConfig].
     */
    fun noteRelayAnswered(url: String) {
        val race = racingOrNull() ?: return
        if (url in race.urls) race.noteRelayAnswered()
    }

    /**
     * The stall ladder gave up on the current attempt:
     * [RelayAddressRace.demoteUnansweredWinner], or -1 when there is no race.
     * Platform call sites: Android `RunViewModel.restartTor`; iOS
     * `AppState.maybeLatchStalled` / `reconnectRelay`. Never in external SOCKS
     * proxy mode (the callers gate it) and never pre-unlock.
     */
    fun demoteUnansweredWinner(): Int = racingOrNull()?.demoteUnansweredWinner() ?: -1

    /**
     * The rendezvous hedge's descriptor reference time
     * ([RelayAddressRace.descriptorReceivedAtMs]) — single address or several.
     * Null when the race does not exist (never initialises [RelayConfig]: a unit
     * test with its own URL never hedges unless it injects a time itself).
     */
    fun descriptorReceivedAtMs(): Long? =
        if (lazyRace.isInitialized()) lazyRace.value.descriptorReceivedAtMs() else null
}

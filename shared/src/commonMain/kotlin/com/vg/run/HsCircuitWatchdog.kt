package com.vg.run

import kotlin.time.TimeSource

/**
 * HUNG ONION-CIRCUIT RUNG (2026-10-08) — close the one circuit that hung, not
 * the whole identity.
 *
 * Evidence (prod Android connects 1 and 7, device-run iOS cycle 4, 2026-10-08): the
 * descriptor was received, the rendezvous circuit built, `introduction circuit
 * launched` — and never `built` for 22–30 s, while healthy intro circuits build
 * in 0.4–1.0 s on every device measured. The only rescue was the warm-up's 25 s
 * budget → NEWNYM (or the 40 s cold rung), after which a fresh intro circuit
 * built in 0.5 s. Mirror image (device-run iOS cycle 9): `introduction complete` but
 * no `rendezvous joined` for 26 s (that rendezvous circuit later failed TIMEOUT).
 *
 * WHY `CLOSECIRCUIT` AND NOT NEWNYM: closing the hung circuit makes Tor's own HS
 * client logic retry — the next introduction point, or a fresh rendezvous point
 * — while every other circuit, the descriptor and the guard state stay as they
 * are. No identity rotation, no descriptor re-fetch, no NEWNYM budget spent;
 * the NEWNYM rungs stay the backstop.
 *
 * RULES (pure; unit-tested in HsCircuitWatchdogTest):
 *  - BUILD (both purposes, 2026-10-08 rev b): an `HS_CLIENT_INTRO` OR
 *    `HS_CLIENT_REND` circuit seen LAUNCHED / EXTENDED / CANNIBALIZED and not
 *    BUILT within [HS_CIRCUIT_BUILD_STALL_FIRST_MS] (the first close of that
 *    kind this process; [HS_CIRCUIT_BUILD_STALL_MS] after) → close THAT circuit. Device-run
 *    iOS cycle 3 (17.9 s): intro built in 0.4 s, the RENDEZVOUS circuit launched and
 *    never built for 23 s — Tor cannot send INTRODUCE1 without the rendezvous
 *    cookie, so `introduction sent` never came and the JOIN rule below never
 *    armed. The morning's prod cases were the mirror (rend built, intro hung):
 *    both kinds stall in the build phase.
 *  - ESTABLISH (2026-10-09, device-run iOS cycle 8): an `HS_CLIENT_REND` circuit
 *    BUILT with no `HSCR_ESTABLISHED_IDLE` (Tor's RENDEZVOUS_ESTABLISHED ack)
 *    within [HS_REND_ESTABLISH_STALL_MS] → close it. Healthy acks land in
 *    ≤ 0.3 s; in that cycle the rendezvous circuit built at +48 s, the intro
 *    circuit built 0.1 s later, and `introduction sent` NEVER came for 34.8 s —
 *    Tor sends INTRODUCE1 only over a READY rendezvous circuit, so the build
 *    rule (circuit was built) and the join rule (no introduction) were both
 *    blind. Any `introduction sent` / `introduction complete` proves SOME
 *    rendezvous circuit is ready and disarms every establish timer.
 *  - JOIN: `introduction complete` (intro HSCI_DONE after HSCI_INTRO_SENT) with
 *    no `HSCR_JOINED` within [HS_REND_JOIN_STALL_MS] → close the rendezvous
 *    circuit (the one waiting for the join, else the newest candidate).
 *  - STREAM (2026-10-09, device-run iOS cycle 8 probe #2 and A20e cycle 4): a
 *    `STREAM … SENTCONNECT <circ> <our onion>:<port>` with no SUCCEEDED / FAILED /
 *    CLOSED / DETACHED within [HS_STREAM_CONNECT_STALL_MS] → close the circuit
 *    the stream rides (its rendezvous circuit). A healthy BEGIN → CONNECTED on
 *    a joined rendezvous circuit is one round trip (< 1 s); the stalled ones sat
 *    14.4 s and 20 s.
 *  - Only before the session's first relay answer ([due]'s input); afterwards
 *    the post-answer stall ladder owns it and tracking is dropped.
 *  - At most [MAX_CLOSES_PER_TOR] closes per Tor process (all four rules
 *    together); never within [NEWNYM_GUARD_MS] of an accepted NEWNYM (which
 *    already killed every circuit — [noteNewnym] also clears the tracking).
 *  - OUR onion only: Tor stamps `REND_QUERY=<onion>` once the circuit has its HS
 *    identity (not yet on the LAUNCHED event). A circuit whose REND_QUERY names
 *    another service is dropped; one without REND_QUERY yet is accepted — before
 *    the first relay answer this app dials no other onion. A STREAM's target is
 *    compared the same way. The address is compared, never copied out.
 *  - Tor answers `CLOSECIRCUIT` with `250` or `552 Unknown circuit` — the
 *    latter means "already gone"; nothing is ever retried.
 *
 * GUARD-CHANNEL KICK DECISION (2026-10-09, see [Decision.channelKick]): when two
 * closes hit circuits that share the SAME FIRST HOP, or the close budget runs
 * out with another stall pending, the evidence points below the circuits — at
 * the TLS channel to an entry guard (a test iPhone 11, 2026-10-08: circuits stalled →
 * closed → rebuilt → stalled again until Tor reported CHANNEL_CLOSED at +75 s,
 * after which circuits built in 5 s). The platform then re-opens every network
 * connection (`SETCONF DisableNetwork=1/0`) — same guards, fresh channels, no
 * identity change. At most [CHANNEL_KICK_MAX_PER_TOR] per Tor process, never
 * within [CHANNEL_KICK_NEWNYM_SPACING_MS] of an accepted NEWNYM.
 *
 * IDENTIFIERS: the circuit id is needed to address `CLOSECIRCUIT` and nothing
 * else — it lives in [Closure]'s `internal` field (Swift reads it through
 * [Closure.commandArgument] only), is validated to be 1–10 ASCII digits, and is
 * never logged. The FIRST HOP of a circuit's path (a relay fingerprint) is held
 * in RAM solely to compare two closes for equality — it has no accessor, is in
 * no `toString`, and is dropped at every reset. Stream ids are pairing keys
 * only. The only lines are the fixed phrases below.
 *
 * Thread-safe (lock-guarded): iOS observes on Tor's control queue and decides on
 * the main actor; Android observes on the event reader and decides on IO.
 */
class HsCircuitWatchdog {

    /** One `CLOSECIRCUIT` to send. [circuitId] is an identifier — never log it. */
    class Closure internal constructor(internal val circuitId: String, val kind: Kind) {
        /** What hung: the intro circuit, the rendezvous circuit, or a stream on it. */
        enum class Kind { INTRO, REND, STREAM }

        /** The `CLOSECIRCUIT` argument (the validated numeric id). Never log it. */
        fun commandArgument(): String = circuitId

        override fun toString(): String = "Closure($kind)"
    }

    /** What [due] decided: closures to send now, whether the budget was found
     *  spent just now (log [BUDGET_SPENT_PHRASE] once), and whether the
     *  guard-channel kick is due now (consumes the per-process kick budget). */
    class Decision internal constructor(
        val closures: List<Closure>,
        val budgetSpentNow: Boolean,
        val channelKick: Boolean = false,
    ) {
        override fun toString(): String = "Decision(${closures.size}, $budgetSpentNow, $channelKick)"
    }

    private class Rend(var state: String?, val seenAtMs: Long)

    private val lock = SyncLock()
    private class PendingBuild(val sinceMs: Long, val kind: Closure.Kind)
    private class PendingStream(val circuitId: String, val sinceMs: Long)

    /** Intro AND rendezvous circuits not yet BUILT: id → first sighting + kind. */
    private val pendingBuilds = LinkedHashMap<String, PendingBuild>()
    /** Rendezvous circuits BUILT but not yet ESTABLISHED: id → built at. */
    private val pendingEstablish = LinkedHashMap<String, Long>()
    /** Streams to our onion with BEGIN sent and no outcome yet: stream id → circuit + since. */
    private val pendingStreams = LinkedHashMap<String, PendingStream>()
    /** Rendezvous circuits not yet JOINED: id → state. */
    private val rends = LinkedHashMap<String, Rend>()
    /** First hop of every tracked HS circuit (RAM only, equality only — never read out). */
    private val firstHops = LinkedHashMap<String, String>()
    /** How many closes each first hop has collected this Tor process (since the last kick). */
    private val closesPerFirstHop = HashMap<String, Int>()
    /** When `introduction complete` armed the join timer; null = not armed. */
    private var introDoneAtMs: Long? = null
    private var lastNewnymAtMs: Long? = null
    private var closesSent = 0
    /** BUILD-rule closes per circuit kind this Tor process — the first one of
     *  each kind fires at [HS_CIRCUIT_BUILD_STALL_FIRST_MS], the rest at
     *  [HS_CIRCUIT_BUILD_STALL_MS]. Survives NEWNYM/kick like [closesSent]. */
    private val buildClosesPerKind = HashMap<Closure.Kind, Int>()
    private var budgetSpentReported = false
    /** The kick evidence is in; waits only for the NEWNYM spacing. */
    private var kickWanted = false
    private var kicksFired = 0

    // ---------------------------------------------------------------- input

    /** [observeAt] on the watchdog's own monotonic clock. */
    fun observe(rawEventLine: String, relayOnionAddress: String?): Long? =
        observeAtAll(rawEventLine, listOf(relayOnionAddress), nowMs())

    /** [observe] against EVERY configured address of the relay (2026-10-23,
     *  [RelayAddressRace.hsFetchAddresses]): a circuit / stream to any of them is
     *  ours. Equality only — no address is copied out. */
    fun observe(rawEventLine: String, relayOnionAddresses: List<String>): Long? =
        observeAtAll(rawEventLine, relayOnionAddresses, nowMs())

    /**
     * Feeds ONE control event line (with or without the `650 ` prefix). Returns
     * the delay in ms after which the platform should call [due] (a timer was
     * armed by this event), else null.
     */
    internal fun observeAt(rawEventLine: String, relayOnionAddress: String?, nowMs: Long): Long? =
        observeAtAll(rawEventLine, listOf(relayOnionAddress), nowMs)

    internal fun observeAtAll(rawEventLine: String, relayOnionAddresses: List<String?>, nowMs: Long): Long? {
        val ours = relayOnionAddresses.filterNot { it.isNullOrEmpty() }.map { it!! }
        if (ours.isEmpty()) return null
        var line = rawEventLine.trimEnd('\r', '\n')
        if (line.length >= 4 && line.startsWith("650") && (line[3] == ' ' || line[3] == '-')) line = line.substring(4)
        val tokens = line.split(' ').filter { it.isNotEmpty() }
        if (tokens.size < 3) return null
        val minor = when (tokens[0]) {
            "CIRC" -> false
            "CIRC_MINOR" -> true
            "STREAM" -> return observeStream(tokens, ours, nowMs)
            else -> return null
        }
        val id = tokens[1].takeIf { isValidCircuitId(it) } ?: return null
        val status = tokens[2].uppercase()
        val purpose = kw(tokens, "PURPOSE")?.uppercase()
        val hsState = kw(tokens, "HS_STATE")?.uppercase()
        val oldHsState = kw(tokens, "OLD_HS_STATE")?.uppercase()
        val query = kw(tokens, "REND_QUERY")
        val firstHop = firstHopOf(tokens)
        return lock.withLock {
            // Another service's circuit (equality only — never copied out).
            if (query != null && ours.none { query.removeSuffix(".onion").equals(it, ignoreCase = true) }) {
                untrack(id)
                return@withLock null
            }
            val terminal = !minor && (status == "FAILED" || status == "CLOSED")
            if (!terminal && firstHop != null && (purpose == "HS_CLIENT_INTRO" || purpose == "HS_CLIENT_REND")) {
                rememberFirstHop(id, firstHop)
            }
            when (purpose) {
                "HS_CLIENT_INTRO" -> {
                    rends.remove(id)
                    pendingEstablish.remove(id)
                    if (pendingBuilds[id]?.kind == Closure.Kind.REND) pendingBuilds.remove(id)
                    when {
                        terminal -> { pendingBuilds.remove(id); firstHops.remove(id); null }
                        // Past the build: sent / acked / re-connecting after a NACK.
                        // INTRODUCE1 only goes out over a READY rendezvous circuit,
                        // so either state also proves the establish phase is done.
                        hsState == "HSCI_INTRO_SENT" -> {
                            pendingBuilds.remove(id)
                            pendingEstablish.clear()
                            null
                        }
                        hsState == "HSCI_DONE" -> {
                            pendingBuilds.remove(id)
                            if (oldHsState == null || oldHsState == "HSCI_INTRO_SENT") {
                                pendingEstablish.clear()
                                // `introduction complete`: arm the join timer.
                                introDoneAtMs = nowMs
                                HS_REND_JOIN_STALL_MS
                            } else null
                        }
                        !minor && status == "BUILT" -> { pendingBuilds.remove(id); null }
                        isBuildingEvent(minor, status, hsState, "HSCI_CONNECTING") ->
                            armBuild(id, Closure.Kind.INTRO, nowMs)
                        else -> null
                    }
                }
                "HS_CLIENT_REND" -> {
                    if (pendingBuilds[id]?.kind == Closure.Kind.INTRO) pendingBuilds.remove(id)
                    when {
                        terminal -> {
                            rends.remove(id); pendingBuilds.remove(id); pendingEstablish.remove(id)
                            firstHops.remove(id)
                            null
                        }
                        hsState == "HSCR_JOINED" -> {
                            // The onion session is up: nothing left to watch.
                            rends.clear()
                            pendingEstablish.clear()
                            pendingBuilds.entries.removeAll { it.value.kind == Closure.Kind.REND }
                            introDoneAtMs = null
                            null
                        }
                        else -> {
                            val r = rends[id]
                            if (r == null) rends[id] = Rend(hsState, nowMs) else if (hsState != null) r.state = hsState
                            when {
                                // Any ESTABLISHED state: built AND acknowledged.
                                hsState == "HSCR_ESTABLISHED_IDLE" || hsState == "HSCR_ESTABLISHED_WAITING" -> {
                                    pendingBuilds.remove(id)
                                    pendingEstablish.remove(id)
                                    null
                                }
                                // BUILT: the build is done, the RENDEZVOUS_ESTABLISHED
                                // ack is now owed (the ESTABLISH rule).
                                !minor && status == "BUILT" -> {
                                    pendingBuilds.remove(id)
                                    if (id in pendingEstablish) null
                                    else {
                                        pendingEstablish[id] = nowMs
                                        HS_REND_ESTABLISH_STALL_MS
                                    }
                                }
                                isBuildingEvent(minor, status, hsState, "HSCR_CONNECTING") ->
                                    armBuild(id, Closure.Kind.REND, nowMs)
                                else -> null
                            }
                        }
                    }
                }
                // Any other purpose: this id is not (or no longer) an HS client
                // circuit we watch (purpose changes, GENERAL, HSDIR, …).
                else -> { untrack(id); null }
            }
        }
    }

    /**
     * `STREAM <StreamID> <Status> <CircuitID> <Target> …` — the STREAM rule.
     * Target is `<host>:<port>`; only its host is compared with the relay's
     * address (equality, never copied out). A SENTCONNECT whose circuit id is
     * not a plain number (`0` = unattached is filtered too) is ignored.
     */
    private fun observeStream(tokens: List<String>, relayOnionAddresses: List<String>, nowMs: Long): Long? {
        if (tokens.size < 3) return null
        val streamId = tokens[1].takeIf { isValidCircuitId(it) } ?: return null
        val status = tokens[2].uppercase()
        return lock.withLock {
            when (status) {
                "SENTCONNECT" -> {
                    if (tokens.size < 5) return@withLock null
                    val circ = tokens[3].takeIf { isValidCircuitId(it) && it != "0" } ?: return@withLock null
                    val host = tokens[4].substringBeforeLast(':').removeSuffix(".onion")
                    if (relayOnionAddresses.none { host.equals(it, ignoreCase = true) }) return@withLock null
                    if (streamId in pendingStreams) return@withLock null
                    pendingStreams[streamId] = PendingStream(circ, nowMs)
                    HS_STREAM_CONNECT_STALL_MS
                }
                // An outcome (or Tor moving the stream to another circuit, which
                // brings a fresh SENTCONNECT): stop watching this one.
                "SUCCEEDED", "FAILED", "CLOSED", "DETACHED" -> { pendingStreams.remove(streamId); null }
                else -> null
            }
        }
    }

    /** LAUNCHED / EXTENDED (CIRC), or CANNIBALIZED / PURPOSE_CHANGED (CIRC_MINOR)
     *  while still in the purpose's connecting state: a circuit being built. */
    private fun isBuildingEvent(minor: Boolean, status: String, hsState: String?, connecting: String): Boolean =
        (!minor && (status == "LAUNCHED" || status == "EXTENDED")) ||
            (minor && (status == "CANNIBALIZED" || status == "PURPOSE_CHANGED") &&
                (hsState == null || hsState == connecting))

    /** Starts the build clock at the FIRST sighting only. */
    private fun armBuild(id: String, kind: Closure.Kind, nowMs: Long): Long? {
        if (id in pendingBuilds) return null
        pendingBuilds[id] = PendingBuild(nowMs, kind)
        return buildStallMs(kind)
    }

    /** The BUILD rule's threshold for [kind] right now: 3 s until this process
     *  has closed one circuit of that kind, 6 s from then on (2026-10-26). */
    private fun buildStallMs(kind: Closure.Kind): Long =
        if ((buildClosesPerKind[kind] ?: 0) == 0) HS_CIRCUIT_BUILD_STALL_FIRST_MS else HS_CIRCUIT_BUILD_STALL_MS

    /** An app-fired NEWNYM was accepted: it killed every circuit, so drop all
     *  tracking and hold closes off for [NEWNYM_GUARD_MS]. The per-first-hop
     *  close counts SURVIVE it — NEWNYM keeps the guards, so evidence against a
     *  guard's channel is still evidence after it. */
    fun noteNewnym() = noteNewnymAt(nowMs())

    internal fun noteNewnymAt(nowMs: Long) {
        lock.withLock {
            lastNewnymAtMs = nowMs
            clearCircuitTrackingLocked()
        }
    }

    /** The platform performed the guard-channel kick: every circuit died with
     *  its channel, so tracking and the per-first-hop evidence start over. Holds
     *  closes off for [NEWNYM_GUARD_MS], like a NEWNYM.
     *
     *  The kick also starts a new CHANNEL EPOCH, and the close budget is per
     *  epoch (2026-10-13, A20e device-run cycles of 152 s / 86 s): Tor relaunches the
     *  intro + rendezvous circuits on the reopened channels, and when the fresh
     *  rendezvous never reported BUILT the budget spent BEFORE the kick left the
     *  watchdog disarmed exactly then, so the session sat two 20 s probe
     *  timeouts until the cold-rung NEWNYM. Only the kick renews it, and
     *  [CHANNEL_KICK_MAX_PER_TOR] stays 1, so the worst case is bounded at
     *  2 × [MAX_CLOSES_PER_TOR] closes per Tor process.
     *
     *  Returns true iff spent budget was renewed (the caller then logs
     *  [BUDGET_RENEWED_PHRASE]). */
    fun noteChannelKick(): Boolean = noteChannelKickAt(nowMs())

    internal fun noteChannelKickAt(nowMs: Long): Boolean = lock.withLock {
        lastNewnymAtMs = nowMs
        clearCircuitTrackingLocked()
        closesPerFirstHop.clear()
        kickWanted = false
        val renewed = closesSent > 0
        closesSent = 0
        budgetSpentReported = false
        renewed
    }

    /** A fresh Tor child (Android's corrupt-state retry): everything resets. */
    fun resetForNewTorProcess() {
        lock.withLock {
            clearCircuitTrackingLocked()
            closesPerFirstHop.clear()
            lastNewnymAtMs = null
            closesSent = 0
            budgetSpentReported = false
            kickWanted = false
            kicksFired = 0
        }
    }

    private fun clearCircuitTrackingLocked() {
        pendingBuilds.clear()
        pendingEstablish.clear()
        pendingStreams.clear()
        rends.clear()
        firstHops.clear()
        introDoneAtMs = null
    }

    // ------------------------------------------------------------- decision

    /** [dueAt] on the watchdog's own monotonic clock. */
    fun due(relayAnsweredThisSession: Boolean): Decision = dueAt(relayAnsweredThisSession, nowMs())

    /**
     * The closes due now. Each returned [Closure] has ALREADY consumed one unit of
     * the per-process budget and left the tracking, so a repeated call can never
     * send the same close twice. Idempotent otherwise.
     */
    internal fun dueAt(relayAnsweredThisSession: Boolean, nowMs: Long): Decision = lock.withLock {
        if (relayAnsweredThisSession) {
            clearCircuitTrackingLocked()
            closesPerFirstHop.clear()
            kickWanted = false
            return@withLock Decision(emptyList(), false)
        }
        val newnymAt = lastNewnymAtMs
        if (newnymAt != null && nowMs - newnymAt < NEWNYM_GUARD_MS) return@withLock Decision(emptyList(), false)

        val wanted = ArrayList<Closure>()
        fun want(id: String, kind: Closure.Kind) {
            if (wanted.none { it.circuitId == id }) wanted += Closure(id, kind)
        }
        for ((id, p) in pendingBuilds) {
            if (nowMs - p.sinceMs >= buildStallMs(p.kind)) {
                want(id, p.kind)
                // Counted when WANTED, sent or not: a stall the budget could not
                // close is evidence all the same, and the next circuit of that
                // kind gets the full 6 s either way.
                buildClosesPerKind[p.kind] = (buildClosesPerKind[p.kind] ?: 0) + 1
            }
        }
        for ((id, builtAt) in pendingEstablish) {
            if (nowMs - builtAt >= HS_REND_ESTABLISH_STALL_MS) want(id, Closure.Kind.REND)
        }
        // Snapshot (stream id, circuit id) BEFORE touching the map: on Kotlin/Native
        // a map entry is a VIEW into the backing map and reading it after any
        // modification throws ConcurrentModificationException (the JVM's entry is a
        // detached node, so the JVM suite never saw it — crashed the iPhone 12 at
        // the first stream stall, 2026-10-09; HsCircuitWatchdogTest on
        // iosSimulatorArm64Test is the guard).
        val streamsDue = pendingStreams.entries
            .filter { nowMs - it.value.sinceMs >= HS_STREAM_CONNECT_STALL_MS }
            .map { it.key to it.value.circuitId }
        for ((streamId, circuitId) in streamsDue) {
            pendingStreams.remove(streamId)
            want(circuitId, Closure.Kind.STREAM)
        }
        val doneAt = introDoneAtMs
        if (doneAt != null && nowMs - doneAt >= HS_REND_JOIN_STALL_MS) {
            introDoneAtMs = null
            val target = rends.entries.lastOrNull { it.value.state == "HSCR_ESTABLISHED_WAITING" }
                ?: rends.entries.maxByOrNull { it.value.seenAtMs }
            if (target != null) want(target.key, Closure.Kind.REND)
        }
        val out = ArrayList<Closure>()
        var spentNow = false
        for (c in wanted) {
            val hop = firstHops[c.circuitId]
            // Leaves the tracking whether or not it is sent: a circuit the budget
            // could not close is the NEWNYM rungs' (or the kick's) business now.
            untrack(c.circuitId)
            if (closesSent < MAX_CLOSES_PER_TOR) {
                closesSent++
                out += c
                if (hop != null) {
                    val n = (closesPerFirstHop[hop] ?: 0) + 1
                    closesPerFirstHop[hop] = n
                    if (n >= CHANNEL_KICK_SAME_HOP_CLOSES) kickWanted = true
                }
            } else {
                // Another stall with the close budget gone: below the circuits.
                kickWanted = true
                if (!budgetSpentReported) {
                    budgetSpentReported = true
                    spentNow = true
                }
            }
        }
        var kick = false
        if (kickWanted && kicksFired < CHANNEL_KICK_MAX_PER_TOR) {
            val sinceNewnym = newnymAt?.let { nowMs - it }
            if (sinceNewnym == null || sinceNewnym >= CHANNEL_KICK_NEWNYM_SPACING_MS) {
                kick = true
                kicksFired++
                kickWanted = false
            }
        }
        Decision(out, spentNow, kick)
    }

    /** ms until the earliest armed deadline (pushed past the NEWNYM guard), or
     *  null when nothing is armed. Platforms re-schedule [due] with it after
     *  every check, which is how a guard-deferred close — and a kick deferred by
     *  the NEWNYM spacing — still happens. */
    fun msUntilNextDeadline(): Long? = msUntilNextDeadlineAt(nowMs())

    internal fun msUntilNextDeadlineAt(nowMs: Long): Long? = lock.withLock {
        val deadlines = ArrayList<Long>()
        pendingBuilds.values.forEach { deadlines += it.sinceMs + buildStallMs(it.kind) }
        pendingEstablish.values.forEach { deadlines += it + HS_REND_ESTABLISH_STALL_MS }
        pendingStreams.values.forEach { deadlines += it.sinceMs + HS_STREAM_CONNECT_STALL_MS }
        introDoneAtMs?.let { deadlines += it + HS_REND_JOIN_STALL_MS }
        val guarded = deadlines.minOrNull()?.let { earliest ->
            lastNewnymAtMs?.let { maxOf(earliest, it + NEWNYM_GUARD_MS) } ?: earliest
        }
        val kickAt = if (kickWanted && kicksFired < CHANNEL_KICK_MAX_PER_TOR) {
            lastNewnymAtMs?.let { it + CHANNEL_KICK_NEWNYM_SPACING_MS } ?: nowMs
        } else null
        val next = listOfNotNull(guarded, kickAt).minOrNull() ?: return@withLock null
        (next - nowMs).coerceAtLeast(0L)
    }

    private fun untrack(id: String) {
        pendingBuilds.remove(id)
        pendingEstablish.remove(id)
        rends.remove(id)
        firstHops.remove(id)
        pendingStreams.entries.removeAll { it.value.circuitId == id }
    }

    /** Bounded: an event storm can never grow the map past [MAX_TRACKED_HOPS]. */
    private fun rememberFirstHop(id: String, hop: String) {
        if (id !in firstHops && firstHops.size >= MAX_TRACKED_HOPS) {
            firstHops.keys.firstOrNull()?.let { firstHops.remove(it) }
        }
        firstHops[id] = hop
    }

    private fun kw(tokens: List<String>, key: String): String? {
        val p = "$key="
        return tokens.firstOrNull { it.startsWith(p) }?.substring(p.length)
    }

    /** The path's first element's FINGERPRINT (`$<40 hex>`), or null. Lives
     *  only inside this class (equality only) — see the IDENTIFIERS note. */
    private fun firstHopOf(tokens: List<String>): String? {
        val path = tokens.getOrNull(3)?.takeIf { it.startsWith("$") } ?: return null
        val fp = path.substringBefore(',').substringBefore('~').substringBefore('=')
        return fp.takeIf { it.length in 2..41 }
    }

    override fun toString(): String = "HsCircuitWatchdog"

    companion object {
        /** THE FIRST build-stall close of each circuit kind per Tor process
         *  (2026-10-26, connect-time lever). Evidence, 101 prod cold launches
         *  (iPhone 11, 1.6.49, one network): healthy intro circuits built in
         *  p50 0.49 s / max 1.38 s (n=70), rendezvous circuits p50 0.26 s / p95
         *  0.71 s (n=75, two outliers at 3.07 and 4.24 s); the 14 stalled ones
         *  never built until the 6 s close, after which the replacement built in
         *  0.2–1.3 s. Those stalls WERE the connect tail: descriptor→join p90
         *  7.8 s against a p50 of 1.7 s. 3 s saves ~3 s on 14 % of cold opens at
         *  the cost of closing ~1 healthy circuit in 70 (~0.6 s). Slow mobile
         *  networks are unmeasured, hence the escalation: the first close of a
         *  kind is the cheap bet, every later one waits the full
         *  [HS_CIRCUIT_BUILD_STALL_MS]. */
        const val HS_CIRCUIT_BUILD_STALL_FIRST_MS = 3_000L

        /** Healthy intro AND rendezvous circuits build in 0.4–1.0 s on every
         *  device measured (2026-10-08); the stalled ones (intro: prod Android
         *  connects 1 + 7, device-run iOS cycle 4; rendezvous: device-run iOS cycle 3)
         *  never did within 22–30 s. Since 2026-10-26 this is the threshold for
         *  the SECOND and later build-stall close of a kind — see
         *  [HS_CIRCUIT_BUILD_STALL_FIRST_MS]. */
        const val HS_CIRCUIT_BUILD_STALL_MS = 6_000L

        /** Built → RENDEZVOUS_ESTABLISHED is one round trip on a built circuit:
         *  ≤ 0.3 s in every healthy timeline of 2026-10-08 (both platforms); the
         *  stalled one (device-run iOS cycle 8) never acked in 34.8 s. */
        const val HS_REND_ESTABLISH_STALL_MS = 3_000L

        /** Ack → join is one round trip through the rendezvous point; the stalled
         *  one (device-run iOS cycle 9) waited 26 s and then failed TIMEOUT. */
        const val HS_REND_JOIN_STALL_MS = 8_000L

        /** BEGIN → CONNECTED on a joined rendezvous circuit: < 1 s healthy; the
         *  stalled ones took 14.4 s (A20e) and never (ios7 probe #2). */
        const val HS_STREAM_CONNECT_STALL_MS = 8_000L

        /** Closes per Tor process before the first relay answer, all rules
         *  together. Four, because the ESTABLISH and STREAM rules share
         *  it: one ios7-shaped connect spends a STREAM close and an ESTABLISH
         *  close before the build/join rules ever arm. */
        const val MAX_CLOSES_PER_TOR = 4

        /** No close within this long after an accepted NEWNYM (or channel kick). */
        const val NEWNYM_GUARD_MS = 2_000L

        /** Closes that must share ONE first hop before the channel kick is due. */
        const val CHANNEL_KICK_SAME_HOP_CLOSES = 2

        /** Guard-channel kicks per Tor process. */
        const val CHANNEL_KICK_MAX_PER_TOR = 1

        /** No kick within this long after an accepted NEWNYM — same spacing the
         *  bootstrap-stall kick keeps ([TorBootstrapStall.NEWNYM_SPACING_MS]). */
        const val CHANNEL_KICK_NEWNYM_SPACING_MS = 10_000L

        private const val MAX_TRACKED_HOPS = 64

        const val INTRO_PHRASE = "introduction circuit stalled - closing it so Tor retries"
        const val REND_PHRASE = "rendezvous circuit stalled - closing it so Tor retries"
        const val STREAM_PHRASE = "relay stream stalled - closing its circuit so Tor retries"
        const val BUDGET_SPENT_PHRASE = "circuit close budget spent"
        const val BUDGET_RENEWED_PHRASE = "circuit close budget renewed after network reopen"
        const val CHANNEL_KICK_PHRASE = "guard connection stalled - reopening network connections"
        const val CHANNEL_KICK_SKIP_PHRASE = "guard connection stalled - network reopen unavailable"
        const val SOCKS_MOVED_PHRASE = "network reopened - SOCKS listener moved"
        const val SOCKS_LOST_PHRASE = "network reopened - SOCKS listener not found"

        /** Tor's `CLOSECIRCUIT` ids are numeric; only this shape reaches the
         *  authenticated control socket. */
        fun isValidCircuitId(id: String): Boolean = id.length in 1..10 && id.all { it in '0'..'9' }

        /** Writes the fixed phrase for [kind] (platform log + coded panel line —
         *  the code names the rung on the telemetry timeline; the relay allowlist
         *  carries it, see [ConnectionLog.Code]). */
        fun logClosing(kind: Closure.Kind) {
            val (phrase, code) = when (kind) {
                Closure.Kind.INTRO -> INTRO_PHRASE to ConnectionLog.Code.INTRO_CIRC_CLOSED
                Closure.Kind.REND -> REND_PHRASE to ConnectionLog.Code.REND_CIRC_CLOSED
                Closure.Kind.STREAM -> STREAM_PHRASE to ConnectionLog.Code.STREAM_CIRC_CLOSED
            }
            platformLog("TorManager", phrase)
            ConnectionLog.append(ConnectionLog.Kind.TOR, phrase, code)
        }

        /** Fixed, uncoded line: the guard-channel kick renewed the close budget. */
        fun logBudgetRenewed() {
            platformLog("TorManager", BUDGET_RENEWED_PHRASE)
            ConnectionLog.append(ConnectionLog.Kind.TOR, BUDGET_RENEWED_PHRASE)
        }

        fun logBudgetSpent() {
            platformLog("TorManager", BUDGET_SPENT_PHRASE)
            ConnectionLog.append(ConnectionLog.Kind.TOR, BUDGET_SPENT_PHRASE, ConnectionLog.Code.CLOSE_BUDGET_SPENT)
        }

        /** The telemetry code for one of the four fixed kick phrases; a phrase
         *  that is not one of them carries no code (a code is never invented
         *  from a string). */
        fun kickCode(phrase: String): ConnectionLog.Code? = when (phrase) {
            CHANNEL_KICK_PHRASE -> ConnectionLog.Code.GUARD_KICK
            CHANNEL_KICK_SKIP_PHRASE -> ConnectionLog.Code.GUARD_KICK_SKIP
            SOCKS_MOVED_PHRASE -> ConnectionLog.Code.SOCKS_MOVED
            SOCKS_LOST_PHRASE -> ConnectionLog.Code.SOCKS_LOST
            else -> null
        }

        /** One of the four fixed kick phrases above, coded via [kickCode]. Both
         *  platforms call this, so the panels read identically. */
        fun logKick(phrase: String) {
            platformLog("TorManager", phrase)
            ConnectionLog.append(ConnectionLog.Kind.STALL, phrase, kickCode(phrase))
        }

        private val CLOCK_ORIGIN = TimeSource.Monotonic.markNow()
        private fun nowMs(): Long = CLOCK_ORIGIN.elapsedNow().inWholeMilliseconds
    }
}

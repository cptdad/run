package com.vg.run

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

// ---------------------------------------------------------------------------
// ConnectionLog — RAM-only ring buffer behind the live connection-log panel.
//
// The panel is reached by triple-tapping the "Connecting to…" caption on the
// main screen and streams what the transport is doing RIGHT NOW: Tor bootstrap
// phases, the relay health probe, the self-heal ladder, session lifecycle.
//
// Unlike [LogBuffer] this is NOT gated on [LoggingState] — the whole point is
// that a RELEASE user stuck on "Connecting…" can see (and read out) why. That
// makes it a potential leak surface, so two rules hold:
//
//  1. PRODUCERS EMIT NO IDENTIFIERS BY CONSTRUCTION. Every call site builds its
//     line from fixed phrases plus numbers. Never an inbox id (not even a
//     shortId), never a capability, never an onion host or URL, never message
//     content, never a contact/group name or alias. Tor's own phase lines are
//     safe because the daemon runs with `SafeLogging 1`.
//  2. [redact] IS DEFENCE IN DEPTH, not the primary control. It strips URLs,
//     `.onion` hosts and any opaque base64url run ≥ 32 chars (which covers both
//     the 32-char inbox id and the 43-char capability) before a line is stored,
//     so a future producer that gets careless leaks a placeholder instead.
//  3. THE PANEL KEEPS EVERYTHING. Nothing is ever filtered OUT of this ring —
//     filtering would hide stuck streams from the one surface a stuck user can
//     read. The stream PAIRING ([Line.streamKey] / [Line.streamShip])
//     only annotates lines so [DebugLogUploader] can leave an uneventful,
//     sub-[SLOW_STREAM_MS] stream out of an UPLOAD; the panel still shows it.
//
// Cleared on lock and on wipe (the same sites that clear [LogBuffer]) so a
// seized locked-but-powered device yields nothing from it.
//
// Timestamps are UTC time-of-day, same arithmetic as [LogEntry.formatted] — the
// relay's own logs are UTC, which is what these lines are usually correlated
// against, and it keeps the formatter deterministic for unit tests.
// ---------------------------------------------------------------------------

object ConnectionLog {

    /** Ring-buffer capacity. Oldest lines are evicted first. */
    const val MAX_LINES = 300

    /**
     * STREAM PAIRING — how long a Tor stream may take from
     * [Code.STREAM_SENT] to [Code.STREAM_OK] before the pair counts as SLOW and
     * becomes worth uploading.
     *
     * The panel keeps every stream line, always: filtering would hide stuck
     * streams, and the connection panel is where a user reads one out. Only
     * what the UPLOADER ships is reduced — >90 % of a real debug-mode
     * upload was per-request plumbing, and a stream that connected in under a
     * second is the single most repeated, least informative pair in it. A slow
     * or failed stream is exactly the opposite and always ships, together with
     * its SENT line. See [DebugLogUploader.streamDisposition].
     */
    internal const val SLOW_STREAM_MS: Long = 5_000L

    /**
     * Bound on [openStreams]. Tor stream ids are a per-process counter, so an
     * entry only leaks when a stream's outcome event never arrives (the tap's
     * 2 s per-code dedupe swallowed it, or the socket dropped mid-request).
     * Past this the OLDEST pending pair is forgotten — its SENT line then falls
     * back to the age rule in [DebugLogUploader.streamDisposition], which ships
     * it. Failing toward shipping is the only safe direction: the alternative is
     * a line that never becomes decidable and stalls the uploader's cursor.
     */
    private const val MAX_OPEN_STREAMS = 64

    /** Opaque-token threshold: an inbox id is 32 chars, a capability 43. */
    internal const val MIN_OPAQUE_TOKEN_LEN = 32

    internal const val PLACEHOLDER_URL = "[url]"
    internal const val PLACEHOLDER_ONION = "[onion]"
    internal const val PLACEHOLDER_TOKEN = "[redacted]"

    /** Which subsystem produced a line. Rendered as the line's prefix tag. */
    enum class Kind { TOR, RELAY, HEALTH, STALL, SYSTEM }

    /**
     * Closed vocabulary a producer may attach to a line, set AT THE PRODUCER
     * (never parsed back out of [Line.text]). A code names a phase transition
     * or an outcome and carries no argument: everything Tor reports next to it
     * (fingerprints, addresses, circuit ids, the onion, SUMMARY/WARNING prose)
     * stays out of both the code and the text. Lines without a code are plain
     * narration for the panel.
     *
     * WHY GROWING THIS LIST IS CHEAP, AND WHERE THE LIMIT ACTUALLY IS (the
     * vocabulary is ~70 entries today and the argument below holds at that size).
     *  - WIRE SIZE does not scale with the vocabulary at all. The connect report
     *    is bounded by [ConnectTelemetry.MAX_LOG_ENTRIES] (48) and its worst case
     *    is derived from the LONGEST NAME here, so the only size cost of a new
     *    code is `48 × (len − 21)` bytes when it is longer than the current
     *    longest (`TOR_BOOTSTRAP_PROBLEM`). Every C2 name is ≤ 20 chars, so the
     *    ceiling arithmetic — and the 450 B of headroom
     *    `payload_worstCaseBodyStaysUnderTheRelayCeiling` asserts — is unchanged.
     *  - ENTROPY. Splitting one code into k does not add a new CHANNEL: no value
     *    is echoed (the tag→code map is a fixed lookup; an unknown token falls
     *    back to the old catch-all), the 5 s offset grid and the dedupe are
     *    untouched, and Tor's bootstrap ladder is MONOTONE and identical on every
     *    client, so what the split adds is WHICH phase of a shared ladder paused —
     *    not a per-device property. The session-linkability limitation documented in
     *    [ConnectTelemetry] (an unusual phase pattern distinguishes two connects)
     *    is unchanged in kind and marginally sharper in degree; it is a known
     *    limitation, and nothing here becomes cross-session (nothing persists).
     *  - The real limit is the RELAY's allowlist, which mirrors this enum and
     *    caps the relay's connect-code metric label cardinality at
     *    2 platforms × |codes|. A code added here without a relay deploy makes the
     *    relay reject the WHOLE report — deliberately loud. Ship the relay first.
     */
    enum class Code {
        // Tor process / bootstrap
        TOR_START, TOR_STOP, TOR_BOOTSTRAP_TAG, TOR_BOOTSTRAP_PROBLEM, SOCKS_READY, CIRCUIT_OK, CIRCUIT_LOST,
        DIR_ENOUGH, DIR_NOT_ENOUGH, NET_UP, NET_DOWN, CLOCK_SKEW, CLOCK_JUMPED,
        TOR_INTERNAL_RETRY, TOR_RELAUNCH_LATCHED, TOR_RESTART,
        // THE BOOTSTRAP LADDER, CODED. A bootstrap line carries a per-phase code rather than the single
        // [TOR_BOOTSTRAP_TAG], so a 70–125 s silence inside the bootstrap is
        // attributable on the wire: "Tor was bootstrapping" says nothing about
        // WHICH phase stalled (guard channel? directory? one-hop? descriptors?).
        // These nine name the phase GROUPS of Tor's own monotone ladder; the
        // mapping from Tor's TAG token lives in [TorBootstrapPhase] (one shared
        // table, both platforms) and an unrecognised tag still falls back to
        // [TOR_BOOTSTRAP_TAG] — a code is never invented from a string.
        TOR_BOOT_STARTING, TOR_BOOT_CONN, TOR_BOOT_HANDSHAKE, TOR_BOOT_ONEHOP,
        TOR_BOOT_DESCRIPTORS, TOR_BOOT_DIRINFO, TOR_BOOT_AP_CONN, TOR_BOOT_CIRCUIT, TOR_BOOT_DONE,
        // THE BOOTSTRAP-STALL RUNG ([TorBootstrapStall]): the percent
        // stood still for 20 s inside the ladder and the network was re-kicked
        // (pipelined `SETCONF DisableNetwork=1/0`), or the kick was due but the
        // command channel could not carry it. Names ≤ 20 chars on purpose (the
        // telemetry ceiling is sized by the longest name). RELAY FIRST: the relay
        // allowlist must carry both before a client sending them ships.
        TOR_BOOT_KICK, TOR_BOOT_KICK_SKIP,
        // Guard channels + directory freshness (a stalled NEW OR connection is what a
        // 45 s CircuitBuildTimeout prices; the consensus age at start separates a
        // warm-but-stale directory from a genuinely warm one — which is the whole
        // reason C2c split the one CONSENSUS_AGE code into the three OUTCOMES:
        // "we asked and the directory was fresh" / "…and it was stale" / "Tor had
        // no consensus to report" are three different explanations of a stall and
        // were indistinguishable in the timeline, where only the code travels)
        ORCONN_LAUNCHED, ORCONN_CONNECTED, ORCONN_FAILED,
        CONSENSUS_FRESH, CONSENSUS_STALE, CONSENSUS_UNKNOWN,
        // Onion service half. The two *_CIRC_LAUNCHED codes (C2d) are the onion
        // twin of ORCONN_LAUNCHED: a LAUNCHED with no BUILT after it is the
        // signature of a circuit that never completed, and until now the panel
        // and the timeline only ever saw the BUILT that did not arrive.
        HSDESC_REQUESTED, HSDESC_RECEIVED, HSDESC_FAILED,
        HSDIR_CIRC_FAILED, INTRO_CIRC_LAUNCHED, INTRO_CIRC_BUILT, INTRO_SENT, INTRO_DONE, INTRO_CIRC_FAILED,
        REND_CIRC_LAUNCHED, REND_CIRC_BUILT, REND_JOINED, REND_CIRC_FAILED,
        STREAM_SENT, STREAM_OK, STREAM_FAILED,
        GUARD_UP, GUARD_DOWN, GUARD_DROPPED,
        // Relay / app side. PROBE_FAILED (C2d) is the probe that came back FAST
        // without an answer — a broken/refused stream, a different fault from the
        // full-budget PROBE_TIMEOUT and must not be lumped in with it.
        WARMUP_STARTED, WARMUP_DONE, WARMUP_FAILED, WARMUP_SKIPPED,
        PROBE_OK, PROBE_TIMEOUT, PROBE_FAILED, PROBE_ERROR, FIRST_ROUNDTRIP,
        NEWNYM, RELAY_STALLED, MANUAL_RECONNECT, APP_BACKGROUNDED, APP_FOREGROUNDED, SESSION_LOCKED,
        // The two relay loops that share the cold circuit with the health probe but were
        // invisible in the panel (a 160 s prod connect had 40 s of "nothing" before probe #1)
        PRIME_PASS, CONTROL_POLL_PASS,
        // THE USER-VISIBLE END OF THE CONNECT. [REVEAL] is the frame the contact list actually appears in — the relay's
        // first answer AND the unread prime having settled — which is LATER than
        // FIRST_ROUNDTRIP and would be invisible to a first-roundtrip measurement.
        // [PRIME_CAP] is the backstop that reveals WITHOUT the prime, i.e. the reveal was
        // held by a wedged peek rather than by the network. Both name a phase transition
        // and carry no argument, like every other code here.
        REVEAL, PRIME_CAP,
        // THE STALL LADDER'S OWN RUNGS ([HsCircuitWatchdog]): a hung
        // intro / rendezvous circuit or a relay stream with no connect outcome was
        // CLOSED so Tor retries; the per-Tor close budget ran out; the guard
        // channel was re-kicked (SETCONF DisableNetwork=1/0) after two closes on
        // the same first hop, or the kick could not be sent; the SOCKS listener
        // moved to a new port after the kick, or could not be found again. Phase
        // names only — no circuit id, port or hop identity travels. Names ≤ 18
        // chars (ceiling unchanged). RELAY FIRST: the relay's LOG_CODES allowlist carries
        // all eight (deployed before any client sending them ships).
        INTRO_CIRC_CLOSED, REND_CIRC_CLOSED, STREAM_CIRC_CLOSED, CLOSE_BUDGET_SPENT,
        GUARD_KICK, GUARD_KICK_SKIP, SOCKS_MOVED, SOCKS_LOST,
        // CONNECT DIAGNOSTICS. [TOR_REUSED] codes the existing Android
        // keep-alive line "reused warm Tor from the previous session" (and the
        // iOS bounded keep-alive's identical warm-return line, BackgroundTorKeepAlive)
        // so a WARM connect (no bootstrap at all) can be told from a cold one on the wire.
        // The five HSDESC_* split [HSDESC_FAILED] by Tor's own REASON keyword via
        // the FIXED map in [TorReasonVocabulary.hsDescFailureCode]; an unknown or
        // missing reason keeps [HSDESC_FAILED]. Names ≤ 19 chars (ceiling
        // unchanged). RELAY FIRST: the relay's LOG_CODES allowlist must carry all six, and
        // be DEPLOYED, before a client sending them ships — an old relay 400s the
        // whole report on an unknown code.
        TOR_REUSED,
        HSDESC_NOT_FOUND, HSDESC_NO_HSDIR, HSDESC_RATE_LIMITED, HSDESC_BAD_DESC, HSDESC_UNEXPECTED,
    }

    data class Line(
        val timestamp: Long,
        val kind: Kind,
        val text: String,
        /** See [Code]. Null for plain narration. */
        val code: Code? = null,
        /**
         * Position in the process-wide [DebugLogSeq] stream, shared with
         * [LogEntry.seq] so this ring and [LogBuffer] merge into ONE ordered
         * stream for [DebugLogUploader]'s cursor. RAM-only, starts at 0 every
         * launch, never persisted, never on the wire (the connect telemetry
         * timeline reads [code] and nothing else). Defaulted so every existing
         * construction site — including the test fixtures — is unchanged.
         */
        val seq: Long = 0L,
        /**
         * RAM-ONLY pairing handle for a `STREAM_*` line — Tor's own stream id,
         * taken off the control-port event purely so a `SENT` can be matched to
         * the `OK`/`FAILED` that ends it, and discarded with the line.
         *
         * IT NEVER LEAVES THIS PROCESS. [formatted] does not render it (so it
         * cannot reach the panel, a screenshot, [LogBuffer] or a debug-mode
         * upload), [ConnectTelemetry] reads [code] and nothing else, and the
         * producer rule stands unchanged: the stream id is NOT put on the line's
         * TEXT. Null for every line that is not a paired stream event.
         */
        val streamKey: Long? = null,
        /**
         * Whether this stream line is worth UPLOADING — `true` ship,
         * `false` skip, `null` not decided yet.
         *
         * Set when the pair RESOLVES: a `STREAM_OK` decides itself and, when the
         * pair was slow, retro-marks its `SENT`; a `STREAM_FAILED` always ships
         * and always marks its `SENT`. A `SENT` whose outcome has not arrived
         * stays `null` and is decided by age at read time — a stream still open
         * past [SLOW_STREAM_MS] IS the slow case. Irrelevant (and always null)
         * for every non-stream line, which always ships.
         */
        val streamShip: Boolean? = null,
    ) {
        /** `HH:mm:ss.SSS KIND text` — what the panel renders. */
        fun formatted(): String = "${formatClock(timestamp)} ${kind.name} $text"
    }

    private val entries = mutableListOf<Line>()
    private val lock = SyncLock()

    /** One un-resolved [Code.STREAM_SENT], by stream key. Guarded by [lock]. */
    private class OpenStream(val seq: Long, val atMs: Long)

    private val openStreams = mutableMapOf<Long, OpenStream>()

    private val _lines = MutableStateFlow<List<Line>>(emptyList())

    /** Newest-last. Compose collects this directly; Swift polls [snapshot]. */
    val lines: StateFlow<List<Line>> = _lines.asStateFlow()

    /**
     * Records one line. Appended from the Tor watcher (Dispatchers.IO), the
     * health-probe thread, the main thread and (on iOS) Tor's own callback
     * queue, so the buffer is lock-guarded exactly like [LogBuffer].
     */
    fun append(kind: Kind, text: String) = append(kind, text, null)

    /** [append] with a producer-set [Code]. Separate overload (not a default
     *  argument) so the two-argument form keeps exporting to Swift unchanged. */
    fun append(kind: Kind, text: String, code: Code?) = append(kind, text, code, null)

    /**
     * [append] with the STREAM PAIRING handle — Tor's own stream id,
     * used only to match a `STREAM_SENT` to the `STREAM_OK`/`STREAM_FAILED`
     * that ends it. Both control-port taps (Android `TorControlEvents.kt`, iOS
     * `TorControlEventTap.swift`) pass it for the three `STREAM_*` codes and
     * `null` for everything else.
     *
     * The id is NOT put on the line's text and never leaves the process — see
     * [Line.streamKey]. A line appended with a null key behaves exactly as it
     * did before this existed: it always ships.
     *
     * A fourth overload rather than a default argument, for the same reason the
     * third one is: the existing Swift/Kotlin call sites keep their selectors.
     */
    fun append(kind: Kind, text: String, code: Code?, streamKey: Long?) {
        appendAt(currentTimeMillis(), kind, text, code, streamKey)
    }

    /**
     * Test seam: [append] with an explicit wall-clock stamp, so the
     * [SLOW_STREAM_MS] pairing threshold can be exercised without a 5 s wait.
     * NEVER called in production — the two producers use [append], which reads
     * the clock inside the lock.
     */
    internal fun appendForTest(kind: Kind, text: String, code: Code?, streamKey: Long?, atMs: Long) {
        appendAt(atMs, kind, text, code, streamKey)
    }

    private fun appendAt(atMs: Long, kind: Kind, text: String, code: Code?, streamKey: Long?) {
        val redacted = redact(text)
        lock.withLock {
            // Clock AND seq are drawn INSIDE the lock, back to back, so the ring
            // stays seq-ordered and a slow redact() above cannot leave this line
            // with an older timestamp than a higher seq (DebugLogUploader sorts
            // by seq and renders clock offsets from the first line).
            val seq = DebugLogSeq.next()
            val ship = resolveStreamLocked(code, streamKey, atMs, seq)
            entries.add(Line(atMs, kind, redacted, code, seq, streamKey, ship))
            // removeAt(0), NOT removeFirst(): on Android `MutableList.removeFirst`
            // resolves to JDK 21's SequencedCollection method, which throws
            // NoSuchMethodError on every older runtime (minSdk 30 devices and the
            // JVM unit-test tier alike). LogBuffer has the same call but never
            // reaches its cap in a test, so it never surfaced there.
            while (entries.size > MAX_LINES) entries.removeAt(0)
            _lines.value = entries.toList()
        }
        // Mirror the CODE (never the text) into LogBuffer, which the e2e harness reads
        // through the in-app log viewer (a long onion blackout after a
        // network restore leaves no phase evidence otherwise: this ring is RAM-only and
        // the session's telemetry has already shipped at its first answer). LogBuffer
        // drops everything unless LoggingState.enabled, which store builds never flip,
        // so this is inert outside logging-enabled debug sessions. Outside the lock:
        // LogBuffer has its own.
        if (code != null) LogBuffer.append("D", "Conn", code.name)
    }

    /**
     * The pairing decision for ONE incoming stream line, under [lock]. Returns
     * the line's own [Line.streamShip] and retro-marks its `SENT` partner when
     * the pair turns out to be worth uploading.
     *
     * A `STREAM_OK` whose `SENT` is not in [openStreams] (the tap's per-code
     * dedupe swallowed it, or the ring evicted it) is skipped: with no start
     * there is no duration, and an unpaired "stream connected" is exactly the
     * content-free plumbing the uploader filter drops. A `STREAM_FAILED` in the same
     * position still ships — a failure is never plumbing.
     */
    private fun resolveStreamLocked(code: Code?, streamKey: Long?, atMs: Long, seq: Long): Boolean? {
        if (streamKey == null) return null
        return when (code) {
            Code.STREAM_SENT -> {
                if (openStreams.size >= MAX_OPEN_STREAMS) {
                    val oldest = openStreams.entries.minByOrNull { it.value.seq }?.key
                    if (oldest != null) openStreams.remove(oldest)
                }
                openStreams[streamKey] = OpenStream(seq, atMs)
                null                       // undecided until its outcome lands
            }
            Code.STREAM_OK -> {
                val open = openStreams.remove(streamKey)
                // A backwards clock step must not turn a fast stream into a slow
                // one; `atMs - open.atMs` negative is simply not slow.
                val slow = open != null && atMs - open.atMs >= SLOW_STREAM_MS
                // DECIDE the SENT either way. Leaving a fast pair's SENT
                // undecided would leave it to the age rule, which HOLDS the
                // uploader's cursor for [SLOW_STREAM_MS] on every ordinary
                // request — the opposite of what the filter is for.
                if (open != null) markStreamShipLocked(open.seq, slow)
                slow
            }
            Code.STREAM_FAILED -> {
                val open = openStreams.remove(streamKey)
                if (open != null) markStreamShipLocked(open.seq, true)
                true
            }
            else -> null
        }
    }

    /**
     * Records the pair's verdict on the already-stored `STREAM_SENT` at [seq].
     * The ring is seq-ascending, so the scan walks backwards and stops the
     * moment it drops below [seq] — an evicted line is simply not found, which
     * is harmless (nothing above the uploader's cursor can reference it).
     */
    private fun markStreamShipLocked(seq: Long, ship: Boolean) {
        for (i in entries.indices.reversed()) {
            val at = entries[i].seq
            if (at == seq) {
                entries[i] = entries[i].copy(streamShip = ship)
                return
            }
            if (at < seq) return
        }
    }

    /** Drops every buffered line. Called on session lock and on every wipe. */
    fun clear() {
        lock.withLock {
            entries.clear()
            openStreams.clear()
            _lines.value = emptyList()
        }
    }

    /**
     * Coroutine-free read for the Swift panel (Kotlin `StateFlow` does not
     * cross the ObjC bridge). `ConnectionLogPanel.swift` polls this at 1 Hz
     * while it is expanded.
     */
    fun snapshot(): List<Line> = _lines.value

    /**
     * Lines whose [Line.seq] is strictly above [seq], newest last — what
     * [DebugLogUploader] has not shipped yet. Ring eviction can drop lines
     * before they are ever read; that is accepted.
     */
    fun since(seq: Long): List<Line> = lock.withLock { entries.filter { it.seq > seq } }

    /** [snapshot] pre-rendered, so Swift needs no access to [Line]. */
    fun snapshotFormatted(): List<String> = _lines.value.map { it.formatted() }

    // -----------------------------------------------------------------------
    // Redaction
    // -----------------------------------------------------------------------

    /**
     * Strips the three identifier shapes that could plausibly reach a line:
     * an `http(s)://…` URL, a bare `.onion` host, and any opaque base64url run
     * of [MIN_OPAQUE_TOKEN_LEN] characters or more (inbox ids, capabilities,
     * ratchet keys, blob fragments).
     *
     * Hand-rolled rather than [Regex] on purpose — the same K/N stack-safety
     * rule `UpdateCheck.parseAppVersion` follows. Ordinary phase text (words,
     * percentages, short numbers, punctuation) passes through untouched.
     */
    internal fun redact(text: String): String =
        stripLongTokens(stripOnionHosts(stripUrls(text)))

    private fun isB64Char(c: Char): Boolean =
        (c in 'A'..'Z') || (c in 'a'..'z') || (c in '0'..'9') || c == '-' || c == '_'

    private fun isHostChar(c: Char): Boolean = isB64Char(c) || c == '.'

    /** `http://…` / `https://…` up to the next whitespace ⇒ [PLACEHOLDER_URL]. */
    private fun stripUrls(s: String): String {
        val sb = StringBuilder()
        var i = 0
        while (i < s.length) {
            val http = s.regionMatches(i, "http://", 0, 7, ignoreCase = true)
            val https = s.regionMatches(i, "https://", 0, 8, ignoreCase = true)
            if (http || https) {
                sb.append(PLACEHOLDER_URL)
                while (i < s.length && !s[i].isWhitespace()) i++
            } else {
                sb.append(s[i])
                i++
            }
        }
        return sb.toString()
    }

    // Also [DebugLogRedactor]'s rule 1b (the same character class and placeholder).
    /** Any host-shaped token containing `.onion` ⇒ [PLACEHOLDER_ONION]. */
    internal fun stripOnionHosts(s: String): String {
        val sb = StringBuilder()
        var i = 0
        while (i < s.length) {
            if (isHostChar(s[i])) {
                var j = i
                while (j < s.length && isHostChar(s[j])) j++
                val token = s.substring(i, j)
                sb.append(if (token.contains(".onion", ignoreCase = true)) PLACEHOLDER_ONION else token)
                i = j
            } else {
                sb.append(s[i])
                i++
            }
        }
        return sb.toString()
    }

    /** Any base64url run ≥ [MIN_OPAQUE_TOKEN_LEN] ⇒ [PLACEHOLDER_TOKEN]. */
    private fun stripLongTokens(s: String): String {
        val sb = StringBuilder()
        var i = 0
        while (i < s.length) {
            if (isB64Char(s[i])) {
                var j = i
                while (j < s.length && isB64Char(s[j])) j++
                sb.append(if (j - i >= MIN_OPAQUE_TOKEN_LEN) PLACEHOLDER_TOKEN else s.substring(i, j))
                i = j
            } else {
                sb.append(s[i])
                i++
            }
        }
        return sb.toString()
    }
}

/** `HH:mm:ss.SSS` (UTC time-of-day) for a wall-clock epoch-millis value. */
internal fun formatClock(timestamp: Long): String {
    val t = ((timestamp % 86_400_000L) + 86_400_000L) % 86_400_000L
    val h = (t / 3_600_000L) % 24L
    val m = (t / 60_000L) % 60L
    val s = (t / 1_000L) % 60L
    val ms = t % 1_000L
    return "${clockPad2(h)}:${clockPad2(m)}:${clockPad2(s)}.${clockPad3(ms)}"
}

private fun clockPad2(v: Long): String = if (v < 10) "0$v" else "$v"

private fun clockPad3(v: Long): String = when {
    v < 10 -> "00$v"
    v < 100 -> "0$v"
    else -> "$v"
}

/**
 * `1834` ⇒ `"1.8"` — one-decimal seconds for the health-probe lines. Pure and
 * allocation-cheap; never a locale-dependent formatter (a comma decimal
 * separator would make the panel's numbers unreadable in a bug report).
 */
internal fun formatSeconds(millis: Long): String {
    val tenths = (if (millis < 0) 0L else millis + 50L) / 100L
    return "${tenths / 10}.${tenths % 10}"
}

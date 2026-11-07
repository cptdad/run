package com.vg.run

import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.os.SystemClock
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.io.File
import java.io.InterruptedIOException

// ---------------------------------------------------------------------------
// TorControlEvents — the ONION half of a connect, surfaced in [ConnectionLog].
//
// Tor's notice log (which [TorManager] tails) reports the bootstrap and the
// SOCKS listener and then goes quiet: everything that happens between "Tor is
// connected" and "the relay answered" — the HSDir descriptor fetch, the
// introduction circuit, the rendezvous, the stream — is only visible on the
// CONTROL port's asynchronous `650` events. That gap is exactly where a user
// stuck on "Connecting…" sits, so we subscribe to it.
//
// A SECOND control connection, deliberately.
// [TorManager]'s command socket reads replies per command — one line for most,
// a bounded multi-line read only after its own `GETINFO net/listeners/socks` —
// so an interleaved 650 would be taken as a reply. A `SETEVENTS` on that socket would interleave async
// `650` lines into the NEWNYM / HSFETCH reply parsing and hand the self-heal
// ladder a "250" that belongs to something else (or an event line read as a
// failed reply). So this reader owns its own socket to the same AF_UNIX
// ControlSocket, authenticated with the same cookie, and writes at most ONE
// command after its own `SETEVENTS` — the deferred consensus `GETINFO`, whose
// reply [consumeReplyLine] assembles around interleaved 650s. The two sockets
// share nothing but the cookie file.
//
// Non-negotiable: this is a DIAGNOSTIC. Failing to open, authenticate or read it
// must never affect connectivity — Tor is fully usable without it. Every failure
// path degrades to one SYSTEM line ("control events unavailable") and silence.
//
// PRODUCER RULE (ConnectionLog.kt rule 1) — the panel is release-visible, so
// every line built here is a FIXED PHRASE plus, at most, a token from Tor's own
// CLOSED vocabulary (a bootstrap TAG, a circuit/stream REASON, an HS_DESC
// action, a GUARD status) that is matched against an allowlist first and
// replaced by "OTHER" when it is not in it. NEVER an argument: no HSAddress, no
// HsDir fingerprint, no DescriptorID, no Path, no nickname, no Target, no
// SOURCE/SOURCE_ADDR, no HOSTID/HOSTADDR, no SUMMARY=/WARNING= prose, no
// circuit/stream id. [ConnectionLog.redact] stays defence in depth only.
// ---------------------------------------------------------------------------

/** One connection-log line derived from a control event. See [parseTorControlEvent]. */
internal data class TorEventLine(
    val kind: ConnectionLog.Kind,
    val text: String,
    val code: ConnectionLog.Code,
    /**
     * Tor's own StreamID for the three `STREAM_*` lines, null for everything
     * else — the PAIRING handle [ConnectionLog] uses to match a `SENT` with the
     * `SUCCEEDED`/`FAILED` that ends it (fix 2b, 2026-09-16), so the uploader
     * can leave an uneventful sub-5 s stream out of a debug-mode batch while
     * still shipping a slow or failed one together with its start line.
     *
     * It is NOT part of [text] and never will be: the producer rule in this
     * file's header bans a stream id from a line, and [ConnectionLog.Line]
     * keeps this one in a field that nothing renders, uploads or reports.
     */
    val streamKey: Long? = null,
)

/**
 * The events we subscribe to — the onion path, the client status, liveness and
 * (2026-09-14) the OR connections to the entry guards.
 *
 * ORCONN is the missing half of the "Tor says 100 % in 0.5 s, then 155 s of
 * rendezvous silence" report: with `NumEntryGuards 8` circuits are spread over
 * three primary guards, and a NEW OR connection to guard 2/3 that never
 * completes is invisible in every other event family — CIRC just sits there
 * until the 45 s CircuitBuildTimeout prices it.
 *
 * CIRC_MINOR (2026-10-06) carries the onion HANDSHAKE itself. Tor reports an
 * intro/rendezvous circuit's HS_STATE transitions (intro sent → acked, rendezvous
 * joined) ONLY as `CIRC_MINOR … PURPOSE_CHANGED` — `circuit_change_purpose()`
 * never re-emits a plain CIRC event — so without it INTRO_SENT / INTRO_DONE /
 * REND_JOINED were never produced (0 of 3677 coded timelines) and an intro-side
 * stall could not be told from a rendezvous-side one.
 */
internal const val TOR_SETEVENTS_COMMAND =
    "SETEVENTS HS_DESC CIRC CIRC_MINOR STREAM STATUS_CLIENT STATUS_GENERAL NETWORK_LIVENESS GUARD ORCONN"

/**
 * Asked ONCE per session, on this socket only (see [TorControlEventReader]): a
 * consensus that is hours old sends the client to relays that may be gone, which
 * looks exactly like the stall above but is a directory-freshness problem, not a
 * guard-reachability one. Only the AGE BUCKET is ever logged.
 */
internal const val TOR_GETINFO_CONSENSUS_VALID_AFTER = "GETINFO consensus/valid-after"

// --- Closed vocabularies -------------------------------------------------
// Every one of these is a Tor-defined token set. A value outside its set is
// reported as "OTHER" rather than printed, so no free-form argument (an
// address, a nickname, a smuggled string) can reach a line through a REASON
// field. Order/content follow control-spec.txt.

// The sets themselves live in commonMain [TorReasonVocabulary] (2026-10-23) so
// the HS_DESC reason→code split and the debug-mode redactor's passthrough read
// the SAME words this parser prints; the iOS parser mirrors them
// (TorReasonParitySourceTest pins the two equal).
private val HS_DESC_FAIL_REASONS = TorReasonVocabulary.HS_DESC_FAIL
private val CIRC_FAIL_REASONS = TorReasonVocabulary.CIRC_FAIL
private val STREAM_FAIL_REASONS = TorReasonVocabulary.STREAM_FAIL
private val ORCONN_FAIL_REASONS = TorReasonVocabulary.ORCONN_FAIL
private val BOOTSTRAP_PROBLEM_REASONS = TorReasonVocabulary.BOOTSTRAP_PROBLEM

/** Fallback for any REASON-shaped value that is not in its allowlist. */
internal const val REASON_OTHER = "OTHER"

/**
 * Longest token we will ever echo (a bootstrap TAG). Tor's tags are short words
 * (`conn`, `handshake`, `requesting_descriptors`); anything longer is not one.
 */
private const val MAX_ECHOED_TOKEN_LEN = 32

/**
 * Parses ONE control-protocol line into the connection-log line it should
 * produce, or null when the line is not an event we surface.
 *
 * PURE — no I/O, no clock, no [ConnectionLog] — so every branch (and, more
 * importantly, the fact that no argument ever reaches the text) is unit-testable
 * on the JVM. The reader owns dedupe and emission.
 */
internal fun parseTorControlEvent(raw: String): TorEventLine? {
    val line = raw.trimEnd('\r', '\n')
    // `650 ` (single), `650-` (mid multi-line), `650+` (data-block header). The
    // data PAYLOAD is skipped by the reader and never reaches here.
    if (line.length < 5) return null
    if (!line.startsWith("650")) return null
    val sep = line[3]
    if (sep != ' ' && sep != '-' && sep != '+') return null
    val tokens = line.substring(4).split(' ').filter { it.isNotEmpty() }
    if (tokens.isEmpty()) return null
    return when (tokens[0]) {
        "HS_DESC" -> parseHsDesc(tokens)
        "CIRC" -> parseCirc(tokens)
        "CIRC_MINOR" -> parseCircMinor(tokens)
        "STREAM" -> parseStream(tokens)
        "STATUS_CLIENT" -> parseStatusClient(tokens)
        "STATUS_GENERAL" -> parseStatusGeneral(tokens)
        "NETWORK_LIVENESS" -> parseNetworkLiveness(tokens)
        "GUARD" -> parseGuard(tokens)
        "ORCONN" -> parseOrConn(tokens)
        else -> null
    }
}

private fun torLine(text: String, code: ConnectionLog.Code, streamKey: Long? = null) =
    TorEventLine(ConnectionLog.Kind.TOR, text, code, streamKey)

/**
 * `650 HS_DESC <Action> <HSAddress> <AuthType> <HsDir> [DescriptorID] [REASON=…]`
 * — the address, the HSDir fingerprint and the descriptor id are all ignored by
 * construction (only `tokens[1]` and a REASON keyword are ever read).
 */
private fun parseHsDesc(tokens: List<String>): TorEventLine? {
    if (tokens.size < 2) return null
    return when (tokens[1].uppercase()) {
        "REQUESTED" -> torLine("descriptor requested", ConnectionLog.Code.HSDESC_REQUESTED)
        "RECEIVED" -> torLine("descriptor received", ConnectionLog.Code.HSDESC_RECEIVED)
        "FAILED" -> {
            // The TEXT keeps its allowlist-or-OTHER rendering; the CODE is the
            // fixed REASON → code split (2026-10-23), so the connect timeline can
            // tell NOT_FOUND from QUERY_NO_HSDIR from BAD_DESC. Neither is ever
            // built from the raw value: an off-list reason is "OTHER" in the text
            // and HSDESC_FAILED in the code.
            val rawReason = keywordValue(tokens, "REASON")
            torLine(
                "descriptor fetch failed: ${allowlisted(rawReason, HS_DESC_FAIL_REASONS)}",
                TorReasonVocabulary.hsDescFailureCode(rawReason),
            )
        }
        // CREATED / UPLOAD / UPLOADED / IGNORE are the service side (we run no
        // onion service) or noise — no line.
        else -> null
    }
}

/** Which half of the onion handshake a circuit belongs to. */
private enum class HsCircRole { HSDIR, INTRO, REND }

/**
 * `650 CIRC <id> <Status> [<Path>] [PURPOSE=…] [HS_STATE=…] [REASON=…] …`
 *
 * Only the three HS_CLIENT purposes are surfaced: GENERAL circuits turn over
 * constantly and would drown the panel. The path (`$FP~nick,…`) is never read.
 */
private fun parseCirc(tokens: List<String>): TorEventLine? {
    if (tokens.size < 3) return null
    val status = tokens[2].uppercase()
    val role = when (keywordValue(tokens, "PURPOSE")?.uppercase()) {
        "HS_CLIENT_HSDIR" -> HsCircRole.HSDIR
        "HS_CLIENT_INTRO" -> HsCircRole.INTRO
        "HS_CLIENT_REND" -> HsCircRole.REND
        else -> return null
    }
    if (status == "FAILED" || status == "CLOSED") {
        val rawReason = keywordValue(tokens, "REASON")?.uppercase()
        // An intro circuit's ORDINARY end is a close, not a failure: once the
        // INTRODUCE_ACK arrives Tor flips it to INTRODUCE_ACKED (HS_STATE=HSCI_DONE)
        // and closes it with REASON=FINISHED (hs_client.c
        // handle_introduce_ack_success). Coding that as INTRO_CIRC_FAILED put a
        // "failure" into ~70 % of fast, healthy timelines. Every FINISHED close of
        // an intro circuit is Tor's own bookkeeping — the ack above, the give-up
        // after a NACK (already reported as "introduction refused" from
        // CIRC_MINOR), a descriptor replacement, RELAY_EARLY exhaustion — never a
        // network fault. A genuine failure stays one: FAILED (never built), or a
        // CLOSED with any other REASON while the intro was still unacknowledged.
        if (role == HsCircRole.INTRO && status == "CLOSED" &&
            (rawReason == "FINISHED" || keywordValue(tokens, "HS_STATE")?.uppercase() == "HSCI_DONE")
        ) return null
        val reason = allowlisted(rawReason, CIRC_FAIL_REASONS)
        return when (role) {
            HsCircRole.HSDIR -> torLine("directory circuit failed: $reason", ConnectionLog.Code.HSDIR_CIRC_FAILED)
            HsCircRole.INTRO -> torLine("introduction circuit failed: $reason", ConnectionLog.Code.INTRO_CIRC_FAILED)
            HsCircRole.REND -> torLine("rendezvous circuit failed: $reason", ConnectionLog.Code.REND_CIRC_FAILED)
        }
    }
    // DEFENSIVE ONLY. Tor does NOT re-emit a plain CIRC event when the HS state
    // changes — those transitions arrive solely as CIRC_MINOR PURPOSE_CHANGED
    // (see [parseCircMinor]). A non-terminal CIRC carrying one of these states is
    // not expected from Tor 0.4.9; it is still narrated as the state rather than
    // as a second "circuit built", should a future Tor ever send one.
    when (keywordValue(tokens, "HS_STATE")?.uppercase()) {
        "HSCI_INTRO_SENT" -> return torLine("introduction sent", ConnectionLog.Code.INTRO_SENT)
        "HSCI_DONE" -> return torLine("introduction complete", ConnectionLog.Code.INTRO_DONE)
        "HSCR_JOINED" -> return torLine("rendezvous joined", ConnectionLog.Code.REND_JOINED)
    }
    if (status == "BUILT") {
        return when (role) {
            // An HSDir circuit being built says nothing the HS_DESC events don't.
            HsCircRole.HSDIR -> null
            HsCircRole.INTRO -> torLine("introduction circuit built", ConnectionLog.Code.INTRO_CIRC_BUILT)
            HsCircRole.REND -> torLine("rendezvous circuit built", ConnectionLog.Code.REND_CIRC_BUILT)
        }
    }
    // LAUNCHED: the onion twin of ORCONN_LAUNCHED. A LAUNCHED with no
    // BUILT after it is the signature of a circuit that never completed, and the
    // measured stalls are exactly that shape — the panel and the timeline could only show the BUILT that
    // never arrived, i.e. nothing at all. Reached only when the HS_STATE switch
    // above did not match, which is the case at launch (HSCI_CONNECTING /
    // HSCR_CONNECTING are not states we narrate). HSDIR stays silent for the
    // same reason as on BUILT: HS_DESC already says it.
    if (status == "LAUNCHED") {
        return when (role) {
            HsCircRole.HSDIR -> null
            HsCircRole.INTRO -> torLine("introduction circuit launched", ConnectionLog.Code.INTRO_CIRC_LAUNCHED)
            HsCircRole.REND -> torLine("rendezvous circuit launched", ConnectionLog.Code.REND_CIRC_LAUNCHED)
        }
    }
    return null
}

/**
 * `650 CIRC_MINOR <id> <Event> [<Path>] [BUILD_FLAGS=…] [PURPOSE=…] [HS_STATE=…]
 *  [REND_QUERY=…] [TIME_CREATED=…] [OLD_PURPOSE=…] [OLD_HS_STATE=…]`
 *
 * The ONLY place Tor reports the onion handshake's progress: every
 * `circuit_change_purpose()` on an intro/rendezvous circuit is a
 * `PURPOSE_CHANGED` here and nowhere else. Read: the event keyword, PURPOSE,
 * HS_STATE and OLD_HS_STATE — all closed Tor vocabularies, matched exactly and
 * never echoed. The circuit id, Path, REND_QUERY (the onion) and TIME_CREATED
 * are never read.
 *
 * Transitions narrated (hs_client.c, Tor 0.4.9):
 *  - INTRO → `HSCI_INTRO_SENT`: INTRODUCE1 is on the wire (INTRO_SENT).
 *  - INTRO `HSCI_INTRO_SENT` → `HSCI_DONE`: the intro point ACKED (INTRO_DONE).
 *  - INTRO `HSCI_INTRO_SENT` → `HSCI_CONNECTING`: the intro point NACKED — Tor
 *    goes back to "connecting" to re-extend to another intro point
 *    (handle_introduce_ack_bad). A genuine intro failure → INTRO_CIRC_FAILED.
 *  - INTRO `HSCI_CONNECTING` → `HSCI_DONE`: the give-up after that NACK
 *    (close_or_reextend_intro_circ) — NOT an ack, and already reported: no line.
 *  - REND → `HSCR_JOINED`: RENDEZVOUS2 arrived, the onion session is up (REND_JOINED).
 * Everything else (rendezvous established/waiting, CANNIBALIZED, GENERAL and
 * HSDIR purposes) produces no line.
 */
private fun parseCircMinor(tokens: List<String>): TorEventLine? {
    if (tokens.size < 3) return null
    if (tokens[2].uppercase() != "PURPOSE_CHANGED") return null
    val state = keywordValue(tokens, "HS_STATE")?.uppercase()
    return when (keywordValue(tokens, "PURPOSE")?.uppercase()) {
        "HS_CLIENT_INTRO" -> {
            val old = keywordValue(tokens, "OLD_HS_STATE")?.uppercase()
            when (state) {
                "HSCI_INTRO_SENT" -> torLine("introduction sent", ConnectionLog.Code.INTRO_SENT)
                // Tor always names OLD_HS_STATE for an intro purpose; a missing one
                // is read as the ack (the only path that ever reaches DONE from
                // the sent state) rather than dropped.
                "HSCI_DONE" ->
                    if (old == null || old == "HSCI_INTRO_SENT") {
                        torLine("introduction complete", ConnectionLog.Code.INTRO_DONE)
                    } else {
                        null
                    }
                "HSCI_CONNECTING" ->
                    if (old == "HSCI_INTRO_SENT") {
                        torLine("introduction refused", ConnectionLog.Code.INTRO_CIRC_FAILED)
                    } else {
                        null
                    }
                else -> null
            }
        }
        "HS_CLIENT_REND" ->
            if (state == "HSCR_JOINED") torLine("rendezvous joined", ConnectionLog.Code.REND_JOINED) else null
        else -> null
    }
}

/**
 * `650 STREAM <id> <Status> <CircID> <Target> [REASON=…] [SOURCE=…] [SOURCE_ADDR=…]`
 *
 * The Target is the `.onion:port` we are dialling and SOURCE_ADDR is the local
 * app socket — neither is ever read here, only the status and an allowlisted
 * REASON.
 */
private fun parseStream(tokens: List<String>): TorEventLine? {
    if (tokens.size < 3) return null
    // The StreamID is read ONLY as a pairing handle (see [TorEventLine.streamKey]);
    // it is never echoed into the line's text. A non-numeric id (Tor never emits
    // one) simply leaves the pair unmatched, which ships the line — the safe side.
    val key = tokens[1].toLongOrNull()
    return when (tokens[2].uppercase()) {
        "SENTCONNECT" -> torLine("stream connecting", ConnectionLog.Code.STREAM_SENT, key)
        "SUCCEEDED" -> torLine("stream connected", ConnectionLog.Code.STREAM_OK, key)
        "FAILED", "CLOSED" -> {
            val rawReason = keywordValue(tokens, "REASON")?.uppercase()
            // A CLOSED stream that finished normally (DONE) or was ended by the
            // far side (END) is the ordinary end of every request — not a fault.
            if (tokens[2].uppercase() == "CLOSED" && (rawReason == "DONE" || rawReason == "END")) return null
            torLine(
                "stream failed: ${allowlisted(rawReason, STREAM_FAIL_REASONS)}",
                ConnectionLog.Code.STREAM_FAILED,
                key,
            )
        }
        else -> null
    }
}

/**
 * `650 STATUS_CLIENT <Severity> <Action> [KEY=VALUE …]`
 *
 * The BOOTSTRAP branch carries WARNING=/SUMMARY=/HOSTID=/HOSTADDR= arguments —
 * free-form prose and a relay's identity/address. None of them is read: the line
 * is built from TAG, PROGRESS, an allowlisted REASON and COUNT only.
 */
private fun parseStatusClient(tokens: List<String>): TorEventLine? {
    if (tokens.size < 3) return null
    val severity = tokens[1].uppercase()
    return when (tokens[2].uppercase()) {
        "ENOUGH_DIR_INFO" -> torLine("enough directory info", ConnectionLog.Code.DIR_ENOUGH)
        "NOT_ENOUGH_DIR_INFO" -> torLine("not enough directory info", ConnectionLog.Code.DIR_NOT_ENOUGH)
        "CIRCUIT_ESTABLISHED" -> torLine("circuit established", ConnectionLog.Code.CIRCUIT_OK)
        "CIRCUIT_NOT_ESTABLISHED" -> {
            val jumped = keywordValue(tokens, "REASON")?.uppercase() == "CLOCK_JUMPED"
            torLine(
                if (jumped) "circuit lost (clock jumped)" else "circuit lost",
                ConnectionLog.Code.CIRCUIT_LOST,
            )
        }
        // Progress BOOTSTRAP events are NOTICE and already covered by the notice
        // log tail; only the WARN/ERR "bootstrap problem" ones add anything. ERR
        // is included deliberately: it is Tor giving up, the single most useful
        // line for a user stuck on "Connecting…".
        "BOOTSTRAP" -> {
            if (severity != "WARN" && severity != "ERR") return null
            val reason = keywordValue(tokens, "REASON") ?: return null
            val tag = echoableToken(keywordValue(tokens, "TAG")) ?: "unknown"
            val progress = numericToken(keywordValue(tokens, "PROGRESS")) ?: "?"
            val count = numericToken(keywordValue(tokens, "COUNT")) ?: "?"
            torLine(
                "bootstrap problem at $tag ($progress%): " +
                    "${allowlisted(reason, BOOTSTRAP_PROBLEM_REASONS)}, count $count",
                ConnectionLog.Code.TOR_BOOTSTRAP_PROBLEM,
            )
        }
        else -> null
    }
}

/**
 * `650 STATUS_GENERAL <Severity> CLOCK_SKEW SKEW=<s> [MIN_SKEW=<s>] SOURCE=<…>`
 * / `… CLOCK_JUMPED TIME=<s>`.
 *
 * SOURCE names the directory authority or NETINFO peer that disagreed with our
 * clock (`DIRSERV:1.2.3.4:443`) and is never read. The offset itself is reported
 * as a coarse BUCKET, not a value: a precise skew is a device fingerprint.
 */
private fun parseStatusGeneral(tokens: List<String>): TorEventLine? {
    if (tokens.size < 3) return null
    return when (tokens[2].uppercase()) {
        "CLOCK_SKEW" -> {
            val skew = signedSeconds(keywordValue(tokens, "SKEW") ?: keywordValue(tokens, "MIN_SKEW"))
                ?: return null
            torLine("clock skew: ${clockOffsetBucket(skew)}", ConnectionLog.Code.CLOCK_SKEW)
        }
        "CLOCK_JUMPED" -> {
            val jump = signedSeconds(keywordValue(tokens, "TIME")) ?: return null
            torLine("clock jumped: ${clockOffsetBucket(jump)}", ConnectionLog.Code.CLOCK_JUMPED)
        }
        else -> null
    }
}

/** `650 NETWORK_LIVENESS UP|DOWN`. */
private fun parseNetworkLiveness(tokens: List<String>): TorEventLine? {
    if (tokens.size < 2) return null
    return when (tokens[1].uppercase()) {
        "UP" -> torLine("network up", ConnectionLog.Code.NET_UP)
        "DOWN" -> torLine("network down", ConnectionLog.Code.NET_DOWN)
        else -> null
    }
}

/**
 * `650 GUARD ENTRY <$fingerprint~nickname> <Status>` — the guard's identity is
 * the one thing that must never reach the panel (it is the most durable link
 * between a device and its Tor usage), so only `tokens[3]` is read.
 */
private fun parseGuard(tokens: List<String>): TorEventLine? {
    if (tokens.size < 4) return null
    if (tokens[1].uppercase() != "ENTRY") return null
    return when (tokens[3].uppercase()) {
        "UP" -> torLine("guard up", ConnectionLog.Code.GUARD_UP)
        "DOWN" -> torLine("guard down", ConnectionLog.Code.GUARD_DOWN)
        "DROPPED" -> torLine("guard dropped", ConnectionLog.Code.GUARD_DROPPED)
        // NEW / BAD / GOOD are bookkeeping, not connectivity — no line.
        else -> null
    }
}

/**
 * `650 ORCONN <target> <Status> [REASON=…] [NCIRCS=…] [ID=…]`
 *
 * The target is `$fingerprint~nickname`, a bare nickname or an `IP:port` — i.e.
 * the single most identifying argument in the whole event stream (it names the
 * guard this device is attached to). `tokens[1]` is therefore never read; only
 * the status and an allowlisted REASON reach a line.
 *
 * What this is for: a LAUNCHED with no CONNECTED after it is the signature of a
 * stalled new OR connection to a secondary guard. Also the reason CONNECTED
 * carries no count — NCIRCS is a circuit count on a named channel.
 */
private fun parseOrConn(tokens: List<String>): TorEventLine? {
    if (tokens.size < 3) return null
    val reason = keywordValue(tokens, "REASON")
    return when (tokens[2].uppercase()) {
        "LAUNCHED" -> torLine("or connection launched", ConnectionLog.Code.ORCONN_LAUNCHED)
        "CONNECTED" -> torLine("or connection connected", ConnectionLog.Code.ORCONN_CONNECTED)
        "FAILED" -> torLine(
            "or connection failed: ${allowlisted(reason, ORCONN_FAIL_REASONS)}",
            ConnectionLog.Code.ORCONN_FAILED,
        )
        "CLOSED" -> {
            // A clean close (REASON=DONE) is ordinary channel churn — Tor closes
            // idle OR connections constantly. Anything else closed the channel
            // under us, which is the failure we are hunting, so it is reported
            // with the same code/phrasing as FAILED. A CLOSED with NO reason at
            // all names nothing we could report honestly: no line.
            if (reason == null || reason.uppercase() == "DONE") null
            else torLine(
                "or connection failed: ${allowlisted(reason, ORCONN_FAIL_REASONS)}",
                ConnectionLog.Code.ORCONN_FAILED,
            )
        }
        // NEW is an INBOUND connection (we are a client — it should never appear).
        else -> null
    }
}

// --- Consensus age -------------------------------------------------------

/** What [consensusAgeLine] reports when the reply is 552 / unparseable. */
internal const val CONSENSUS_AGE_UNKNOWN = "unknown"

/**
 * True for the LAST line of a control reply: a 3-digit code followed by a SPACE
 * (`250 OK`, `552 Unrecognized key …`). Continuation lines use `-` or `+`.
 */
internal fun isFinalReplyLine(line: String): Boolean =
    line.length >= 4 &&
        line[0] in '0'..'9' && line[1] in '0'..'9' && line[2] in '0'..'9' &&
        line[3] == ' '

/**
 * The `consensus/valid-after` VALUE from a `GETINFO` reply, or null.
 *
 * Reply shape: `250-consensus/valid-after=2026-09-14 06:00:00` followed by
 * `250 OK`; `552 …` when Tor has no consensus yet. Pure so both the happy path
 * and every degraded one are unit-testable without a daemon.
 */
internal fun parseConsensusValidAfter(replyLines: List<String>): String? {
    for (raw in replyLines) {
        val line = raw.trimEnd('\r', '\n')
        if (!line.startsWith("250")) continue
        val key = line.indexOf("consensus/valid-after=")
        if (key < 0) continue
        val value = line.substring(key + "consensus/valid-after=".length).trim()
        if (value.isNotEmpty()) return value
    }
    return null
}

/**
 * `YYYY-MM-DD HH:MM:SS` (Tor's control-protocol UTC form) as epoch seconds, or
 * null if it is not exactly that shape.
 *
 * Hand-rolled — no `java.time`, no formatter, no locale and no time zone — for
 * the same reason [ConnectionLog.redact] is: a parser on this path must be
 * deterministic under unit test and must never depend on the device's locale.
 */
internal fun parseUtcTimestampSeconds(value: String): Long? {
    if (value.length < 19) return null
    if (value[4] != '-' || value[7] != '-' || value[10] != ' ' || value[13] != ':' || value[16] != ':') return null
    val year = value.substring(0, 4).toIntOrNull() ?: return null
    val month = value.substring(5, 7).toIntOrNull() ?: return null
    val day = value.substring(8, 10).toIntOrNull() ?: return null
    val hour = value.substring(11, 13).toIntOrNull() ?: return null
    val minute = value.substring(14, 16).toIntOrNull() ?: return null
    val second = value.substring(17, 19).toIntOrNull() ?: return null
    if (month !in 1..12 || day !in 1..31 || hour !in 0..23 || minute !in 0..59 || second !in 0..60) return null
    return daysFromCivil(year, month, day) * 86_400L + hour * 3_600L + minute * 60L + second
}

/** Days since 1970-01-01 for a proleptic-Gregorian date (Howard Hinnant's algorithm). */
private fun daysFromCivil(year: Int, month: Int, day: Int): Long {
    val y = if (month <= 2) year - 1 else year
    val era = (if (y >= 0) y else y - 399) / 400
    val yoe = y - era * 400                                   // [0, 399]
    val doy = (153 * (if (month > 2) month - 3 else month + 9) + 2) / 5 + day - 1
    val doe = yoe * 365 + yoe / 4 - yoe / 100 + doy           // [0, 146096]
    return era.toLong() * 146_097L + doe.toLong() - 719_468L
}

/**
 * The consensus age as a COARSE BUCKET. Like [clockOffsetBucket], the value
 * itself never leaves: a `valid-after` timestamp is a directory-wide fact, but
 * publishing it alongside a device's own clock narrows when that device was on.
 */
internal fun consensusAgeBucket(ageSeconds: Long): String = when {
    ageSeconds < 3_600L -> "under 1 h"          // negatives (clock behind) land here: fresh
    ageSeconds < CONSENSUS_STALE_AFTER_SECONDS -> "under 3 h"
    ageSeconds < 24 * 3_600L -> "under 24 h"
    else -> "over 24 h"
}

/**
 * Where FRESH ends and STALE begins: 3 hours, because that is a consensus's own
 * validity window (the authorities publish hourly and a document is valid for
 * three), so "older than the thing Tor is allowed to be using" is the honest
 * line rather than an invented one.
 *
 * iOS sibling: `TorControlEventParser.consensusStaleAfterSeconds` — keep the two
 * in step, the panel phrasing AND the code must read identically on both.
 */
internal const val CONSENSUS_STALE_AFTER_SECONDS = 3 * 3_600L

/**
 * The CODE for a consensus age. The three outcomes were one code
 * (`CONSENSUS_AGE`) until 2026-09-15, which made them indistinguishable in the
 * connect timeline — where only the code travels, never the bucket text — even
 * though "the directory was fresh", "the directory was hours stale" and "Tor had
 * no consensus at all to report" are three different explanations of the same
 * stall. Null [ageSeconds] = the question was not answered.
 */
internal fun consensusAgeCode(ageSeconds: Long?): ConnectionLog.Code = when {
    ageSeconds == null -> ConnectionLog.Code.CONSENSUS_UNKNOWN
    ageSeconds < CONSENSUS_STALE_AFTER_SECONDS -> ConnectionLog.Code.CONSENSUS_FRESH
    else -> ConnectionLog.Code.CONSENSUS_STALE
}

/**
 * The ONE line a session reports about directory freshness, built from a raw
 * `GETINFO consensus/valid-after` reply and the current wall clock.
 *
 * Always produces a line: an unparseable or `552` reply reads
 * "consensus age: unknown" rather than going silent, because "Tor had no
 * consensus at all when we asked" is itself the answer to the stall question.
 *
 * NOTE the honest dependency: the age is `now − valid-after` against the DEVICE
 * clock, so a badly skewed clock mis-buckets it. That is not a hidden failure —
 * a device skewed enough to matter also emits CLOCK_SKEW from STATUS_GENERAL.
 */
internal fun consensusAgeLine(replyLines: List<String>, nowEpochSeconds: Long): TorEventLine {
    val value = parseConsensusValidAfter(replyLines)
    val validAfter = if (value == null) null else parseUtcTimestampSeconds(value)
    val age = if (validAfter == null) null else nowEpochSeconds - validAfter
    val bucket = if (age == null) CONSENSUS_AGE_UNKNOWN else consensusAgeBucket(age)
    return torLine("consensus age: $bucket", consensusAgeCode(age))
}

// --- Token helpers -------------------------------------------------------

/**
 * The value of a `KEY=VALUE` argument, or null. `startsWith` on the full token
 * means `REMOTE_REASON=…` can never be mistaken for `REASON=…`, and a value is
 * only ever returned to a caller that allowlists or shape-checks it.
 */
private fun keywordValue(tokens: List<String>, key: String): String? {
    val prefix = "$key="
    for (t in tokens) {
        if (t.startsWith(prefix)) return t.substring(prefix.length).trim('"')
    }
    return null
}

/** [value] when it is in [allowed] (case-insensitively), else [REASON_OTHER]. */
private fun allowlisted(value: String?, allowed: Set<String>): String {
    val v = value?.uppercase() ?: return REASON_OTHER
    return if (v in allowed) v else REASON_OTHER
}

/**
 * A bootstrap TAG, echoed only if it has the shape of one: a short
 * `[A-Za-z0-9_]` word. Tor's tags are a closed set, but the shape check means a
 * future/unknown tag cannot smuggle punctuation, whitespace or an address into
 * the panel — it just reads as "unknown".
 */
private fun echoableToken(value: String?): String? {
    if (value.isNullOrEmpty() || value.length > MAX_ECHOED_TOKEN_LEN) return null
    for (c in value) {
        val ok = (c in 'a'..'z') || (c in 'A'..'Z') || (c in '0'..'9') || c == '_'
        if (!ok) return null
    }
    return value
}

/** Digits only (a PROGRESS percentage or a COUNT), else null. */
private fun numericToken(value: String?): String? {
    if (value.isNullOrEmpty() || value.length > 6) return null
    for (c in value) if (c !in '0'..'9') return null
    return value
}

/** A signed second count (`-3600`, `+120`, `42`), else null. */
private fun signedSeconds(value: String?): Long? {
    if (value.isNullOrEmpty() || value.length > 20) return null
    return value.toLongOrNull()
}

/**
 * A clock offset as a COARSE BUCKET plus a direction — never the value.
 *
 * Sign convention follows Tor's (`apparent_skew = our clock - their clock`), so
 * a positive offset means this device's clock is AHEAD of the network's. Being
 * wrong about the direction would only mislabel a line; being wrong about the
 * granularity would publish a fingerprintable quantity, which is why the bucket
 * is the only thing that leaves this function.
 */
internal fun clockOffsetBucket(seconds: Long): String {
    val abs = if (seconds < 0) -seconds else seconds
    val magnitude = when {
        abs < 0L -> "1 d or more"          // Long.MIN_VALUE negates to itself
        abs < 60L -> "under 1 min"
        abs < 600L -> "under 10 min"
        abs < 3_600L -> "under 1 h"
        abs < 86_400L -> "under 1 d"
        else -> "1 d or more"
    }
    return "$magnitude ${if (seconds < 0) "behind" else "ahead"}"
}

/**
 * Rate limit for event-derived lines: at most one line per [ConnectionLog.Code]
 * per [windowMs].
 *
 * Tor fires these in bursts — a descriptor fetch hits several HSDirs, a stream
 * retries, a failing circuit is reported FAILED then CLOSED — and a panel that
 * scrolls a burst away is worse than one that shows the phase once. Keyed on the
 * CODE (not the text) exactly as specified, so a second failure reason inside
 * the same 2 s window is folded into the first; the ladder's shape is what the
 * panel is for, not the exhaustive list.
 *
 * A plain map with a caller-supplied clock: pure enough to unit-test, and only
 * ever touched from the single reader coroutine.
 */
internal class TorEventDedupe(private val windowMs: Long = TOR_EVENT_DEDUPE_WINDOW_MS) {
    private val lastAtMs = HashMap<ConnectionLog.Code, Long>()

    /** True (and records the emission) when [code] may be logged at [nowMs]. */
    fun allow(code: ConnectionLog.Code, nowMs: Long): Boolean {
        val key = dedupeKey(code)
        val last = lastAtMs[key]
        if (last != null && nowMs - last < windowMs) return false
        lastAtMs[key] = nowMs
        return true
    }

    /**
     * The HS_DESC failure family shares ONE window (2026-10-23): before the
     * REASON split every failed fetch carried [ConnectionLog.Code.HSDESC_FAILED],
     * so a burst of failures with different reasons folded into one panel line.
     * Keying the family on that code keeps the panel exactly as it was.
     */
    private fun dedupeKey(code: ConnectionLog.Code): ConnectionLog.Code =
        if (code in TorReasonVocabulary.HS_DESC_FAILURE_CODES) ConnectionLog.Code.HSDESC_FAILED else code
}

internal const val TOR_EVENT_DEDUPE_WINDOW_MS = 2_000L

/**
 * Reads Tor's asynchronous control events on a socket of its OWN and appends the
 * resulting lines to [ConnectionLog]. See the file header for why the socket is
 * separate from [TorManager]'s command socket.
 *
 * Lifecycle is tied to one [TorManager] session: [start] after the SOCKS port is
 * known, [close] from `stop()`. [torAlive] lets the reader give up the moment the
 * daemon it was following is gone instead of retrying against a dead socket.
 */
internal class TorControlEventReader(
    private val dataDir: File,
    private val torAlive: () -> Boolean,
    /**
     * The relay's descriptor race ([RelayAddressRace], 2026-10-23): its
     * configured onion addresses are held ONLY to be compared against the
     * `HS_DESC` HSAddress field ([RelayAddressRace.parseDescriptorEvent]) — never
     * logged, never part of a line. Null disables the watchdog hook.
     */
    private val relayRace: RelayAddressRace? = null,
    /**
     * Descriptor-fetch watchdog hook ([TorManager.onRelayDescriptorEvent]):
     * called on this reader's coroutine for every `HS_DESC` REQUESTED /
     * RECEIVED / FAILED of any of the relay's onions, BEFORE (and independent of) the
     * log dedupe. Must not block; it only feeds the [HsDirLedger] and
     * arms/disarms a timer. The event's HSDir fingerprint is SENSITIVE and is
     * never logged. The `HSFETCH` the watchdog may send never goes out on this
     * socket — it uses the COMMAND socket.
     */
    private val onRelayDescriptorEvent: (RelayDescriptorEvent) -> Unit = {},
    /**
     * Bootstrap-stall rung hook ([TorManager.noteBootstrapProgressForStall]): the
     * PROGRESS integer of every `STATUS_CLIENT … BOOTSTRAP` event, extracted by
     * the shared [TorBootstrapStall.progressFromControlEvent] (nothing else of
     * the event leaves it). Called on this reader's coroutine, before the log
     * dedupe; must not block. Null = not wired.
     */
    private val onBootstrapProgress: ((Int) -> Unit)? = null,
    /**
     * Hung onion-circuit rung hook ([TorManager.onHsCircuitEvent]): every raw
     * event line, before the log dedupe, for [HsCircuitWatchdog] — which reads
     * only `CIRC` / `CIRC_MINOR` / `STREAM` (the STREAM rule, 2026-10-09) and
     * keeps circuit ids solely to address a `CLOSECIRCUIT` (on the COMMAND
     * socket). Must not block. Null = not wired.
     */
    private val onControlEvent: ((String) -> Unit)? = null,
) {

    private companion object {
        const val CONNECT_ATTEMPTS = 20
        const val CONNECT_RETRY_MS = 300L
        /** Short while we expect an immediate `250` reply (AUTHENTICATE/SETEVENTS). */
        const val HANDSHAKE_TIMEOUT_MS = 3_000
        /**
         * Generous while we wait for events: an idle onion session can be quiet
         * for minutes. Not infinite, so the loop still re-checks [torAlive] and
         * the close latch even if `close()` fails to interrupt the read.
         */
        const val EVENT_READ_TIMEOUT_MS = 65_000
        /** Bound on a single event line so a garbled stream can't grow the read. */
        const val MAX_EVENT_LINE_CHARS = 4096
        const val RECONNECT_DELAY_MS = 1_000L
        /**
         * Tor answers `552` to `GETINFO consensus/valid-after` until it HAS a
         * consensus, which on a cold start is a few seconds in. One retry.
         */
        const val CONSENSUS_RETRY_DELAY_MS = 5_000L
        /**
         * Short idle-read timeout WHILE the consensus answer is still
         * outstanding, so the deferred retry fires on time even if the event
         * stream happens to be silent. Raised to [EVENT_READ_TIMEOUT_MS] the
         * moment the question is settled.
         */
        const val CONSENSUS_POLL_TIMEOUT_MS = 2_000
        /** Bound on a control reply (`250-…` lines + its final `250 OK`). */
        const val MAX_REPLY_LINES = 64
    }

    @Volatile private var socket: LocalSocket? = null
    @Volatile private var job: Job? = null
    @Volatile private var closed = false

    /**
     * Completed the first time `SETEVENTS` was accepted on this socket — or when
     * the reader gives up / is closed, so nothing can wait on it forever.
     * [TorManager] holds `Connected` (bounded) until it completes, so the
     * session's FIRST `HS_DESC REQUESTED` / `RECEIVED` — the HSDir the
     * [HsDirLedger] pins re-fetches to — is never lost to a subscription that
     * lands after the first onion request.
     */
    val subscribed: kotlinx.coroutines.CompletableDeferred<Unit> = kotlinx.coroutines.CompletableDeferred()

    private val dedupe = TorEventDedupe()
    private var inDataBlock = false
    private var reportedUnavailable = false

    // Consensus-age question, asked at most once per session (see
    // [askConsensusAge]). All three are touched only from the reader coroutine.
    private var consensusReported = false
    /** [SystemClock.elapsedRealtime] the one deferred retry is due at; 0 = none. */
    private var consensusRetryAtMs = 0L
    /** Accumulates the deferred retry's reply while events interleave with it. */
    private var pendingReply: MutableList<String>? = null

    /** Launches the reader. Non-blocking; never throws. */
    fun start() {
        job = CoroutineScope(Dispatchers.IO).launch {
            try { run() } finally { subscribed.complete(Unit) }
        }
    }

    /** Idempotent teardown. `close()` on the socket also unblocks a parked read. */
    fun close() {
        closed = true
        subscribed.complete(Unit)
        job?.cancel()
        job = null
        try { socket?.close() } catch (_: Exception) {}
        socket = null
    }

    private suspend fun run() {
        // ONE reconnect: a control socket that drops while Tor is alive is worth
        // re-establishing once (a transient), but a reader that reconnects
        // forever would be a battery drain on a daemon that is going away.
        var reconnectsLeft = 1
        while (!closed) {
            val sock = openAuthenticated()
            if (sock == null) {
                subscribed.complete(Unit)
                reportUnavailableOnce()
                return
            }
            subscribed.complete(Unit)
            socket = sock
            try {
                readLoop(sock)
            } catch (e: Exception) {
                platformLogWarn("TorControlEvents", "event stream ended: ${e.javaClass.simpleName}")
            } finally {
                try { sock.close() } catch (_: Exception) {}
                socket = null
            }
            if (closed || !torAlive() || reconnectsLeft <= 0) return
            reconnectsLeft--
            // Per-connection parser state. The consensus question is NOT reset:
            // if it was already answered the reconnect must not ask again, and if
            // it was not, openAuthenticated() asks it afresh on the new socket.
            inDataBlock = false
            pendingReply = null
            consensusRetryAtMs = 0L
            delay(RECONNECT_DELAY_MS)
        }
    }

    private fun reportUnavailableOnce() {
        if (reportedUnavailable) return
        reportedUnavailable = true
        platformLogWarn("TorControlEvents", "control event channel unavailable — onion phases will not be logged")
        // Diagnostics only: Tor is unaffected, the panel just shows less.
        ConnectionLog.append(ConnectionLog.Kind.SYSTEM, "control events unavailable")
    }

    /**
     * Connects the AF_UNIX ControlSocket, AUTHENTICATEs with the cookie and
     * subscribes. Same bounded-retry + full-length-cookie discipline as
     * [TorManager.connectControlChannel] (a short read of a cookie Tor is still
     * writing must retry, never be sent as the secret); the cookie read itself is
     * the shared [readTorControlCookie] (TorManager.kt). The socket CONNECT is
     * deliberately its own copy rather than a shared helper, so the command
     * socket's one-line reply parser and this event socket can never end up on
     * the same stream.
     */
    private suspend fun openAuthenticated(): LocalSocket? {
        val socketFile = File(dataDir, TOR_CONTROL_SOCKET_NAME)
        val cookieFile = File(dataDir, TOR_CONTROL_COOKIE_NAME)
        var attempt = 0
        while (attempt < CONNECT_ATTEMPTS && !closed && torAlive()) {
            attempt++
            val cookie = readTorControlCookie(cookieFile)
            if (cookie == null || !socketFile.exists()) {
                // `cookie != null` here whenever the SOCKET is what is missing
                // (Tor writes the cookie before it binds the socket, so this is
                // the ordinary first-attempt path, not a corner case) — zero it
                // like the connect-failure and handshake branches below do,
                // instead of dropping a live control secret into the heap for
                // the GC to relocate.
                cookie?.fill(0)
                delay(CONNECT_RETRY_MS)
                continue
            }
            val sock = try {
                LocalSocket().apply {
                    connect(
                        LocalSocketAddress(
                            socketFile.absolutePath,
                            LocalSocketAddress.Namespace.FILESYSTEM,
                        ),
                    )
                    setSoTimeout(HANDSHAKE_TIMEOUT_MS)
                }
            } catch (_: Exception) {
                cookie.fill(0)
                delay(CONNECT_RETRY_MS)
                continue
            }
            // Local handshake result — NOT the class-level [subscribed] deferred,
            // which [run] completes once this function returns (socket or null).
            val handshakeOk = try {
                if (!send(sock, "AUTHENTICATE ${bytesToHex(cookie)}")) {
                    false
                } else {
                    // BEFORE SETEVENTS, deliberately: until we subscribe, no
                    // async 650 line can exist on this stream, so the GETINFO's
                    // multi-line reply cannot be interleaved with one. (The
                    // command socket must never ask this — it reads replies per
                    // command, so an interleaved 650 would be taken as a reply.)
                    askConsensusAge(sock)
                    send(sock, TOR_SETEVENTS_COMMAND)
                }
            } catch (e: Exception) {
                platformLogWarn("TorControlEvents", "event socket handshake threw: ${e.javaClass.simpleName}")
                false
            } finally {
                // Zeroes the byte copy; the hex String built for AUTHENTICATE
                // lives until GC (a String cannot be zeroed). Same on the
                // command socket (TorManager.connectControlChannel).
                cookie.fill(0)
            }
            if (handshakeOk) {
                settleReadTimeout(sock)
                platformLog("TorControlEvents", "subscribed to Tor control events")
                return sock
            }
            try { sock.close() } catch (_: Exception) {}
            delay(CONNECT_RETRY_MS)
        }
        return null
    }

    /** Writes one command and returns whether Tor answered `250`. */
    private fun send(sock: LocalSocket, command: String): Boolean {
        write(sock, command)
        val reply = readLine(sock.inputStream) ?: return false
        return reply.startsWith("250")
    }

    private fun write(sock: LocalSocket, command: String) {
        val out = sock.outputStream
        out.write("$command\r\n".toByteArray(Charsets.US_ASCII))
        out.flush()
    }

    /**
     * Writes [command] and collects its WHOLE reply — `250-…`/`250+…`
     * continuation lines through the final `250 OK` (or a `5xx`). Only safe
     * before SETEVENTS; the deferred retry, which runs with events live, is
     * assembled by [consumeReplyLine] instead.
     */
    private fun command(sock: LocalSocket, command: String): List<String> {
        write(sock, command)
        val lines = ArrayList<String>()
        while (lines.size < MAX_REPLY_LINES) {
            val line = readLine(sock.inputStream) ?: break
            if (line.startsWith("650")) continue   // defensive: cannot happen pre-SETEVENTS
            lines.add(line)
            if (isFinalReplyLine(line)) break
        }
        return lines
    }

    /**
     * Asks for the consensus age ONCE per session. A `552` (Tor has no consensus
     * yet — normal on a cold start) schedules the single retry from inside the
     * read loop rather than blocking here, so SETEVENTS is not delayed by 5 s:
     * the events of those 5 s are the early guard connections this whole line
     * exists to put in context.
     */
    private fun askConsensusAge(sock: LocalSocket) {
        if (consensusReported) return
        // Deliberately NOT wrapped in its own catch: if the read times out, the
        // reply may still arrive later and would then be consumed as SETEVENTS'
        // "250" — the exact reply-desync this design exists to avoid. Letting it
        // propagate drops the socket and reconnects, which is the only safe
        // response to a stream whose state is unknown.
        val reply = command(sock, TOR_GETINFO_CONSENSUS_VALID_AFTER)
        if (parseConsensusValidAfter(reply) != null) {
            emitConsensusAge(reply)
        } else {
            consensusRetryAtMs = SystemClock.elapsedRealtime() + CONSENSUS_RETRY_DELAY_MS
        }
    }

    /** Emits the one consensus-freshness line (bucket only — never the timestamp). */
    private fun emitConsensusAge(reply: List<String>) {
        consensusReported = true
        consensusRetryAtMs = 0L
        pendingReply = null
        val line = consensusAgeLine(reply, currentTimeMillis() / 1000L)
        ConnectionLog.append(line.kind, line.text, line.code)
    }

    /** Short idle reads while the consensus retry is pending, long ones after. */
    private fun settleReadTimeout(sock: LocalSocket) {
        try {
            sock.setSoTimeout(
                if (consensusReported && pendingReply == null) EVENT_READ_TIMEOUT_MS
                else CONSENSUS_POLL_TIMEOUT_MS,
            )
        } catch (_: Exception) { /* best-effort: only affects wake granularity */ }
    }

    private fun readLoop(sock: LocalSocket) {
        val input = sock.inputStream
        while (!closed && torAlive()) {
            maybeRetryConsensus(sock)
            val line = try {
                readLine(input) ?: return          // EOF: the daemon closed it
            } catch (_: InterruptedIOException) {
                // Idle-read timeout: re-check the loop conditions and keep waiting.
                continue
            }
            if (consumeReplyLine(sock, line)) continue
            handle(line)
        }
    }

    /** Fires the ONE deferred GETINFO retry once its delay has elapsed. */
    private fun maybeRetryConsensus(sock: LocalSocket) {
        if (consensusReported || pendingReply != null) return
        if (consensusRetryAtMs == 0L || SystemClock.elapsedRealtime() < consensusRetryAtMs) return
        consensusRetryAtMs = 0L                     // one retry, whatever it answers
        try {
            write(sock, TOR_GETINFO_CONSENSUS_VALID_AFTER)
            pendingReply = ArrayList()
        } catch (e: Exception) {
            platformLogWarn("TorControlEvents", "consensus-age retry could not be sent: ${e.javaClass.simpleName}")
            // Report it as unknown rather than leaving the question open (and the
            // idle-read timeout short) for the rest of the session.
            emitConsensusAge(emptyList())
            settleReadTimeout(sock)
        }
    }

    /**
     * True when [line] belonged to the deferred GETINFO reply rather than being
     * an event. `650` lines are events even mid-reply (Tor may interleave them),
     * and so are the payload lines of a `650+` data block.
     */
    private fun consumeReplyLine(sock: LocalSocket, line: String): Boolean {
        val pending = pendingReply ?: return false
        if (inDataBlock || line.startsWith("650")) return false
        pending.add(line)
        if (isFinalReplyLine(line) || pending.size >= MAX_REPLY_LINES) {
            emitConsensusAge(pending)
            settleReadTimeout(sock)
        }
        return true
    }

    /**
     * Routes one raw line from the event socket, skipping `650+` data payloads
     * outright. In order:
     *  1. the descriptor watchdog hook ([onRelayDescriptorEvent], via the relay
     *     race's parser),
     *  2. the circuit watchdog hook ([onControlEvent]),
     *  3. the bootstrap-stall hook ([onBootstrapProgress]),
     * then parses the line, applies the 2 s per-code dedupe and emits it to the
     * connection log. The three hooks run BEFORE the dedupe on purpose: the
     * dedupe decides what the panel shows, never what the watchdogs and the
     * stall timer know — they must see every event.
     */
    private fun handle(raw: String) {
        if (inDataBlock) {
            if (raw == ".") inDataBlock = false
            return
        }
        if (raw.startsWith("650+")) inDataBlock = true
        // The watchdog sees EVERY descriptor event: the 2 s log dedupe below
        // decides what the panel shows, not what the timer knows.
        relayRace?.parseDescriptorEvent(raw)?.let { event ->
            try {
                onRelayDescriptorEvent(event)
            } catch (e: Exception) {
                platformLogWarn("TorControlEvents", "descriptor watchdog hook threw: ${e.javaClass.simpleName}")
            }
        }
        onControlEvent?.let { hook ->
            try {
                hook(raw)
            } catch (e: Exception) {
                platformLogWarn("TorControlEvents", "circuit watchdog hook threw: ${e.javaClass.simpleName}")
            }
        }
        onBootstrapProgress?.let { hook ->
            TorBootstrapStall.progressFromControlEvent(raw)?.let { pct ->
                try {
                    hook(pct)
                } catch (e: Exception) {
                    platformLogWarn("TorControlEvents", "bootstrap-stall hook threw: ${e.javaClass.simpleName}")
                }
            }
        }
        val event = parseTorControlEvent(raw) ?: return
        if (!dedupe.allow(event.code, SystemClock.elapsedRealtime())) return
        ConnectionLog.append(event.kind, event.text, event.code, event.streamKey)
    }

    /**
     * One CRLF-terminated line, or null at EOF. Bounded by
     * [MAX_EVENT_LINE_CHARS]: an over-long line is truncated (the excess is
     * consumed and dropped) rather than allowed to grow the buffer — the parser's
     * allowlists make a truncated line degrade to "OTHER", never to a leak.
     */
    private fun readLine(input: java.io.InputStream): String? {
        val sb = StringBuilder()
        while (true) {
            val b = input.read()
            if (b < 0) return if (sb.isEmpty()) null else sb.toString()
            if (b == '\n'.code) return sb.toString()
            if (b == '\r'.code) continue
            if (sb.length < MAX_EVENT_LINE_CHARS) sb.append(b.toChar())
        }
    }
}

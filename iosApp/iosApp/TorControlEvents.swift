import Foundation

// ---------------------------------------------------------------------------
// TorControlEvents — the PURE half of the Tor control-port event tap.
//
// Turns one raw `650` async event line from Tor's control port into at most one
// ConnectionLog line. No I/O, no state, no framework types: the whole file is
// stdlib-only so the mapping can be reasoned about (and exercised) on its own,
// and so a careless future edit cannot reach a log sink from here. The impure
// half — the SETEVENTS subscription, the observer block, the de-dupe window and
// the bridge to `ConnectionLog` (commonMain) — lives in TorControlEventTap.swift.
//
// WHY THIS EXISTS: everything between "Tor bootstrapped" and "the relay
// answered" (HSDir descriptor fetch → introduction point → rendezvous → first
// stream) would be invisible to the app without this tap, because the bootstrap
// observers are removed the moment CIRCUIT_ESTABLISHED arrives. That phase is
// exactly where a stuck connect stalls, so the live connection-log panel gets
// the onion half of the story here.
//
// PRODUCER RULE (ConnectionLog.kt, rule 1 — emit no identifiers BY
// CONSTRUCTION). Every line this file returns is a fixed phrase plus, at most,
// one token from Tor's own CLOSED vocabulary (HS_DESC action/reason, CIRC
// purpose/HS_STATE/REASON, STREAM status/reason, GUARD status, bootstrap TAG)
// or a small integer. Values that identify anything — the onion address
// (HSAddress / REND_QUERY), the HSDir or guard fingerprint/nickname, the circuit
// path, the stream Target, SOURCE/SOURCE_ADDR, HOSTID/HOSTADDR, descriptor ids,
// circuit/stream ids, and the free-text SUMMARY / WARNING prose — are NEVER
// copied into a line, not even in a "failed" message. Unknown vocabulary tokens
// collapse to "OTHER" rather than being passed through, so a Tor version that
// invents a new REASON cannot widen what we print. `ConnectionLog.redact()` is
// defence in depth on top of that, never the control.
//
// Android sibling: the same phrases are produced by the Android Tor watcher, so
// the panel reads identically on both platforms — do not reword one side alone.
// ---------------------------------------------------------------------------

/// Mirror of `ConnectionLog.Kind` (commonMain), kept framework-free so this file
/// stays pure. Bridged in TorControlEventTap.swift.
enum TorLogKind {
    case tor, relay, health, stall, system
}

/// Mirror of the `ConnectionLog.Code` subset this parser can produce (commonMain
/// owns the full vocabulary). Bridged in TorControlEventTap.swift, where the
/// exhaustive `switch` makes a missing case a compile error rather than a silent
/// untagged line.
enum TorLogCode: String {
    // Onion-service half. The two *Launched cases (C2d) are the onion twin of
    // orconnLaunched: LAUNCHED-without-BUILT is the shape of a circuit that
    // never completed, which is exactly the measured stall.
    case hsdescRequested, hsdescReceived, hsdescFailed
    // hsdescFailed split by Tor's REASON (2026-10-23) — see
    // TorControlEventParser.hsDescFailCodes. Not rate-limited, like hsdescFailed.
    case hsdescNotFound, hsdescNoHsdir, hsdescRateLimited, hsdescBadDesc, hsdescUnexpected
    case hsdirCircFailed, introCircLaunched, introCircBuilt, introSent, introDone, introCircFailed
    case rendCircLaunched, rendCircBuilt, rendJoined, rendCircFailed
    case streamSent, streamOk, streamFailed
    case guardUp, guardDown, guardDropped
    // Guard CHANNELS (not circuits) + directory freshness. The three consensus
    // cases (C2c) were ONE code until 2026-09-15; only the code reaches the
    // connect timeline, so "fresh" / "stale" / "Tor had no consensus to report"
    // — three different explanations of the same stall — were indistinguishable
    // there. Android sibling: TorControlEvents.kt's consensusAgeCode.
    case orconnLaunched, orconnConnected, orconnFailed
    case consensusFresh, consensusStale, consensusUnknown
    // Client/daemon status
    case dirEnough, dirNotEnough, circuitOk, circuitLost
    case netUp, netDown, clockSkew, clockJumped
    case torBootstrapProblem

    /// Codes whose event can legitimately repeat many times a second (Tor
    /// reports every purpose/state transition via CIRC_MINOR, and several
    /// circuits race for the same onion), or that two producers can report — the
    /// tap applies a short one-line-per-code window to these. See
    /// `TorControlEventTap.dedupeWindowSec`.
    var isRateLimited: Bool {
        switch self {
        case .introCircLaunched, .introCircBuilt, .introSent, .introDone, .introCircFailed,
             .rendCircLaunched, .rendCircBuilt, .rendJoined, .rendCircFailed, .hsdirCircFailed,
             // circuitOk has TWO producers: this tap and TorManager's own
             // forCircuitEstablished observer (which also fires from the
             // registration-time GETINFO readback). The window collapses that
             // pair into the one line the panel should show.
             .circuitOk:
            return true
        default:
            return false
        }
    }
}

/// One ConnectionLog line derived from one control-port event.
struct TorLogLine: Equatable {
    let kind: TorLogKind
    let text: String
    let code: TorLogCode
    /// Tor's own StreamID, for the three `stream*` codes only — the PAIRING
    /// handle `ConnectionLog` uses to match a `SENTCONNECT` with the
    /// `SUCCEEDED`/`FAILED` that ends it (fix 2b, 2026-09-16), so the debug-mode
    /// uploader can leave an uneventful sub-5 s stream out of a batch while
    /// still shipping a slow or failed one together with its start line.
    ///
    /// It is NOT part of `text` and never will be: the producer rule in this
    /// file's header bans a stream id from a line, and the commonMain
    /// `ConnectionLog.Line` keeps this one in a field nothing renders, uploads
    /// or reports. Android sibling: `TorEventLine.streamKey`.
    let streamKey: Int64?

    init(kind: TorLogKind, text: String, code: TorLogCode, streamKey: Int64? = nil) {
        self.kind = kind
        self.text = text
        self.code = code
        self.streamKey = streamKey
    }
}

enum TorControlEventParser {

    // MARK: - Entry point

    /// Maps ONE async control-port reply line to a log line, or nil when the
    /// event is not one we narrate (the overwhelming majority — GENERAL-purpose
    /// circuits, descriptor uploads, guard bookkeeping, bootstrap NOTICEs that
    /// the existing progress observer already renders).
    ///
    /// Accepts the line with or without its `650` reply prefix: TORController
    /// hands observers the text after the code, while Tor's own control-spec
    /// examples (and this parser's tests) carry it.
    static func parse(_ raw: String) -> TorLogLine? {
        let line = stripReplyPrefix(raw)
        guard let sp = line.firstIndex(of: " ") else { return nil }
        let event = String(line[line.startIndex..<sp])
        let rest = tokenize(String(line[line.index(after: sp)...]))
        guard !rest.isEmpty else { return nil }

        switch event {
        case "HS_DESC":          return parseHsDesc(rest)
        case "CIRC":             return parseCirc(rest)
        case "CIRC_MINOR":       return parseCircMinor(rest)
        case "ORCONN":           return parseOrConn(rest)
        case "STREAM":           return parseStream(rest)
        case "STATUS_CLIENT":    return parseStatusClient(rest)
        case "STATUS_GENERAL":   return parseStatusGeneral(rest)
        case "NETWORK_LIVENESS": return parseNetworkLiveness(rest)
        case "GUARD":            return parseGuard(rest)
        default:                 return nil
        }
    }

    // MARK: - HS_DESC  (the v3 descriptor fetch — the first onion-only phase)
    //
    // `HS_DESC <Action> <HSAddress> <AuthType> <HsDir> [<DescriptorID>] [REASON=]`
    // Fields 1-4 are ALL identifying (the onion address and the HSDir's
    // fingerprint~nickname) and are never read.

    private static func parseHsDesc(_ t: [String]) -> TorLogLine? {
        switch t[0] {
        case "REQUESTED":
            return line("descriptor requested", .hsdescRequested)
        case "RECEIVED":
            return line("descriptor received", .hsdescReceived)
        case "FAILED":
            // TEXT: allowlist-or-OTHER, unchanged. CODE: the fixed REASON → code
            // split (2026-10-23) — an off-map reason keeps .hsdescFailed. Neither
            // is ever built from the raw value.
            let raw = value(of: "REASON", in: t)
            let reason = allow(raw, hsDescReasons)
            return line("descriptor fetch failed: \(reason)", hsDescFailureCode(raw))
        default:
            // CREATED / UPLOAD / UPLOADED / IGNORE — service-side or noise.
            return nil
        }
    }

    private static let hsDescReasons: Set<String> = [
        "NOT_FOUND", "QUERY_NO_HSDIR", "QUERY_RATE_LIMITED", "QUERY_REJECTED",
        "BAD_DESC", "UNEXPECTED",
    ]

    /// The FIXED `HS_DESC FAILED` REASON → connect-code split (2026-10-23).
    /// Android/commonMain sibling: `TorReasonVocabulary.hsDescFailureCode` —
    /// `TorReasonParitySourceTest` (androidApp) pins this table to that one.
    /// QUERY_REJECTED, a future Tor's new reason and a missing REASON all keep
    /// the pre-split `.hsdescFailed`.
    static let hsDescFailCodes: [String: TorLogCode] = [
        "NOT_FOUND": .hsdescNotFound,
        "QUERY_NO_HSDIR": .hsdescNoHsdir,
        "QUERY_RATE_LIMITED": .hsdescRateLimited,
        "BAD_DESC": .hsdescBadDesc,
        "UNEXPECTED": .hsdescUnexpected,
    ]

    static func hsDescFailureCode(_ raw: String?) -> TorLogCode {
        guard let raw else { return .hsdescFailed }
        return hsDescFailCodes[raw.uppercased()] ?? .hsdescFailed
    }

    // MARK: - CIRC  (introduction + rendezvous circuits)
    //
    // `CIRC <CircID> <Status> [<Path>] [PURPOSE=] [HS_STATE=] [REND_QUERY=] …`
    // CircID, Path and REND_QUERY (the onion address) are never read.

    private static func parseCirc(_ t: [String]) -> TorLogLine? {
        guard t.count >= 2 else { return nil }
        let status = t[1]
        let purpose = value(of: "PURPOSE", in: t) ?? ""
        // GENERAL-purpose circuits (the bulk of Tor's churn) get no line at all:
        // they say nothing about this app's connect and would bury the rest.
        let isHs = purpose == "HS_CLIENT_HSDIR" || purpose == "HS_CLIENT_INTRO" || purpose == "HS_CLIENT_REND"
        guard isHs else { return nil }

        // Failure FIRST: a FAILED/CLOSED event still carries HS_STATE, and the
        // outcome is what matters.
        if status == "FAILED" || status == "CLOSED" {
            let rawReason = value(of: "REASON", in: t)
            // An intro circuit's ORDINARY end is a close, not a failure: once the
            // INTRODUCE_ACK arrives Tor flips it to INTRODUCE_ACKED
            // (HS_STATE=HSCI_DONE) and closes it with REASON=FINISHED (hs_client.c
            // handle_introduce_ack_success). Coding that as introCircFailed put a
            // "failure" into ~70 % of fast, healthy timelines. Every FINISHED
            // close of an intro circuit is Tor's own bookkeeping — the ack above,
            // the give-up after a NACK (already reported as "introduction
            // refused" from CIRC_MINOR), a descriptor replacement, RELAY_EARLY
            // exhaustion — never a network fault. A genuine failure stays one:
            // FAILED (never built), or a CLOSED with any other REASON while the
            // intro was still unacknowledged.
            // Android sibling: TorControlEvents.kt parseCirc.
            if purpose == "HS_CLIENT_INTRO", status == "CLOSED",
               rawReason == "FINISHED" || value(of: "HS_STATE", in: t) == "HSCI_DONE" {
                return nil
            }
            let reason = allow(rawReason, circReasons)
            switch purpose {
            case "HS_CLIENT_HSDIR": return line("directory circuit failed: \(reason)", .hsdirCircFailed)
            case "HS_CLIENT_INTRO": return line("introduction circuit failed: \(reason)", .introCircFailed)
            default:                return line("rendezvous circuit failed: \(reason)", .rendCircFailed)
            }
        }

        // DEFENSIVE ONLY. Tor does NOT re-emit a plain CIRC event when the HS
        // state changes — `circuit_change_purpose()` reports it solely as
        // CIRC_MINOR PURPOSE_CHANGED (see parseCircMinor), which is why
        // introSent / introDone / rendJoined never appeared before CIRC_MINOR was
        // subscribed. A non-terminal CIRC carrying one of these states is not
        // expected from Tor 0.4.9; it is still narrated as the state rather than
        // as a second "circuit built", should a future Tor ever send one.
        switch value(of: "HS_STATE", in: t) {
        case "HSCI_INTRO_SENT": return line("introduction sent", .introSent)
        case "HSCI_DONE":       return line("introduction complete", .introDone)
        case "HSCR_JOINED":     return line("rendezvous joined", .rendJoined)
        default:                break
        }

        if status == "BUILT" {
            switch purpose {
            // An HSDIR circuit being built says nothing the HS_DESC lines don't.
            case "HS_CLIENT_HSDIR": return nil
            case "HS_CLIENT_INTRO": return line("introduction circuit built", .introCircBuilt)
            default:                return line("rendezvous circuit built", .rendCircBuilt)
            }
        }

        // LAUNCHED (C2d). Reached only when the HS_STATE switch above did not
        // match, which is the case at launch (HSCI_CONNECTING / HSCR_CONNECTING
        // are not states we narrate). A LAUNCHED with no BUILT after it is the
        // stall signature the panel and the timeline were blind to: they could
        // only show the BUILT that never arrived, i.e. nothing.
        // Android sibling: TorControlEvents.kt parseCirc.
        guard status == "LAUNCHED" else { return nil }
        switch purpose {
        case "HS_CLIENT_HSDIR": return nil
        case "HS_CLIENT_INTRO": return line("introduction circuit launched", .introCircLaunched)
        default:                return line("rendezvous circuit launched", .rendCircLaunched)
        }
    }

    // MARK: - CIRC_MINOR  (the onion handshake itself)
    //
    // `CIRC_MINOR <CircID> <Event> [<Path>] [BUILD_FLAGS=] [PURPOSE=] [HS_STATE=]
    //  [REND_QUERY=] [TIME_CREATED=] [OLD_PURPOSE=] [OLD_HS_STATE=]`
    //
    // The ONLY place Tor reports the onion handshake's progress: every
    // `circuit_change_purpose()` on an intro/rendezvous circuit is a
    // PURPOSE_CHANGED here and nowhere else. Read: the event keyword, PURPOSE,
    // HS_STATE and OLD_HS_STATE — closed Tor vocabularies, matched exactly and
    // never echoed. CircID, Path, REND_QUERY (the onion) and TIME_CREATED are
    // never read.
    //
    // Transitions narrated (hs_client.c, Tor 0.4.9):
    //  - INTRO → HSCI_INTRO_SENT: INTRODUCE1 is on the wire (introSent).
    //  - INTRO HSCI_INTRO_SENT → HSCI_DONE: the intro point ACKED (introDone).
    //  - INTRO HSCI_INTRO_SENT → HSCI_CONNECTING: the intro point NACKED — Tor goes
    //    back to "connecting" to re-extend (handle_introduce_ack_bad). A genuine
    //    intro failure → introCircFailed.
    //  - INTRO HSCI_CONNECTING → HSCI_DONE: the give-up after that NACK
    //    (close_or_reextend_intro_circ) — NOT an ack, already reported: no line.
    //  - REND → HSCR_JOINED: RENDEZVOUS2 arrived, the onion session is up (rendJoined).
    // Everything else (rendezvous established/waiting, CANNIBALIZED, GENERAL and
    // HSDIR purposes) produces no line.
    // Android sibling: TorControlEvents.kt parseCircMinor — same phrases.

    private static func parseCircMinor(_ t: [String]) -> TorLogLine? {
        guard t.count >= 2, t[1] == "PURPOSE_CHANGED" else { return nil }
        let state = value(of: "HS_STATE", in: t)
        switch value(of: "PURPOSE", in: t) {
        case "HS_CLIENT_INTRO":
            let old = value(of: "OLD_HS_STATE", in: t)
            switch state {
            case "HSCI_INTRO_SENT":
                return line("introduction sent", .introSent)
            case "HSCI_DONE":
                // Tor always names OLD_HS_STATE for an intro purpose; a missing
                // one is read as the ack (the only path that reaches DONE from
                // the sent state) rather than dropped.
                guard old == nil || old == "HSCI_INTRO_SENT" else { return nil }
                return line("introduction complete", .introDone)
            case "HSCI_CONNECTING":
                guard old == "HSCI_INTRO_SENT" else { return nil }
                return line("introduction refused", .introCircFailed)
            default:
                return nil
            }
        case "HS_CLIENT_REND":
            return state == "HSCR_JOINED" ? line("rendezvous joined", .rendJoined) : nil
        default:
            return nil
        }
    }

    private static let circReasons: Set<String> = [
        "TIMEOUT", "DESTROYED", "CHANNEL_CLOSED", "CONNECTFAILED", "NOPATH",
        "RESOURCELIMIT", "OR_IDENTITY", "INTERNAL", "MEASUREMENT_EXPIRED", "FINISHED",
    ]

    // MARK: - ORCONN  (the TLS channel to a relay, underneath every circuit)
    //
    // `ORCONN <Target> <Status> [REASON=] [NCIRCS=] [ID=]`
    //
    // WHY IT IS HERE (2026-09-14): a production connect spent 155 s after
    // "bootstrapped 100 %" with nothing reaching the relay. A CIRC-only view
    // cannot tell "the circuit is slow" from "the CHANNEL to guard #2 never came
    // up" — with NumEntryGuards 8 a new OR connection is attempted often, and a
    // stalled one blocks every circuit that wanted that guard until the 45 s
    // CircuitBuildTimeout prices it. LAUNCHED-without-CONNECTED is that shape,
    // visible only here.
    //
    // Target is `$fingerprint~nickname` or `IP:port` — the relay this user is
    // dialling right now. It is NEVER copied into a line.

    private static func parseOrConn(_ t: [String]) -> TorLogLine? {
        guard t.count >= 2 else { return nil }
        switch t[1] {
        case "LAUNCHED":
            return line("or connection launched", .orconnLaunched)
        case "CONNECTED":
            return line("or connection connected", .orconnConnected)
        case "FAILED":
            return line("or connection failed: \(allow(value(of: "REASON", in: t), orConnReasons))", .orconnFailed)
        case "CLOSED":
            // An ordinary close (REASON=DONE, or Tor simply dropping an idle
            // channel) is not a failure and happens constantly.
            let raw = value(of: "REASON", in: t)
            guard let raw, raw != "DONE" else { return nil }
            return line("or connection failed: \(allow(raw, orConnReasons))", .orconnFailed)
        default:
            // NEW = an INCOMING connection (a client never has those in a way
            // that matters here).
            return nil
        }
    }

    private static let orConnReasons: Set<String> = [
        "DONE", "CONNECTREFUSED", "IDENTITY", "CONNECTRESET", "TIMEOUT",
        "NOROUTE", "IOERROR", "RESOURCELIMIT", "MISC", "PT_MISSING",
    ]

    // MARK: - STREAM  (the actual request riding the rendezvous circuit)
    //
    // `STREAM <StreamID> <Status> <CircID> <Target> [REASON=] [SOURCE=] …`
    // Target is `<onion>:<port>` and SOURCE/SOURCE_ADDR is a local address —
    // neither is ever read.

    private static func parseStream(_ t: [String]) -> TorLogLine? {
        guard t.count >= 2 else { return nil }
        // The StreamID is read ONLY as a pairing handle (see
        // `TorLogLine.streamKey`); it is never echoed into the line's text. A
        // non-numeric id (Tor never emits one) leaves the pair unmatched, which
        // ships the line — the safe side.
        let key = Int64(t[0])
        switch t[1] {
        case "SENTCONNECT":
            return line("stream connecting", .streamSent, key)
        case "SUCCEEDED":
            return line("stream connected", .streamOk, key)
        case "FAILED", "CLOSED":
            let raw = value(of: "REASON", in: t)
            // A CLOSED stream reporting DONE/END is an ORDINARY completed
            // request (every relay call closes its stream) — not a failure, and
            // it would otherwise out-number every real line in the panel.
            if t[1] == "CLOSED", raw == "DONE" || raw == "END" { return nil }
            return line("stream failed: \(allow(raw, streamReasons))", .streamFailed, key)
        default:
            return nil
        }
    }

    private static let streamReasons: Set<String> = [
        "TIMEOUT", "RESOLVEFAILED", "CONNECTREFUSED", "DESTROY", "TORPROTOCOL",
        "INTERNAL", "RESOURCELIMIT", "MISC", "END", "DONE",
    ]

    // MARK: - STATUS_CLIENT
    //
    // `STATUS_CLIENT <Severity> <Action> [KEY=VALUE …]`

    private static func parseStatusClient(_ t: [String]) -> TorLogLine? {
        guard t.count >= 2 else { return nil }
        let severity = t[0]
        switch t[1] {
        case "ENOUGH_DIR_INFO":
            return line("enough directory info", .dirEnough)
        case "NOT_ENOUGH_DIR_INFO":
            return line("not enough directory info", .dirNotEnough)
        case "CIRCUIT_ESTABLISHED":
            return line("circuit established", .circuitOk)
        case "CIRCUIT_NOT_ESTABLISHED":
            // REASON here is a closed vocabulary of one (CLOCK_JUMPED); anything
            // else stays unqualified rather than being echoed.
            let jumped = value(of: "REASON", in: t) == "CLOCK_JUMPED"
            return line(jumped ? "circuit lost (clock jumped)" : "circuit lost", .circuitLost)
        case "BOOTSTRAP":
            // NOTICE bootstrap events are the ordinary progress ladder, already
            // rendered by TorManager's own progress observer — only the
            // PROBLEM variants (which carry REASON/COUNT and are dropped there)
            // are new information. WARNING=, RECOMMENDATION=, HOSTID= and
            // HOSTADDR= ride the SAME event and are deliberately never read:
            // the first is free prose, the last two name the relay we failed
            // against.
            //
            // WARN *or* ERR: tor raises the severity to ERR on the LAST
            // bootstrap problem before it gives up, which is the single most
            // diagnostic one — Android has always accepted both
            // (TorControlEvents.kt), and this parser dropped it. Keep the two
            // in step.
            guard severity == "WARN" || severity == "ERR" else { return nil }
            guard let raw = value(of: "REASON", in: t) else { return nil }
            let tag = sanitizedTag(value(of: "TAG", in: t))
            let progress = nonNegativeInt(value(of: "PROGRESS", in: t))
            let count = nonNegativeInt(value(of: "COUNT", in: t))
            return line(
                "bootstrap problem at \(tag) (\(progress)%): \(allow(raw, bootstrapReasons)), count \(count)",
                .torBootstrapProblem
            )
        default:
            return nil
        }
    }

    private static let bootstrapReasons: Set<String> = [
        "MISC", "RESOURCELIMIT", "IDENTITY", "CONNECTREFUSED", "CONNECTRESET",
        "TIMEOUT", "NOROUTE", "IOERROR", "PT_MISSING",
    ]

    // MARK: - STATUS_GENERAL  (clock health — the classic silent onion killer)
    //
    // A skewed clock breaks descriptor validation and consensus acceptance with
    // no other symptom, so the panel says HOW FAR off, in buckets. Never the
    // exact offset (a precise clock delta is a fingerprint) and never SOURCE=
    // (which names the relay that told us).

    private static func parseStatusGeneral(_ t: [String]) -> TorLogLine? {
        guard t.count >= 2 else { return nil }
        switch t[1] {
        case "CLOCK_SKEW":
            // SKEW= is absent when tor only has a LOWER BOUND on the offset
            // (it then reports MIN_SKEW=), so fall back to it rather than
            // dropping the event — the bucket is coarse either way and a
            // "clock is at least this far off" line is exactly as actionable.
            // Android does the same (TorControlEvents.kt); SOURCE= stays unread
            // on both (it names the relay that told us).
            guard let s = seconds(value(of: "SKEW", in: t) ?? value(of: "MIN_SKEW", in: t)) else { return nil }
            return line("clock skew: \(bucket(s))", .clockSkew)
        case "CLOCK_JUMPED":
            guard let s = seconds(value(of: "TIME", in: t)) else { return nil }
            return line("clock jumped: \(bucket(s))", .clockJumped)
        default:
            return nil
        }
    }

    /// Coarse magnitude + direction. Tor reports a POSITIVE skew when our clock
    /// is ahead of the other party's.
    static func bucket(_ secs: Int) -> String {
        let magnitude = secs.magnitude
        let size: String
        switch magnitude {
        case ..<60:     size = "under 1 min"
        case ..<600:    size = "under 10 min"
        case ..<3_600:  size = "under 1 h"
        case ..<86_400: size = "under 1 d"
        default:        size = "1 d or more"
        }
        return "\(size) \(secs < 0 ? "behind" : "ahead")"
    }

    // MARK: - NETWORK_LIVENESS / GUARD

    private static func parseNetworkLiveness(_ t: [String]) -> TorLogLine? {
        switch t[0] {
        case "UP":   return line("network up", .netUp)
        case "DOWN": return line("network down", .netDown)
        default:     return nil
        }
    }

    /// `GUARD <Type> <Name> <Status>` — Name is `$fingerprint~nickname`, i.e. a
    /// direct pointer at this user's sticky entry node. It is never read; only
    /// the status transition is narrated, and only for ENTRY guards.
    private static func parseGuard(_ t: [String]) -> TorLogLine? {
        guard t.count >= 3, t[0] == "ENTRY" else { return nil }
        switch t[2] {
        case "UP":      return line("guard up", .guardUp)
        case "DOWN":    return line("guard down", .guardDown)
        case "DROPPED": return line("guard dropped", .guardDropped)
        // NEW / BAD / GOOD are bookkeeping, not connectivity.
        default:        return nil
        }
    }

    // MARK: - Consensus freshness  (a GETINFO answer, not an event)
    //
    // `GETINFO consensus/valid-after` answers with Tor's own UTC timestamp for
    // the consensus it is using. A warm daemon that kept a STALE directory looks
    // identical to a healthy warm one until something needs a relay the old
    // consensus no longer describes — which is exactly the "bootstrapped in 0.5 s
    // then 155 s of silence" shape. Only the BUCKET is ever narrated: the exact
    // timestamp would pin this install to a consensus (and to a relay it talked
    // to), and the age is the whole diagnostic.

    static func consensusAgeBucket(ageSeconds: Int) -> String {
        switch max(ageSeconds, 0) {
        case ..<3_600:                      return "under 1 h"
        case ..<consensusStaleAfterSeconds: return "under 3 h"
        case ..<86_400:                     return "under 24 h"
        default:                            return "over 24 h"
        }
    }

    /// Where FRESH ends and STALE begins: 3 hours, a consensus's own validity
    /// window (published hourly, valid for three), so the line is "older than
    /// what Tor is allowed to be using" rather than an invented threshold.
    /// Android sibling: `CONSENSUS_STALE_AFTER_SECONDS` in TorControlEvents.kt —
    /// keep the two in step, both the bucket text and the code.
    static let consensusStaleAfterSeconds = 10_800

    /// The CODE for an age (C2c). Only the code reaches the connect timeline, so
    /// fresh and stale had to stop sharing one.
    static func consensusAgeCode(ageSeconds: Int) -> TorLogCode {
        ageSeconds < consensusStaleAfterSeconds ? .consensusFresh : .consensusStale
    }

    /// The line for a successfully read `consensus/valid-after`, or nil when the
    /// value is not a Tor UTC timestamp (the caller then narrates "unknown").
    static func consensusAgeLine(validAfter raw: String, nowEpochSeconds: Int) -> TorLogLine? {
        guard let validAfter = parseTorTimestampUTC(raw) else { return nil }
        let age = nowEpochSeconds - validAfter
        return line("consensus age: \(consensusAgeBucket(ageSeconds: age))", consensusAgeCode(ageSeconds: age))
    }

    /// Used when the value is missing, a 552, or unparseable — one line either
    /// way, so the panel never just goes quiet about the directory. Its own code
    /// since C2c: "Tor had no consensus to report" is a different answer from
    /// "the consensus was fresh", and it used to be indistinguishable on the wire.
    static func consensusAgeUnknownLine() -> TorLogLine {
        line("consensus age: unknown", .consensusUnknown)
    }

    /// `YYYY-MM-DD HH:MM:SS` (UTC, Tor's control-port format) → epoch seconds.
    /// Hand-rolled civil-days arithmetic rather than a date formatter: no
    /// locale, no time zone database, no allocation — and it stays a pure
    /// function that can be checked against known values.
    static func parseTorTimestampUTC(_ raw: String) -> Int? {
        let s = raw.trimmingCharacters(in: CharacterSet(charactersIn: " \"\t\r\n"))
        // Tor also emits the ISO form with a 'T' separator in some replies.
        let parts = s.split(whereSeparator: { $0 == " " || $0 == "T" })
        guard parts.count >= 2 else { return nil }
        let date = parts[0].split(separator: "-")
        let time = parts[1].split(separator: ":")
        guard date.count == 3, time.count == 3,
              let y = Int(date[0]), let mo = Int(date[1]), let d = Int(date[2]),
              let h = Int(time[0]), let mi = Int(time[1]), let sec = Int(time[2].prefix(2)),
              y >= 2000, y <= 2200, (1...12).contains(mo), (1...31).contains(d),
              (0...23).contains(h), (0...59).contains(mi), (0...60).contains(sec)
        else { return nil }
        return daysFromCivil(y: y, m: mo, d: d) * 86_400 + h * 3_600 + mi * 60 + sec
    }

    /// Days since 1970-01-01 for a proleptic-Gregorian date (Howard Hinnant's
    /// `days_from_civil`).
    private static func daysFromCivil(y: Int, m: Int, d: Int) -> Int {
        let year = y - (m <= 2 ? 1 : 0)
        let era = (year >= 0 ? year : year - 399) / 400
        let yoe = year - era * 400
        let doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
        return era * 146_097 + doe - 719_468
    }

    // MARK: - Helpers

    private static func line(_ text: String, _ code: TorLogCode, _ streamKey: Int64? = nil) -> TorLogLine {
        TorLogLine(kind: .tor, text: text, code: code, streamKey: streamKey)
    }

    /// `650 `, `650-` or `650+` (mid/data reply lines) if present.
    private static func stripReplyPrefix(_ s: String) -> String {
        guard s.count > 4, s.hasPrefix("650") else { return s }
        let sep = s[s.index(s.startIndex, offsetBy: 3)]
        guard sep == " " || sep == "-" || sep == "+" else { return s }
        return String(s[s.index(s.startIndex, offsetBy: 4)...])
    }

    /// Space-separated fields, except inside double quotes: Tor's SUMMARY= and
    /// WARNING= values are quoted free text and CONTAIN spaces. Keeping them as
    /// one token is what stops a `KEY=VALUE` lookup from matching a fragment of
    /// that prose (and the prose itself is never emitted).
    static func tokenize(_ s: String) -> [String] {
        var out: [String] = []
        var cur = ""
        var inQuotes = false
        var escaped = false
        for ch in s {
            if escaped {
                cur.append(ch)
                escaped = false
            } else if ch == "\\" && inQuotes {
                cur.append(ch)
                escaped = true
            } else if ch == "\"" {
                inQuotes.toggle()
                cur.append(ch)
            } else if ch == " " && !inQuotes {
                if !cur.isEmpty { out.append(cur); cur = "" }
            } else {
                cur.append(ch)
            }
        }
        if !cur.isEmpty { out.append(cur) }
        return out
    }

    /// First `KEY=VALUE` token for [key], unquoted. nil when absent.
    private static func value(of key: String, in tokens: [String]) -> String? {
        let prefix = key + "="
        for token in tokens where token.hasPrefix(prefix) {
            let v = String(token.dropFirst(prefix.count))
            if v.count >= 2, v.hasPrefix("\""), v.hasSuffix("\"") {
                return String(v.dropFirst().dropLast())
            }
            return v
        }
        return nil
    }

    /// A vocabulary token passes through ONLY if it is one we know; everything
    /// else — including a missing value and a future Tor's new reason — becomes
    /// "OTHER". Allowlist, never a blocklist: that is what makes it impossible
    /// for an unexpected value (say a REASON that embedded an address) to reach
    /// a line.
    private static func allow(_ raw: String?, _ allowed: Set<String>) -> String {
        guard let raw, allowed.contains(raw) else { return "OTHER" }
        return raw
    }

    /// Bootstrap TAGs are lowercase identifiers from Tor's own fixed ladder
    /// (`conn_dir`, `handshake_or`, `requesting_descriptors`, …). Shape-checked
    /// rather than enumerated so a new Tor's new phase name still reads, but a
    /// value that is not tag-shaped collapses to a fixed phrase.
    private static func sanitizedTag(_ raw: String?) -> String {
        guard let raw, !raw.isEmpty, raw.count <= 32 else { return "unknown" }
        for c in raw.unicodeScalars {
            let ok = (c >= "a" && c <= "z") || (c >= "0" && c <= "9") || c == "_"
            if !ok { return "unknown" }
        }
        return raw
    }

    /// Clamped, never-negative small integer for PROGRESS/COUNT. A missing or
    /// junk value reads 0 rather than dropping the whole line.
    private static func nonNegativeInt(_ raw: String?) -> Int {
        guard let raw, let v = Int(raw), v >= 0 else { return 0 }
        return min(v, 1_000_000)
    }

    /// Signed seconds, tolerating the fractional form some Tor builds emit for
    /// SKEW. Returns nil when there is nothing parseable — the caller then emits
    /// no line at all rather than a bucket for a number it invented.
    private static func seconds(_ raw: String?) -> Int? {
        guard let raw, !raw.isEmpty else { return nil }
        if let v = Int(raw) { return v }
        guard let d = Double(raw), d.isFinite, d.magnitude < 1e15 else { return nil }
        return Int(d)
    }
}

// ---------------------------------------------------------------------------
// TorLogRedaction — a Swift MIRROR of `ConnectionLog.redact` (commonMain).
//
// Why a mirror and not a call: the Kotlin function is `internal`, so it is not
// exported to Swift by the Kotlin/Native ObjC bridge — only the `ConnectionLog`
// API surface (append / clear / snapshot) crosses. Keep the two in step: same
// three shapes, same placeholders, same order.
//
// Used ONLY for Tor's own daemon log lines on their way into the debug-gated
// `LogBuffer` (see TorManager's log callback). Those lines are Tor's, not ours,
// so unlike every ConnectionLog producer they are not fixed phrases by
// construction — `SafeLogging 1` scrubs the sensitive ones daemon-side and this
// is the second line of defence for the rest (an onion host, a URL, a
// fingerprint-shaped token).
// ---------------------------------------------------------------------------
enum TorLogRedaction {

    /// An inbox id is 32 chars and a capability 43 — the same threshold
    /// ConnectionLog uses, which also catches a 40-char relay fingerprint.
    private static let minOpaqueTokenLen = 32

    private static let placeholderUrl = "[url]"
    private static let placeholderOnion = "[onion]"
    private static let placeholderToken = "[redacted]"

    static func redact(_ text: String) -> String {
        stripLongTokens(stripOnionHosts(stripUrls(text)))
    }

    private static func isB64Char(_ c: Character) -> Bool {
        (c >= "A" && c <= "Z") || (c >= "a" && c <= "z") || (c >= "0" && c <= "9") || c == "-" || c == "_"
    }

    private static func isHostChar(_ c: Character) -> Bool { isB64Char(c) || c == "." }

    private static func stripUrls(_ s: String) -> String {
        var out = ""
        var i = s.startIndex
        while i < s.endIndex {
            let rest = s[i...]
            if rest.lowercased().hasPrefix("http://") || rest.lowercased().hasPrefix("https://") {
                out += placeholderUrl
                while i < s.endIndex, !s[i].isWhitespace { i = s.index(after: i) }
            } else {
                out.append(s[i])
                i = s.index(after: i)
            }
        }
        return out
    }

    private static func stripOnionHosts(_ s: String) -> String {
        var out = ""
        var i = s.startIndex
        while i < s.endIndex {
            if isHostChar(s[i]) {
                var j = i
                while j < s.endIndex, isHostChar(s[j]) { j = s.index(after: j) }
                let token = String(s[i..<j])
                out += token.lowercased().contains(".onion") ? placeholderOnion : token
                i = j
            } else {
                out.append(s[i])
                i = s.index(after: i)
            }
        }
        return out
    }

    private static func stripLongTokens(_ s: String) -> String {
        var out = ""
        var i = s.startIndex
        while i < s.endIndex {
            if isB64Char(s[i]) {
                var j = i
                while j < s.endIndex, isB64Char(s[j]) { j = s.index(after: j) }
                let token = String(s[i..<j])
                out += token.count >= minOpaqueTokenLen ? placeholderToken : token
                i = j
            } else {
                out.append(s[i])
                i = s.index(after: i)
            }
        }
        return out
    }
}

import Foundation
import shared

// ---------------------------------------------------------------------------
// TorControlEventTap — the IMPURE half of the Tor control-port event tap: it
// owns the de-dupe window and the bridge from this app's stdlib-only
// `TorLogLine` (TorControlEvents.swift) to `ConnectionLog` (commonMain).
//
// Called from Tor's own control-socket queue (the observer block installed in
// TorManager.armControlEventTap), NEVER from the main actor, so everything here
// is deliberately actor-free and lock-guarded. `ConnectionLog.append` is itself
// lock-guarded for exactly this reason, so no hop to main is needed — and a hop
// would reorder lines against the ones the main actor appends.
//
// Nothing here decides WHAT a line says: that is the pure parser's job, and the
// producer rule (no identifiers, fixed phrases + closed vocabulary) is enforced
// there. This file must never format a line of its own from event data.
// ---------------------------------------------------------------------------
final class TorControlEventTap: @unchecked Sendable {

    static let shared = TorControlEventTap()

    /// One line per code per window. Tor re-reports a circuit's purpose/state on
    /// every transition and several circuits race for the same onion, so without
    /// this the panel's 300-line ring buffer would be flushed by CIRC churn in
    /// seconds — evicting the bootstrap and relay lines a stuck user actually
    /// needs to read out. Applies only to `TorLogCode.isRateLimited`.
    private static let dedupeWindowSec: TimeInterval = 2.0

    private let lock = NSLock()
    /// code → `systemUptime` of the last emitted line. Monotonic clock on
    /// purpose: a wall-clock step (the very thing CLOCK_JUMPED reports) must not
    /// be able to open or close the window.
    private var lastEmittedAt: [TorLogCode: TimeInterval] = [:]

    private init() {}

    /// Entry point for the raw `650` observer: parse, then emit at most one line.
    func handle(replyLine: String) {
        // Descriptor hedge (TorManager.noteRelayDescriptorAction): the
        // SHARED classifier compares the HS_DESC address with the relay's and
        // returns only an enum, so nothing from the event leaves this call. It
        // sees EVERY descriptor event — the de-dupe window below governs the
        // panel, not the timer. Hopped to main (TorManager is main-actor
        // isolated); the serial hop keeps REQUESTED/SETTLED in Tor's order.
        //
        // HSDir pin (2026-10-08): the same parse also feeds the per-process
        // HsDirLedger HERE, on Tor's queue (the ledger is lock-guarded), so the
        // event's HSDir fingerprint never becomes a Swift value at all — it stays
        // inside the Kotlin event object, and nothing here logs it.
        //
        // Several onion addresses (2026-10-23): the SHARED race parses against
        // every configured address (only a slot index leaves it) and decides,
        // here on Tor's queue, the winner — which may switch the session's base
        // URL and abort the in-flight probe via the controller's hook — and
        // whether the event is the hedge's business at all.
        let race = TorManager.relayRace
        if let event = race.parseDescriptorEvent(rawEventLine: replyLine) {
            TorManager.hsDirLedger.observe(event: event)
            let observation = race.observe(event: event)
            // An Int crosses the hop, not the Kotlin event (not Sendable): 0 =
            // REQUESTED, 1 = RECEIVED, 2 = FAILED (TorManager.noteRelayDescriptorAction).
            let ordinal: Int
            switch event.action {
            case RelayDescriptorEvent.Action.requested: ordinal = 0
            case RelayDescriptorEvent.Action.received: ordinal = 1
            default: ordinal = 2
            }
            if observation.feedHedge {
                hopToMain { TorManager.shared.noteRelayDescriptorAction(ordinal) }
            }
        }
        // Hung onion-circuit rung (2026-10-08): the SHARED HsCircuitWatchdog reads
        // only CIRC / CIRC_MINOR / STREAM (the STREAM rule, 2026-10-09 — STREAM is
        // in the full event set); it keeps the circuit id solely to address a
        // CLOSECIRCUIT and returns only a delay, so nothing identifying crosses
        // the hop (an Int64 does). Fed on Tor's queue — the class is lock-guarded.
        if let delay = TorManager.hsCircuitWatchdog.observe(
            rawEventLine: replyLine,
            relayOnionAddresses: TorManager.relayHsFetchAddresses
        ) {
            let ms = delay.int64Value
            hopToMain { TorManager.shared.scheduleHsCircuitCheck(afterMs: ms) }
        }
        guard let line = TorControlEventParser.parse(replyLine) else { return }
        emit(line)
    }

    /// Emits a parsed line, honouring the de-dupe window. Also used by
    /// TorManager for the one line it produces itself that the tap can ALSO see
    /// (circuit established), so the two producers can never double it.
    func emit(_ line: TorLogLine) {
        if line.code.isRateLimited, !claim(line.code) { return }
        // The 4-argument overload carries the STREAM PAIRING handle (fix 2b) —
        // `nil` for every non-stream line, which behaves exactly as the
        // 3-argument form did. The id is a pairing key only: commonMain keeps it
        // in a field that is never rendered, uploaded or reported.
        ConnectionLog.shared.append(
            kind: line.kind.bridged,
            text: line.text,
            code: line.code.bridged,
            streamKey: line.streamKey.map { KotlinLong(value: $0) }
        )
    }

    /// True when [code] has not been emitted within the window (and stamps it).
    private func claim(_ code: TorLogCode) -> Bool {
        let now = ProcessInfo.processInfo.systemUptime
        lock.lock()
        defer { lock.unlock() }
        if let last = lastEmittedAt[code], now - last < TorControlEventTap.dedupeWindowSec {
            return false
        }
        lastEmittedAt[code] = now
        return true
    }

    /// Drops the de-dupe stamps. Called when Tor is torn down so a fresh run's
    /// first line of each kind is never swallowed by the previous run's.
    func reset() {
        lock.lock()
        lastEmittedAt.removeAll()
        lock.unlock()
    }
}

// ---------------------------------------------------------------------------
// Bridges to the commonMain vocabulary. Exhaustive switches (no `default:`) on
// purpose: adding a case to TorLogKind/TorLogCode without mapping it becomes a
// COMPILE error instead of an untagged line in the panel.
// ---------------------------------------------------------------------------

extension TorLogKind {
    var bridged: ConnectionLog.Kind {
        switch self {
        case .tor:    return .tor
        case .relay:  return .relay
        case .health: return .health
        case .stall:  return .stall
        case .system: return .system
        }
    }
}

extension TorLogCode {
    var bridged: ConnectionLog.Code {
        switch self {
        case .hsdescRequested:     return .hsdescRequested
        case .hsdescReceived:      return .hsdescReceived
        case .hsdescFailed:        return .hsdescFailed
        case .hsdescNotFound:      return .hsdescNotFound
        case .hsdescNoHsdir:       return .hsdescNoHsdir
        case .hsdescRateLimited:   return .hsdescRateLimited
        case .hsdescBadDesc:       return .hsdescBadDesc
        case .hsdescUnexpected:    return .hsdescUnexpected
        case .hsdirCircFailed:     return .hsdirCircFailed
        case .introCircLaunched:   return .introCircLaunched
        case .introCircBuilt:      return .introCircBuilt
        case .introSent:           return .introSent
        case .introDone:           return .introDone
        case .introCircFailed:     return .introCircFailed
        case .rendCircLaunched:    return .rendCircLaunched
        case .rendCircBuilt:       return .rendCircBuilt
        case .rendJoined:          return .rendJoined
        case .rendCircFailed:      return .rendCircFailed
        case .streamSent:          return .streamSent
        case .streamOk:            return .streamOk
        case .streamFailed:        return .streamFailed
        case .guardUp:             return .guardUp
        case .guardDown:           return .guardDown
        case .guardDropped:        return .guardDropped
        case .orconnLaunched:      return .orconnLaunched
        case .orconnConnected:     return .orconnConnected
        case .orconnFailed:        return .orconnFailed
        case .consensusFresh:      return .consensusFresh
        case .consensusStale:      return .consensusStale
        case .consensusUnknown:    return .consensusUnknown
        case .dirEnough:           return .dirEnough
        case .dirNotEnough:        return .dirNotEnough
        case .circuitOk:           return .circuitOk
        case .circuitLost:         return .circuitLost
        case .netUp:               return .netUp
        case .netDown:             return .netDown
        case .clockSkew:           return .clockSkew
        case .clockJumped:         return .clockJumped
        case .torBootstrapProblem: return .torBootstrapProblem
        }
    }
}

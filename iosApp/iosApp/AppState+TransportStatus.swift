import SwiftUI
import Combine
@preconcurrency import shared

// ---------------------------------------------------------------------------
// AppState+TransportStatus.swift — the transport half of AppState's published
// state: the mirrored Tor state, the external-proxy status, and the three
// bootstrap-stall hint tiers with the watchdog that raises them. AppState owns
// one instance ([AppState.transport]) and re-publishes its changes as its own
// (installChildForwarders), so views keep reading `appState.torState` etc.
// through the read-only forwarders at the bottom; a publisher subscriber uses
// `appState.transport.$torState` (a computed forwarder has no `$` projection).
// Named AppState+* on purpose: the androidApp source guards read AppState.swift +
// every AppState+*.swift together (SourceScan.kt `iosAppStateSources()`), so their
// whole-file scans (e.g. the log-redaction checks) keep covering this code.
// ---------------------------------------------------------------------------

@MainActor
final class TransportStatus: ObservableObject {
    // Tor connection state — drives runestone background crossfade.
    //
    // The phase-two ("Connecting to Relay…") percent used to be a time curve
    // anchored on the transition INTO .connected, so this property carried a
    // `didSet` that stamped/cleared `torConnectedAtUptime`. Both are gone: the
    // percent now comes from the shared BootstrapProgressPacer, which carries
    // its own clock and needs no anchor (and resets itself on a regression).
    // Writers: AppState only (the TorManager.$state sink, the ext-proxy verdicts,
    // the wipe, startTorOrDirect); views read the forwarder.
    @Published var torState: TorConnectionState = .disconnected

    /// EXTERNAL SOCKS PROXY MODE status for the connecting UI (`ext_proxy_status`).
    /// `.off` = the embedded Tor is this process's transport. Every other value
    /// means the embedded Tor is NOT running in this process (TorManager.start
    /// refuses — ExternalProxyMode.swift) and the relay transport is the user's
    /// proxy or nothing at all (fail closed).
    /// Writers: AppState's external-proxy path only (views read the forwarder).
    @Published var extProxyStatus: ExtProxyStatus = .off

    // PRE-CONNECT bootstrap stall (App Store review 2.1 on 0.8.159: "Add Contact"
    // spun on "Reaching the relay…" for 15+ minutes in Apple's review lab, where
    // Tor never bootstrapped and the relay saw zero requests). Set when Tor has
    // been starting for [torBootstrapStallSec] without reaching .connected, so the
    // UI can say something HONEST instead of an eternal spinner.
    //
    // Strictly INFORMATIONAL: tor_main runs ONCE per process, so nothing here may
    // stop or restart Tor. Bootstrap keeps running and may still succeed at minute
    // 4 — at which point AppState's $state sink clears this and AddContactView's
    // .onReceive(appState.transport.$torState) re-fires the mint on its own.
    //
    // Distinct from relayConnectPhase.stalled, which is the POST-connect
    // reachability hysteresis (24 misses on a WIRED transport). relayConnectPhase
    // .relaunchRequired outranks this everywhere: that latch clears it.
    @Published private(set) var torBootstrapStalled = false

    // TIER 1 of the escalation ladder: the in-session ACTIONABLE ceiling.
    //
    // [torBootstrapStalled] (Tier 0, 90 s) says "this network may be blocking the
    // private connection" and keeps waiting — honest, but it never ends. A
    // production user's Tor sat in exactly this state across relaunches until the
    // phone was rebooted, and nothing on screen ever escalated. After
    // [torBootstrapStalledLongSec] of continuous bootstrapping in THIS session the
    // copy becomes actionable instead: close and reopen Rún.
    //
    // Still strictly INFORMATIONAL, for the same reason Tier 0 is: tor_main runs
    // ONCE per process, so nothing here may stop or restart Tor — closing and
    // reopening the app is genuinely the only in-app lever, which is why the copy
    // reuses the wording pattern of the `.relaunchRequired` flow rather than
    // inventing a button that cannot work. Bootstrap keeps running underneath and
    // this retracts itself if it lands (the $state sink clears both tiers).
    //
    // Superset of Tier 0: whenever this is true, [torBootstrapStalled] is too, so
    // every surface can render one or the other from the same branch.
    @Published private(set) var torBootstrapStalledLong = false

    // TIER 2: cross-launch evidence, read once at Tor start from the Keychain
    // breadcrumb (TorManager / shared `TorBootstrapSelfHeal.shouldSuggestReboot`).
    // True after 3+ failed bootstrap sessions of ANY shape — deliberately not
    // gated on stuck-HIGH, because the incident this exists for stalled LOW and
    // was not resolvable by anything Tor-internal. Does not render on its own: it
    // APPENDS a "restart your iPhone" sentence to whichever stall hint (Tier 0 or
    // Tier 1) is already showing, on the same surfaces.
    @Published private(set) var torRebootHintWarranted = false

    // Mirrors Android TorManager.BOOTSTRAP_TIMEOUT_MS (90s) — the same budget the
    // Android side gives a bootstrap before it declares "No SOCKS port".
    private static let torBootstrapStallSec: TimeInterval = 90

    // Tier 1 ceiling. 240 s is deliberately far past Tier 0's 90 s: a cold Tor on
    // a slow mobile network legitimately takes minutes (the relay-stall
    // escalations upstream had to be backed off 100 s → 240 s for exactly this
    // reason), and telling a user to close the app while a working bootstrap is 20
    // seconds from finishing is worse than saying nothing.
    private static let torBootstrapStalledLongSec: TimeInterval = 240

    // Pre-connect bootstrap watchdog (App Store review 2.1, 0.8.159). Informational
    // ONLY — see torBootstrapStalled.
    private var torStallTask: Task<Void, Never>?

    /// TIER 2 read-back: copy TorManager's cross-launch breadcrumb verdict (it is
    /// computed by TorManager.start() before it returns). Copy only; nothing is
    /// gated on it.
    func refreshRebootHint() {
        torRebootHintWarranted = TorManager.shared.rebootHintWarranted
    }

    /// Arms the PRE-CONNECT bootstrap watchdog — BOTH tiers (see
    /// [torBootstrapStalled] at 90 s and [torBootstrapStalledLong] at 240 s), as a
    /// single sequential task so one cancel disarms the whole ladder.
    ///
    /// Idempotent and cancellation-safe by construction: it cancels any previous
    /// task before starting a new one, so repeated `startTorOrDirect()` calls
    /// (lock → re-unlock in the same process) can never stack watchdogs, and it
    /// re-arms from a clean `false` so a stale hint from the previous session
    /// cannot survive into this one.
    ///
    /// Readiness is read as CURRENT-VALUE state at wake time (`torState`,
    /// `relaunchRequired`) rather than captured at arm time — the same discipline
    /// the port/unlock wiring had to learn (see portCancellable): whichever of the
    /// two flips last still yields the correct decision, and a Tor that connected
    /// while we slept simply makes this a no-op even if the cancel raced us.
    ///
    /// NEVER stops or restarts Tor: tor_main runs once per process.
    ///
    /// RE-ANCHORED (speculative-start package, 2026-09-11): both delays are
    /// measured from when the BOOTSTRAP began, not from when this was armed — see
    /// [reanchoredDelaySec]. Tor now normally starts at launch, so by unlock it
    /// may already be 60 s into a stuck bootstrap; without this it would get a
    /// further full 90 s of silence (a 150 s stuck window). Android sibling:
    /// `RunViewModel.armTorBootstrapWatchdog` / `reanchoredDelayMs`.
    func armTorBootstrapWatchdog() {
        torStallTask?.cancel()
        torBootstrapStalled = false
        torBootstrapStalledLong = false
        let tier0 = TransportStatus.torBootstrapStallSec
        let tier1 = TransportStatus.torBootstrapStalledLongSec
        // Computed at ARM time (an elapsed bootstrap is a property of now, not of
        // wake time); the readiness checks below stay current-value reads.
        let elapsed = torBootstrapElapsedSec()
        let tier0Wait = reanchoredDelaySec(tier0, elapsed: elapsed)
        // Tier 1 sleeps the REMAINDER inside the same task, so it is re-anchored
        // the same way and floored so it can never wake before tier 0 has.
        let tier1Wait = max(tier1 - elapsed - tier0Wait, TransportStatus.minReanchoredWatchdogSec)
        torStallTask = Task { @MainActor [weak self] in
            try? await Task.sleep(nanoseconds: UInt64(tier0Wait * 1_000_000_000))
            guard !Task.isCancelled, let self else { return }
            // Current-value readiness — never a snapshot from arm time.
            guard self.torState != .connected else { return }
            // .relaunchRequired outranks: its own hint is already showing.
            guard !TorManager.shared.relaunchRequired else { return }
            LogBuffer.shared.append(level: "W", tag: "AppState",
                message: "Tor still bootstrapping \(Int(tier0))s into its bootstrap (waited \(Int(tier0Wait))s from arming) — surfacing the network-may-be-blocking hint (bootstrap continues)")
            // Live connection-log panel — Android sibling:
            // RunViewModel.armTorBootstrapWatchdog().
            ConnectionLog.shared.append(
                kind: ConnectionLog.Kind.stall,
                text: "Tor still bootstrapping after \(Int(tier0)) s - this network may be blocking it"
            )
            self.torBootstrapStalled = true

            // TIER 1: keep sleeping in the SAME task rather than arming a second
            // one, so a single cancel (connect / relaunch latch / wipe / re-unlock)
            // disarms the whole ladder — the property that made the original
            // watchdog cancellation-safe, preserved by construction.
            try? await Task.sleep(nanoseconds: UInt64(tier1Wait * 1_000_000_000))
            guard !Task.isCancelled else { return }
            // Re-read every readiness input at WAKE time, exactly as Tier 0 does:
            // a bootstrap that landed while we slept simply makes this a no-op even
            // if the cancel raced us, and the relaunch latch may have tripped in the
            // meantime (its own hint outranks this one).
            guard self.torState != .connected else { return }
            guard !TorManager.shared.relaunchRequired else { return }
            LogBuffer.shared.append(level: "W", tag: "AppState",
                message: "Tor still bootstrapping \(Int(tier1))s into its bootstrap (waited \(Int(tier0Wait + tier1Wait))s from arming) — escalating to the close-and-reopen hint (bootstrap continues)")
            self.torBootstrapStalledLong = true
        }
    }

    /// How long the CURRENT Tor bootstrap has already been running, for the two
    /// unlock-time watchdog tiers to subtract off.
    ///
    /// **Zero unless Tor is genuinely still pre-Connected, and that condition is
    /// the load-bearing half.** The only thing worth compensating for is a
    /// bootstrap that began before the vault opened and has NOT landed. Once Tor
    /// is Connected the head start has already paid off and whatever remains is
    /// about the RELAY handshake, which only begins when the transport is wired at
    /// unlock — subtracting a long but SUCCESSFUL bootstrap there would fire the
    /// hint onto a healthy session. Also zero when Tor never started, or was
    /// stopped (TorManager clears its anchor in stop()).
    ///
    /// Android sibling: `RunViewModel.torBootstrapElapsedMs`.
    private func torBootstrapElapsedSec() -> TimeInterval {
        if torState == .connected { return 0 }
        let startedAt = TorManager.shared.startedAtUptime
        guard startedAt > 0 else { return 0 }
        return max(0, ProcessInfo.processInfo.systemUptime - startedAt)
    }

    /// [full] minus [elapsed], floored at [minReanchoredWatchdogSec].
    ///
    /// Without this a slow credential typer gets one of two wrong answers: arm at
    /// unlock and a Tor 60 s into a stuck bootstrap waits another full window
    /// before anything is said; arm when the PIN screen appears and a HEALTHY
    /// bootstrap gets a scary hint rendered under the user mid-typing. Re-anchoring
    /// surfaces the honest hint ~30 s after unlock for the stuck one and leaves the
    /// healthy one alone. Android sibling: `RunViewModel.reanchoredDelayMs`.
    private func reanchoredDelaySec(_ full: TimeInterval, elapsed: TimeInterval) -> TimeInterval {
        max(full - elapsed, TransportStatus.minReanchoredWatchdogSec)
    }

    /// Floor for a re-anchored watchdog delay: even a bootstrap that is already
    /// past the full window gets a few seconds after unlock to land before the
    /// hint appears. Android sibling: `MIN_REANCHORED_WATCHDOG_MS` (5 s).
    private static let minReanchoredWatchdogSec: TimeInterval = 5

    /// Retracts the stall hint and disarms the watchdog. Safe to call at any time
    /// and from any of the three clearing sites (connected / relaunch latch /
    /// session teardown); a fresh unlock re-arms via `startTorOrDirect()`.
    func clearTorBootstrapStall() {
        torStallTask?.cancel()
        torStallTask = nil
        if torBootstrapStalled { torBootstrapStalled = false }
        // Tier 1 is a superset of Tier 0 — retract them together, or a surface
        // gated on the long hint alone could keep rendering "close and reopen"
        // after a bootstrap that finally landed.
        if torBootstrapStalledLong { torBootstrapStalledLong = false }
    }
}

extension AppState {
    // Read-only forwarders: every view call site stays `appState.X`. Writers go
    // through `transport.X` (AppState only).
    var torState: TorConnectionState { transport.torState }
    var extProxyStatus: ExtProxyStatus { transport.extProxyStatus }
    var torBootstrapStalled: Bool { transport.torBootstrapStalled }
    var torBootstrapStalledLong: Bool { transport.torBootstrapStalledLong }
    var torRebootHintWarranted: Bool { transport.torRebootHintWarranted }
}

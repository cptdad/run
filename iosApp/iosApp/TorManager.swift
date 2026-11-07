import Foundation
import UIKit
import shared
// The Tor.framework Objective-C classes (TorController / TorThread /
// TorConfiguration, iCepa Tor 0.4.9.14, vendored from source) are exposed to
// Swift via Run-Bridging-Header.h — there is no `import Tor` module anymore.

// ---------------------------------------------------------------------------
// TorManager — manages the embedded Tor daemon lifecycle on iOS.
//
// Uses the exact same initialization pattern as SwiftTor's TorHelper,
// which is proven to work with this Tor.xcframework.
// ---------------------------------------------------------------------------

#if DEBUG
import os.log
private let torLogger = Logger(subsystem: "com.vg.run", category: "Tor")
#endif

private func torLog(_ message: String) {
    #if DEBUG
    // DEBUG ONLY: the unified system log is on-disk, persistent, OUTSIDE the app
    // sandbox, and survives emergencyWipe() — so Tor metadata (ports, dir/
    // control-socket paths, bootstrap progress) must never be emitted there in
    // release builds. Default privacy (not .public) so
    // even DEBUG output redacts interpolated dynamic values.
    torLogger.info("\(message)")
    #endif
    // In-app log viewer buffer only: kill-switch + DEBUG gated (LoggingState),
    // in-memory, and cleared by emergencyWipe().
    LogBuffer.shared.append(level: "D", tag: "Tor", message: message)
}

/// DEBUG-only, os_log-only sibling of torLog: NEVER reaches LogBuffer, so it is
/// never uploaded by Debug mode. For raw Tor event arguments (SKEW=, SOURCE=,
/// SUMMARY prose ...) that can carry per-device quasi-identifiers or addresses.
private func torLogLocal(_ message: String) {
    #if DEBUG
    torLogger.info("\(message)")
    #endif
}

/// Carries a non-Sendable Objective-C object into one of Tor's own reply blocks
/// (which the ObjC importer marks `@Sendable`). Every use must justify itself at
/// the call site — see armControlEventTap.
private struct UncheckedBox<T>: @unchecked Sendable {
    let value: T
    init(_ value: T) { self.value = value }
}

// ---------------------------------------------------------------------------
// TorBootstrapBreadcrumbStore — the persistence half of the stuck-bootstrap
// self-heal. The DECISIONS all live in commonMain (`TorBootstrapSelfHeal`,
// shared/src/commonMain/kotlin/com/vg/run/TorBootstrapSelfHeal.kt) so the policy
// that can delete a user's entry guards is unit-tested; this type only reads and
// writes it.
//
// Storage: the KEYCHAIN, in KeychainHelper's dedicated diagnostic service
// ("com.vg.run.diag") under kSecAttrAccessibleWhenUnlockedThisDeviceOnly.
// Explicitly NOT UserDefaults — a plist is AFU-readable and container-writable,
// i.e. a WEAKER class than the <Caches>/tor evidence this record summarises, and
// this record can authorise deleting that directory. Explicitly NOT inside
// <Caches>/tor either: every fast-terminal Tor failure wipes that dir on failure
// #1, so a counter living there could never survive its own trigger.
//
// Day-granularity timestamps only (see TorBootstrapSelfHeal.serialize) — this
// record lives outside the vault by construction, so it must not carry a precise
// "when did you last use Rún" time.
//
// @MainActor: both call sites (TorManager, AppState) are main-actor isolated, so
// the process-lifetime suppression latch below needs no synchronisation — the
// same discipline as TorManager.exitWipeArmed.
// ---------------------------------------------------------------------------
@MainActor
enum TorBootstrapBreadcrumbStore {

    /// Keychain account name inside the diagnostic service. Versioned so a future
    /// format change can land as a new account rather than a legacy read path.
    static let account = "tor_bootstrap_v1"

    /// Process-lifetime "a wipe has happened / is happening" latch. Set by every
    /// wipe path (AppState.emergencyWipe's crypto-erase block and
    /// clearWipeResidue) BEFORE Tor is torn down, so the teardown that follows
    /// cannot re-plant a breadcrumb after the erase — the "NO write after erase"
    /// rule, which exists because post-erase writes re-create residue. Pure RAM,
    /// no I/O, so setting it cannot gate or delay the crypto-erase.
    private static var suppressed = false

    static func suppressForWipe() { suppressed = true }

    /// Reads the record; any absent / unreadable / malformed value fails safe to
    /// the inert EMPTY record (no discard, no reboot hint).
    static func load() -> BootstrapBreadcrumb {
        guard !suppressed else { return TorBootstrapSelfHeal.shared.EMPTY }
        return TorBootstrapSelfHeal.shared.parseOrEmpty(
            raw: KeychainHelper.shared.diagGet(key: account)
        )
    }

    static func save(_ b: BootstrapBreadcrumb) {
        guard !suppressed else { return }
        KeychainHelper.shared.diagPut(
            key: account,
            value: TorBootstrapSelfHeal.shared.serialize(b: b)
        )
    }

    /// Wipe-path erase. Belt to KeychainHelper.kvDeleteAll()'s sweep of the whole
    /// diagnostic service (which every production AND e2e wipe already calls) —
    /// see AppState.clearWipeResidue().
    static func erase() {
        KeychainHelper.shared.diagRemove(key: account)
    }

    /// Whole days since the Unix epoch. Day granularity is the forensic-residue
    /// constraint, not a rounding convenience.
    static func todayEpochDay() -> Int64 {
        Int64((Date().timeIntervalSince1970 / 86_400).rounded(.down))
    }
}

@MainActor
final class TorManager: ObservableObject {

    static let shared = TorManager()

    /// Tor lifecycle as AppState sees it ([state]). Android sibling: TorManager.kt's table.
    ///
    /// | From                  | To                         | Where                                                   |
    /// |-----------------------|----------------------------|---------------------------------------------------------|
    /// | disconnected          | bootstrapping(0)           | start(), past BOTH guards (once per process)            |
    /// | any (second start)    | disconnected + latch       | start() refused: threadEverCreated (tor_main ran once)  |
    /// | bootstrapping(n)      | bootstrapping(m)           | registerBootstrapObservers (STATUS_CLIENT BOOTSTRAP); m may be < n |
    /// | bootstrapping         | connected                  | readBackSocksPort success — the ONLY publisher: socksPort set, then startRelayAddressRace(), then .connected (triggered by the circuit-established callback) |
    /// | bootstrapping         | disconnected + latch       | readBackSocksPort failure / control channel down → stop(discardingState: true) |
    /// | any                   | disconnected (+ latch if Tor ever ran) | stop(discardingState:); socksPort = 0     |
    /// | any                   | disconnected + latch       | markThreadDead() (OS killed tor_main); socksPort = 0    |
    ///
    /// "latch" = [relaunchRequired] (noteRelaunchRequired, one-way per process). There is no
    /// `failed` case: terminal failure is `.disconnected` + the latch (see TorConnectionState).
    /// [socksPort] is published only by readBackSocksPort (before `.connected`) and zeroed
    /// with every `.disconnected` that ends a run; a later guard-channel / network-restore
    /// kick moves the listener without republishing (consumers resolve the live port)
    /// (to be confirmed by the Tor specialist).
    @Published private(set) var state: TorConnectionState = .disconnected
    @Published private(set) var socksPort: UInt16 = 0
    // Latched true the moment this PROCESS can never again produce a working
    // Tor: the once-per-process tor_main thread died (background suspend kill),
    // failed terminally (control connect / auth / port readback), or was
    // stop()ped (emergency wipe). NEWNYM and the manual Reconnect are useless
    // in every one of these states — the only recovery is a fresh process.
    // Consumers: ContentView exits the process on the next `.background` (an
    // invisible self-relaunch, replacing the manual force-quit users would
    // otherwise need to discover — and, unlike a healthy Tor, a latched one is
    // never kept alive: BackgroundTorKeepAlive's gate refuses it), and the
    // contact list swaps "Connecting…" for an honest close-and-reopen hint while
    // the app is still visible.
    @Published private(set) var relaunchRequired = false

    /// `ProcessInfo.systemUptime` at the moment THIS process's Tor bootstrap
    /// actually began (the instant [start] passed its guards), or 0 if Tor has
    /// never started / has been stopped.
    ///
    /// Exists for one reason originally: the speculative (launch-time) start
    /// means the bootstrap now usually begins well BEFORE the vault opens, so
    /// the unlock-time watchdogs must measure from here rather than from when
    /// they were armed — otherwise a Tor 60 s into a STUCK bootstrap would get
    /// another full 90 s of silence after unlock. See
    /// `TransportStatus.reanchoredDelaySec` (AppState+TransportStatus.swift). Also read by `AppState.checkRelayReachability`
    /// as the anchor for the `boot` telemetry field (2026-09-11), since it is
    /// exactly "this session's Tor process start" and never moves across a
    /// restart — `tor_main` runs at most once per process, so a stop() after a
    /// real start always latches `relaunchRequired` (see [stop]). A SECOND
    /// session in the same process (a warm return inside the bounded keep-alive
    /// window) reports too, but started no Tor, so AppState OMITS `boot` for it
    /// rather than measuring from this first-session anchor. Android sibling:
    /// `TorManager.startedAtElapsedMs` (read by `RunViewModel.torBootstrapElapsedMs`
    /// and `RunViewModel.torProcessStartedAtElapsedMs`).
    ///
    /// Boot-relative and monotonic (same clock as `AppState.connectStartUptime`),
    /// so a wall-clock step cannot distort it. Never an identifier: a single
    /// process-local uptime reading, cleared on [stop].
    private(set) var startedAtUptime: TimeInterval = 0

    private var thread: TorThread?
    private var controller: TorController?
    private var progressObserver: Any?
    private var circuitObserver: Any?
    private var started = false
    // One-shot guard for the FIRST connectControlChannel() of this Tor run (P4b). The
    // control-socket poll and its hard timeout fallback both route through
    // fireControllerConnect(), and connectControlChannel() owns its own retry
    // scheduling from there — so it must be ENTERED exactly once.
    private var controllerConnectTriggered = false
    // Process-lifetime latch: a TORThread (tor_main) may be created ONLY ONCE
    // per process. Tor's global C state is not reset by TORThread.cancel(), so a
    // second TorThread(configuration:) aborts with an Objective-C NSAssertion
    // (seen in the wild as the `Tor 0x… + 77052` / NO_CRASH_STACK crashes, chain
    // TORThread.init ← TorManager.start ← startTorOrDirect). stop() resets
    // `started`, but NEVER this — so a post-stop() start() can't recreate it.
    private var threadEverCreated = false

    // MARK: - Stuck-bootstrap self-heal (cross-launch evidence)
    //
    // A production user's Tor never connected across several relaunches and only
    // an iPhone reboot fixed it: none of the four terminal branches below can fire
    // for a daemon that authenticates and then sits at N% forever (they are all
    // fast-early failures, and forCircuitEstablished has no timeout). These fields
    // are the per-run evidence that gets folded into the persisted breadcrumb at
    // teardown. Decisions: TorBootstrapSelfHeal (commonMain).

    /// The breadcrumb as read at [start]. Mutated in RAM by every record, written
    /// back at most once per process (see the write points).
    private var breadcrumb: BootstrapBreadcrumb = TorBootstrapSelfHeal.shared.EMPTY
    /// [start] ran far enough to begin an attempt this process. Without it a
    /// stop() on a process that never started Tor would score a phantom attempt.
    private var bootstrapAttemptStarted = false
    /// One-shot: the attempt has been scored (success or failure). Keeps the
    /// budget at "one read at start, at most one write per process" and stops a
    /// markThreadDead-then-stop() pair from double-counting.
    private var bootstrapAttemptSettled = false
    /// Tor reached `.connected` at least once in this process.
    private var reachedConnected = false
    /// Highest bootstrap percent seen this run — the SHAPE gate. Stuck-HIGH
    /// (guards/circuits) is repairable by a state discard; stuck-LOW is not.
    private var highestBootstrapPercent = 0

    /// FOREGROUND dwell in `.bootstrapping`, in two parts: whole closed segments
    /// plus the currently open one. Foreground, not wall time — iOS suspends the
    /// process in the background where Tor makes no progress and the user sees
    /// nothing, so counting it would let a phone that sat in a pocket overnight
    /// score a "the user waited a minute" failure. Segments are closed on
    /// didEnterBackground and reopened on willEnterForeground.
    private var dwellAccumulatedSec: TimeInterval = 0
    private var dwellSegmentStart: Date?
    /// One-shot registration of the two lifecycle observers (done lazily from
    /// [start], never from init — `TorManager.shared` is not constructed yet there).
    private var dwellObserversRegistered = false

    /// Published so the UI can add the Tier-2 "restart your iPhone" sentence to
    /// the existing stall copy. Computed ONCE at [start], from the breadcrumb as
    /// READ (i.e. before a discard resets the streak) — the user really has had
    /// that many failed sessions, and a discard is not proof the next one works.
    /// Shape-independent by design: the production incident stalled LOW, where no
    /// Tor-internal recovery exists.
    @Published private(set) var rebootHintWarranted = false

    private init() {}

    // MARK: - Public API

    func start() {
        // EXTERNAL SOCKS PROXY MODE (ExternalProxyMode.swift): the embedded Tor
        // may start ONLY on a positive, process-frozen "no external proxy set"
        // decision. External mode (valid or invalid) and an UNREADABLE setting
        // both refuse — before `started`, `threadEverCreated`, the anchor or any
        // log/ConnectionLog line, so nothing below (tor_main, the control
        // socket, the raw-event tap, HSFETCH, NEWNYM, the stall kick) can ever
        // exist in such a process. Not latched as relaunchRequired: nothing died.
        guard ExternalProxyMode.shared.mayStartEmbeddedTor() else {
            torLog("start() refused — external proxy mode (or setting unreadable); embedded Tor not started")
            return
        }
        guard !started else {
            torLog("start() called but already started — skipping")
            return
        }
        // Tor can be initialized only once per process (see threadEverCreated).
        // If iOS killed the embedded Tor thread during a background suspend, it
        // CANNOT be restarted in-process — the only recovery is an app relaunch.
        // Refuse a second init and stay disconnected rather than aborting the
        // whole process with an NSAssertion.
        guard !threadEverCreated else {
            torLog("start() refused — Tor already ran in this process; cannot re-init in-process (relaunch required)")
            state = .disconnected
            noteRelaunchRequired()
            return
        }
        started = true
        // Anchor for the unlock-time watchdog re-anchoring (see startedAtUptime).
        // Set here, past both guards, so a refused/skipped start never moves it.
        startedAtUptime = ProcessInfo.processInfo.systemUptime
        state = .bootstrapping(progress: 0)
        torLog("start() — beginning Tor initialization")
        ConnectionLog.shared.append(
            kind: ConnectionLog.Kind.system,
            text: "Tor starting",
            code: ConnectionLog.Code.torStart
        )

        let torDir = TorManager.workingDirPath()

        // Stuck-bootstrap self-heal, evaluated from CROSS-LAUNCH evidence only and
        // BEFORE the thread starts (and before purgeSessionEphemera below), which
        // is the only point in the process where the working dir can be deleted
        // with no tor_main alive to race it. Never driven by the in-session
        // watchdog: an in-session discard would have to fight a live, un-killable
        // daemon and could not retry anyway (tor_main runs once per process).
        // It targets the same `workingDirPath()` this start() is about to (re)create.
        beginBootstrapAttempt()

        // Working-dir prep (preserve/simulator wipe, mkdir, data protection,
        // per-session purge, fresh onion_auth dir) — see prepareWorkingDir.
        let authPath = prepareWorkingDir(torDir)

        // torrc file + TorConfiguration from the ONE option list (torrcOptions).
        let (config, controlSocketURL) = TorManager.makeTorConfiguration(torDir: torDir, authPath: authPath)

        torLog("torDir=\(torDir) socksPort=auto (read back from control port once bootstrapped)")
        torLog("controlSocket=\(controlSocketURL.path)")

        // NOTE: the Tor daemon-log callback is installed AFTER the control
        // channel authenticates (see connectControlChannel), never here: the
        // vendored TORInstallTorLoggingCallback calls Tor's add_callback_log
        // directly, which asserts the log mutex that only init_logging() inside
        // tor_main creates — calling it before the thread runs is a SIGABRT at
        // every launch (crash report 2026-09-14, all three test iPhones).

        // Create controller BEFORE starting thread (SwiftTor pattern)
        controller = TorController(socketURL: controlSocketURL)
        torLog("TorController created")

        // Start Tor thread. Latch BEFORE creating it: tor_main runs once per
        // process and a second TorThread(configuration:) aborts the process.
        threadEverCreated = true
        thread = TorThread(configuration: config)
        thread?.start()
        torLog("Tor thread started, polling for the control socket before connecting...")

        // P4b: connect the controller as soon as Tor's control socket EXISTS, instead
        // of the old unconditional 1.0s sleep (inherited from SwiftTor, never
        // explained). purgeSessionEphemera() above just deleted `cp`, on BOTH the
        // preserving and the wiping path, so the file reappearing can only mean THIS
        // daemon bound it — a stale socket cannot shortcut the poll.
        //
        // The 1.0s ceiling is a HARD FALLBACK and is LOAD-BEARING: connectControlChannel()
        // owns the two terminal branches (connect-attempt exhaustion, cookie-unreadable
        // exhaustion) that latch relaunchRequired and hand the process to the
        // self-recovery recycle. A poll that just gave up when the socket never appeared
        // would silently lose that guarantee and strand the UI at bootstrapping(0)
        // forever — so at the ceiling we connect unconditionally, socket or not, and let
        // connectControlChannel()'s own bounded retries reach the terminal state.
        //
        // Connecting EARLIER is safe only because those retries absorb the prematurity:
        // a socket that is not accepting yet retries 20 x 1.0s, and a cookie that is
        // absent OR still short (P4a below) retries 20 x 0.5s. P4a and P4b are one
        // change for that reason.
        controllerConnectTriggered = false
        awaitControlSocketThenConnect(
            socketPath: controlSocketURL.path,
            deadline: Date().addingTimeInterval(TorManager.controlSocketPollCeilingSec)
        )
    }

    /// The working-dir preparation of `start()`, in its original order. Returns the
    /// onion-auth dir path (`<torDir>/onion_auth`, freshly emptied).
    private func prepareWorkingDir(_ torDir: String) -> String {
        // The working dir is PRESERVED across launches (see
        // `preservesStateAcrossLaunches`) so Tor reuses its entry guards and its
        // cached consensus/descriptors instead of re-sampling guards and paying a
        // full cold descriptor fetch on every relaunch. Only the two strictly
        // per-session files are cleared, below.
        //
        // On the SIMULATOR the path is pid-suffixed (`/tmp/rt-<pid>`), so it can
        // never be reused anyway — wipe it there so repeated runs don't litter
        // the host's /tmp.
        if !TorManager.preservesStateAcrossLaunches {
            try? FileManager.default.removeItem(atPath: torDir)
        }

        // Create tor data directory
        try? FileManager.default.createDirectory(
            atPath: torDir,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        // Now that the state OUTLIVES the session, harden it: NSFileProtection
        // Complete + backup exclusion, exactly as IosVaultDatabase does for the
        // vault files. Applied to the DIRECTORY before Tor writes anything (new
        // files inherit their directory's protection class) and again over the
        // contents on teardown.
        //
        // What makes Complete safe here is DEVICE unlock, not VAULT unlock. Since
        // the speculative launch-time start (connect-speed lever 2, 2026-09-11)
        // this is reached BEFORE the vault opens — but never before protected data
        // is available: `AppState.startSpeculativeTor` is gated on
        // `UIApplication.shared.isProtectedDataAvailable` (and on the app being
        // ACTIVE, which a device-locked process is not), exactly as the launch
        // security checks are. Since the bounded keep-alive (2026-10-23) a
        // healthy Tor may outlive `.background` by the background-task budget,
        // but AppState ends that window the moment
        // `protectedDataWillBecomeUnavailable` fires (device lock) — still
        // before the Class-A keys are evicted ~10 s later — so Tor never needs
        // this dir while the DEVICE is locked. See `applyDataProtection`.
        TorManager.applyDataProtection(to: torDir)
        // The two per-session files that must NOT be inherited from the previous
        // run (see purgeSessionEphemera) — the auth cookie above all.
        TorManager.purgeSessionEphemera(in: torDir)

        // Create auth directory
        let authPath = "\(torDir)/onion_auth"
        try? FileManager.default.createDirectory(
            atPath: authPath,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )

        // Clear old auth keys
        if let files = try? FileManager.default.contentsOfDirectory(atPath: authPath) {
            for f in files {
                try? FileManager.default.removeItem(atPath: "\(authPath)/\(f)")
            }
        }
        return authPath
    }

    /// The ONE torrc option list, in file order. `makeTorConfiguration` renders it
    /// both into the `.torrc` file (one `Key Value` line per entry) and into
    /// `TorConfiguration.options`, so the two can no longer drift apart.
    /// Passing the options via `TorConfiguration.options` alone does not seem to
    /// reach Tor's argv in the bundled Tor.xcframework on the iOS simulator, so
    /// everything important is ALSO written to the torrc file.
    ///
    /// torrc rendering verified identical to the pre-fold literal (non-comment
    /// lines, same order, same separators, no trailing newline); only the `#`
    /// comment lines Tor ignores moved into the Swift comments below.
    ///
    /// DIRECTORY BOOTSTRAP: no fallback-dir override. Tor's compiled-in 200-entry
    /// list is used, as on Android. The `UseDefaultFallbackDirs 0` + pinned
    /// `FallbackDir` override existed for a static-link symbol collision
    /// (SQLCipher's libtomcrypt vs Tor's flat C names) that shipping Tor as a
    /// dynamic framework fixed (378c6213); the compiled-in list was re-verified
    /// intact on 2026-09-15. History: iosApp/SwiftTor-VERIFICATION.md + git log.
    ///
    /// Do NOT reintroduce the override without re-testing a cold start: if Tor
    /// is ever linked STATICALLY into the app again, the collision — and the
    /// crash — comes back, and disabling fallbacks only hides it until Tor
    /// base16-decodes the directory authorities a moment later.
    private static func torrcOptions(authPath: String) -> [(String, String)] {
        // 9 of these 13 options are shared with Android's TorrcWriter.buildTorrc
        // (SocksPort auto, AvoidDiskWrites, SafeSocks, SafeLogging,
        // LearnCircuitBuildTimeout 0, CircuitBuildTimeout 45, NumEntryGuards 8,
        // ClientUseIPv6, ClientPreferIPv6ORPort auto) — keep those in lockstep.
        // iOS-only: ClientOnionAuthDir, LongLivedPorts, NumCPUs, DisableDebuggerAttachment.
        [
            // `SocksPort auto` — Tor binds an OS-assigned free
            // port on 127.0.0.1 and we read the real port back from the control port
            // (net/listeners/socks) once bootstrapped. Parity with Android's
            // "SocksPort auto". A fixed, well-known port (the old 19050) was trivially
            // pre-bound — or, after iOS silently kills the embedded Tor thread on a
            // long background suspend, re-bound — by a malicious co-installed app that
            // the liveness probe would then accept as "Tor is up", leaking relay
            // capability tokens to a local squatter. An unpredictable OS-assigned port
            // removes that predictable target.
            ("SocksPort", "auto"), // = Android
            ("AvoidDiskWrites", "1"), // = Android
            ("ClientOnionAuthDir", authPath), // iOS-only
            // Mobile reliability: the ADAPTIVE circuit-build timeout (default,
            // LearnCircuitBuildTimeout 1) learns from fast circuits on a variable
            // mobile network and then prematurely KILLS slower-but-valid circuits —
            // intermittently breaking fresh streams to the .onion (GET health check
            // goes unlit / POST mint "can't reach the relay") even though the
            // transport + relay are fine. Adaptive CBT stays OFF; use a FIXED timeout.
            //
            // 45 s, lowered from 90 s (connect-speed lever 3, 2026-09-11). WHY 45:
            // this app's 20 s health budget rotates STREAMS, not circuits, and a
            // stream pending on a dead intro point / rendezvous path inherits its
            // circuit's fate — so until Tor abandons the circuit the client is stuck,
            // for up to the full CBT. 45 s halves that tail. It costs nothing on the
            // happy path (a healthy mobile onion circuit builds in ~10-15 s) and
            // changes no path selection. Never go below 30 s: that is where
            // slow-but-valid circuits start dying, the exact failure
            // LearnCircuitBuildTimeout 0 exists to prevent. Keep in lockstep with
            // Android's TorManager.buildTorrc.
            ("LearnCircuitBuildTimeout", "0"),
            ("CircuitBuildTimeout", "45"),
            // NumEntryGuards 8 is a KNOWING reliability
            // decision (~3x guard exposure) — removed once, reinstated the same day
            // after cross:multi3 failed 4/4 with the slow-guard signature it cures.
            // See TorManager.kt buildTorrc kdoc. Keep in lockstep with Android.
            ("NumEntryGuards", "8"),
            ("SafeSocks", "1"), // = Android
            ("LongLivedPorts", "80,443"), // iOS-only
            ("NumCPUs", "2"), // iOS-only
            ("DisableDebuggerAttachment", "1"), // iOS-only
            ("SafeLogging", "1"), // = Android
            // Guideline 2.1 (App Store review rejection, v0.8.159): "Add Contact"
            // loaded indefinitely because Tor never finished bootstrapping in
            // Apple's review lab. Prod relay logs proved the review devices never
            // reached the relay at all. Apple's review networks (and plenty of
            // enterprise Wi-Fi) are frequently IPv6-only NAT64: IPv4 literal dials
            // — which is all Tor does by default, since ClientUseIPv6 defaults to
            // 0 — cannot be translated on such networks, so bootstrap stalls at
            // 0-25% forever. ClientUseIPv6 lets Tor also dial the IPv6 ORPorts
            // that the directory authorities and many of Tor's compiled-in fallback
            // directory mirrors advertise (their `ipv6=` addresses);
            // ClientPreferIPv6ORPort auto lets Tor pick whichever family actually
            // works instead of always trying IPv4 first, which is what would still
            // stall on an IPv6-only network. Both are safe on dual-stack/IPv4-only
            // networks too — "auto" only prefers IPv6 when it looks reachable.
            ("ClientUseIPv6", "1"), // = Android
            ("ClientPreferIPv6ORPort", "auto"), // = Android
            // NOTE: no "UseDefaultFallbackDirs" entry — Tor's stock compiled-in
            // fallback list is used, same as Android (history in the doc comment above).
        ]
    }

    /// Writes the `.torrc` and builds the `TorConfiguration` for `start()`, both
    /// from `torrcOptions(authPath:)`. Returns the configuration and the
    /// control-socket URL. Bind that URL ONCE: the TorController is constructed
    /// with it, and the P4b appearance poll watches this exact same path — never a
    /// hardcoded one, so the simulator's pid-suffixed /tmp working dir (see
    /// workingDirPath()) keeps working unchanged. Built from torDir (the same URL
    /// dataDirectory is set to), so no optional to unwrap.
    private static func makeTorConfiguration(torDir: String, authPath: String) -> (TorConfiguration, URL) {
        let options = torrcOptions(authPath: authPath)
        let torrc = options.map { "\($0.0) \($0.1)" }.joined(separator: "\n")
        FileManager.default.createFile(
            atPath: "\(torDir)/.torrc",
            contents: torrc.data(using: .utf8),
            attributes: [.posixPermissions: 0o600]
        )

        // Configure — EXACT same pattern as SwiftTor's TorHelper
        let config = TorConfiguration()
        // `options` imports as NSMutableDictionary (TORConfiguration.h), so a Swift
        // Dictionary must be wrapped explicitly; the old literal converted implicitly.
        config.options = NSMutableDictionary(dictionary: Dictionary(uniqueKeysWithValues: options))
        config.cookieAuthentication = true
        config.dataDirectory = URL(fileURLWithPath: torDir)
        config.arguments = ["-f", "\(torDir)/.torrc"]
        let controlSocketURL = URL(fileURLWithPath: torDir).appendingPathComponent("cp")
        config.controlSocket = controlSocketURL
        return (config, controlSocketURL)
    }

    // MARK: - Tor's own daemon log

    /// One-shot guard: `add_callback_log` (inside TORInstallTorLoggingCallback)
    /// APPENDS a log target, so a second install would double every line.
    private static var torDaemonLogInstalled = false

    /// Routes Tor's own log lines (`NOTICE` and worse) into the existing in-app
    /// [LogBuffer]. Until now they went to Tor's default stdout target, which on
    /// an iOS device goes nowhere at all — so a daemon that said exactly why it
    /// was stuck said it into the void.
    ///
    /// THREE GATES, deliberately:
    ///  1. `#if DEBUG` — the whole install. This is now a PRIVACY CONTROL, not a
    ///     cost optimisation: the old rationale ("LoggingState is only ever
    ///     flipped on in DEBUG") no longer holds — user-consented Debug mode can
    ///     flip `LoggingState` on in a RELEASE build too, and Tor's raw daemon
    ///     stream carries content [TorLogRedaction] does not handle, namely relay
    ///     NICKNAMES and NOTICE-line LOCAL-time timestamps (vs. this buffer's UTC
    ///     prefix elsewhere, which would leak the device's timezone). Removing
    ///     this gate requires adding nickname + local-time redaction to
    ///     [TorLogRedaction] FIRST — do not remove it to "just get more detail"
    ///     without that.
    ///  2. `LoggingState.enabled` — the same kill switch every other LogBuffer
    ///     write has, checked FIRST so a disabled buffer costs one boolean read.
    ///  3. Severity — the vendored installer registers the callback at DEBUG
    ///     severity (not ours to change), and Tor's debug stream is a firehose.
    ///
    /// These lines are Tor's, not ours, so unlike every ConnectionLog producer
    /// they are not fixed phrases by construction: `SafeLogging 1` scrubs the
    /// sensitive ones daemon-side and [TorLogRedaction] is the second line of
    /// defence. They go to the DEBUG-gated buffer ONLY — never to ConnectionLog
    /// (which is live in release builds) and never to the unified system log
    /// (on-disk, outside the sandbox, survives the panic wipe).
    private static func installTorDaemonLogCallback() {
        #if DEBUG
        guard !torDaemonLogInstalled else { return }
        torDaemonLogInstalled = true
        // Non-capturing: it is converted to a C function pointer and called from
        // Tor's own threads.
        TORInstallTorLoggingCallback { severity, msg in
            guard LoggingState.shared.enabled else { return }
            guard severity != OSLogType.debug else { return }
            let level: String
            switch severity {
            case OSLogType.fault: level = "E"   // Tor LOG_ERR
            case OSLogType.error: level = "W"   // Tor LOG_WARN
            default:              level = "D"   // Tor LOG_NOTICE / LOG_INFO
            }
            LogBuffer.shared.append(
                level: level,
                tag: "TorD",
                message: TorLogRedaction.redact(String(cString: msg))
            )
        }
        #endif
    }

    // MARK: - Stuck-bootstrap self-heal

    /// Reads the cross-launch breadcrumb, arms the Tier-2 reboot hint, runs the
    /// one-shot state discard when [TorBootstrapSelfHeal.shouldDiscardTorState]
    /// says so, and starts this run's foreground-dwell clock.
    ///
    /// The discard EXTENDS an already-accepted behaviour rather than inventing
    /// one: the four terminal branches in connectControlChannel()/observeProgress()
    /// have always ended in `stop(discardingState: true)`, which deletes exactly
    /// this directory. All this adds is a fifth failure class — the one that is
    /// never terminal, because Tor's forCircuitEstablished observer has no
    /// timeout — under three gates that bound the anonymity cost of re-sampling
    /// entry guards (N-strikes, stuck-HIGH shape, a wall-clock floor). See the
    /// ANONYMITY RATIONALE in TorBootstrapSelfHeal.
    private func beginBootstrapAttempt() {
        registerDwellObserversIfNeeded()

        let loaded = TorBootstrapBreadcrumbStore.load()
        breadcrumb = loaded
        bootstrapAttemptStarted = true
        bootstrapAttemptSettled = false
        reachedConnected = false
        highestBootstrapPercent = 0
        dwellAccumulatedSec = 0
        // start() is only ever reached from AppState.startTorOrDirect, i.e. from a
        // just-unlocked, foreground app — so the first dwell segment opens here.
        dwellSegmentStart = Date()

        // Computed from the value AS READ, before the discard below resets the
        // streak. Copy only; changes no state.
        rebootHintWarranted = TorBootstrapSelfHeal.shared.shouldSuggestReboot(
            consecutiveFailures: loaded.consecutiveFailures
        )

        let today = TorBootstrapBreadcrumbStore.todayEpochDay()
        guard TorBootstrapSelfHeal.shared.shouldDiscardTorState(b: loaded, todayEpochDay: today) else {
            torLog("bootstrap self-heal: keeping Tor state (failures=\(loaded.consecutiveFailures), lastStuck=\(loaded.lastStuckPercent)%, rebootHint=\(rebootHintWarranted))")
            return
        }
        // DEBUG-only surfacing (torLog is #if DEBUG for the system log and
        // LoggingState-gated for the in-app buffer) — no new production logging.
        torLog("bootstrap self-heal: DISCARDING Tor state after \(loaded.consecutiveFailures) stuck-high failures (lastStuck=\(loaded.lastStuckPercent)%) — cold bootstrap, entry guards re-sampled")
        // `confirming: nil` — the eager single-pass delete only. The confirm-wait
        // exists to outlive a still-terminating tor_main; there is none here (we
        // are ahead of this process's one and only TorThread, and the previous
        // process is long gone), so blocking the main actor for it would be pure
        // cost. armExitWipe() is deliberately NOT armed: that atexit hook deletes
        // the working dir at process exit, which would destroy the very state this
        // cold bootstrap is about to rebuild for the next launch.
        wipeWorkingDirectory(confirming: nil)
        // Stamp the wall-clock floor and clear the streak in the SAME write, so
        // the discard immediately disarms itself: the next launches get a fresh
        // budget to prove whether it helped, and no launch can loop on it.
        let updated = TorBootstrapSelfHeal.shared.recordDiscard(b: loaded, todayEpochDay: today)
        breadcrumb = updated
        TorBootstrapBreadcrumbStore.save(updated)
    }

    /// Folds this run into the persisted breadcrumb. One-shot per process, so the
    /// markThreadDead → stop() pair (and a double stop()) can only score once.
    ///
    /// Called from every teardown: the ordinary background stop(), the terminal
    /// `stop(discardingState: true)` branches, and markThreadDead. A process that
    /// is force-quit or jetsammed never reaches here and therefore records
    /// NOTHING — deliberately conservative: it can only ever under-count, never
    /// invent a failure.
    private func settleBootstrapAttempt(reason: String) {
        guard bootstrapAttemptStarted, !bootstrapAttemptSettled else { return }
        bootstrapAttemptSettled = true
        closeDwellSegment()
        // Clamped before the Int32 narrowing: a Double→Int32 conversion TRAPS on
        // overflow, and this value comes from wall-clock arithmetic (a clock jump
        // mid-session could otherwise make a teardown crash the app). The upper
        // bound is a day; anything past the 60 s floor scores identically anyway.
        let dwell = Int32(min(max(dwellAccumulatedSec, 0), 86_400).rounded(.down))
        if TorBootstrapSelfHeal.shared.isFailedAttempt(
            reachedBootstrapping: true,
            reachedConnected: reachedConnected,
            foregroundDwellSeconds: dwell
        ) {
            let updated = TorBootstrapSelfHeal.shared.recordFailure(
                b: breadcrumb, stuckPercent: Int32(highestBootstrapPercent)
            )
            breadcrumb = updated
            TorBootstrapBreadcrumbStore.save(updated)
            torLog("bootstrap self-heal: failed attempt recorded (\(reason)) — streak=\(updated.consecutiveFailures), stuck=\(updated.lastStuckPercent)%, dwell=\(dwell)s")
        } else if reachedConnected, breadcrumb.consecutiveFailures != 0 {
            // Belt for the connect-time reset below (which is the primary one):
            // covers a process that connected before this build's reset existed,
            // or any future path that reaches .connected without noteBootstrapConnected().
            let updated = TorBootstrapSelfHeal.shared.recordSuccess(b: breadcrumb)
            breadcrumb = updated
            TorBootstrapBreadcrumbStore.save(updated)
        } else {
            torLog("bootstrap self-heal: attempt not scored (\(reason)) — connected=\(reachedConnected), dwell=\(dwell)s")
        }
    }

    /// Tor reached `.connected`: the failure streak is broken. Resets HERE rather
    /// than waiting for teardown, because a force-quit right after a successful
    /// connect would otherwise carry a stale streak into the next launch. Writes
    /// NOTHING in the steady state (streak already 0), so a healthy user's every
    /// session costs exactly one Keychain read and zero writes.
    private func noteBootstrapConnected() {
        reachedConnected = true
        guard bootstrapAttemptStarted, !bootstrapAttemptSettled else { return }
        bootstrapAttemptSettled = true
        guard breadcrumb.consecutiveFailures != 0 else { return }
        let updated = TorBootstrapSelfHeal.shared.recordSuccess(b: breadcrumb)
        breadcrumb = updated
        TorBootstrapBreadcrumbStore.save(updated)
        torLog("bootstrap self-heal: connected — failure streak cleared")
    }

    /// Lazily registers the two foreground-boundary observers. `willEnterForeground`
    /// / `didEnterBackground` (NOT willResignActive/didBecomeActive) because the
    /// transient `.inactive` states — Face ID, Control Center, the share sheet —
    /// are still the user waiting on the app, and treating them as "away" would
    /// under-count real dwell. The closures reach the singleton directly rather
    /// than capturing `self`, so nothing here is a Sendable capture.
    private func registerDwellObserversIfNeeded() {
        guard !dwellObserversRegistered else { return }
        dwellObserversRegistered = true
        let center = NotificationCenter.default
        // Tokens deliberately discarded: TorManager is the process-lifetime
        // singleton, so these observers are never removed.
        _ = center.addObserver(forName: UIApplication.didEnterBackgroundNotification,
                               object: nil, queue: .main) { _ in
            Task { @MainActor in TorManager.shared.closeDwellSegment() }
        }
        _ = center.addObserver(forName: UIApplication.willEnterForegroundNotification,
                               object: nil, queue: .main) { _ in
            Task { @MainActor in TorManager.shared.openDwellSegmentIfTracking() }
        }
    }

    private func closeDwellSegment() {
        guard let start = dwellSegmentStart else { return }
        dwellAccumulatedSec += Date().timeIntervalSince(start)
        dwellSegmentStart = nil
    }

    private func openDwellSegmentIfTracking() {
        guard bootstrapAttemptStarted, !bootstrapAttemptSettled, dwellSegmentStart == nil else { return }
        dwellSegmentStart = Date()
    }

    /// Tears Tor down.
    ///
    /// [discardingState] — pass `true` ONLY where a cold start is the intent:
    ///   • every WIPE path (`AppState.emergencyWipe`), and
    ///   • the terminal-failure teardowns below, which latch `relaunchRequired`
    ///     so the process self-recycles: discarding there is this platform's
    ///     "delete the dir and retry once" (tor_main can be created only once per
    ///     process, so the retry has to happen in the NEXT one).
    /// The default `false` is the ORDINARY teardown — lock, background, close —
    /// which now deliberately PRESERVES the working dir so the next launch reuses
    /// its entry guards and cached consensus. That is a knowing forensic tradeoff
    /// (see `preservesStateAcrossLaunches`), not an oversight.
    func stop(discardingState: Bool = false) {
        torLog("stop(discardingState: \(discardingState)) called — tearing down Tor")
        // External proxy mode: the embedded Tor never ran in this process
        // (start() refuses), so there is nothing to narrate. The teardown below
        // still runs — it is a no-op for a never-started daemon EXCEPT the
        // discarding wipe of a working dir left by an earlier embedded-mode
        // launch, which every wipe path must still destroy.
        if !ExternalProxyMode.shared.isExternalThisProcess {
            ConnectionLog.shared.append(
                kind: ConnectionLog.Kind.system,
                text: "Tor stopping",
                code: ConnectionLog.Code.torStop
            )
        }
        // The raw-650 tap dies with the controller below (it lives in the
        // controller's own observer list and we hold no handle to remove it) —
        // drop its de-dupe stamps so nothing from this run can swallow the first
        // line of a later one.
        TorControlEventTap.shared.reset()
        disarmDescriptorHedge()
        disarmBootStall()
        // Score this run into the cross-launch breadcrumb before anything else in
        // the teardown can change the state it reads. One-shot; a no-op for a
        // process that never started Tor, for a run that already connected, and
        // for every wipe path (TorBootstrapBreadcrumbStore is suppressed there, so
        // no write can land after the crypto-erase).
        settleBootstrapAttempt(reason: "stop(discardingState: \(discardingState))")
        if let po = progressObserver { controller?.removeObserver(po) }
        if let co = circuitObserver { controller?.removeObserver(co) }
        progressObserver = nil
        circuitObserver = nil
        // Best-effort: ask tor_main to exit cleanly (SIGNAL HALT) over the control
        // socket before we drop it. thread.cancel() alone does NOT stop tor_run_main
        // (it doesn't poll NSThread.isCancelled).
        //
        // IMPORTANT: HALT is only honoured on an AUTHENTICATED
        // control connection. On the terminal-failure branches that route here BEFORE
        // authenticate() ever succeeded, this HALT does NOT stop tor_main:
        //   • connect-attempt exhaustion — controller.isConnected is false, so the
        //     guard below skips HALT entirely (it is never sent);
        //   • cookie-unreadable / auth-error / auth-success==false — controller.isConnected
        //     is true but AUTHENTICATE never succeeded, so Tor's control server rejects
        //     the command server-side.
        // In all of those cases the once-per-process, un-forcibly-killable tor_main C
        // thread keeps running and keeps writing into the working directory, for the
        // rest of the foreground session. When [discardingState] is set, the wipe in
        // wipeWorkingDirectory() below therefore only sticks if HALT WAS honoured
        // (the post-auth teardown paths); the un-killable-tor_main residue is bounded
        // by the process-exit wipe that discarding teardowns arm (armExitWipe →
        // atexit), which deletes the dir as the process's LAST act on the exit(0)
        // self-recycle — see the note there. Do not claim this HALT terminates
        // tor_main; it often does not. One-shot; a no-op if the control channel is
        // already down.
        //
        // ACKNOWLEDGED, THEN AWAITED (2026-09-14) — it used to be fire-and-forget.
        // The ordinary `.background` caller is ContentView's scenePhase handler,
        // which calls exit(0) microseconds later: the HALT write had not even left
        // the control queue, tor_main therefore never reached `tor_cleanup()`, and
        // `or_state_save()` never wrote the entry-guard state this platform
        // deliberately PRESERVES (see `preservesStateAcrossLaunches`). With
        // `AvoidDiskWrites 1` Tor defers a dirty state file by 3600 s, so no
        // sub-hour session ever persisted a guard change — every launch re-picked
        // guards and paid a cold guard handshake. Android has never had this bug:
        // it SIGTERMs and `waitFor`s the child (TorManager.kt stop()).
        let stopDeadline = Date().addingTimeInterval(TorManager.stopConfirmTimeoutSec)
        let haltAcked = DispatchSemaphore(value: 0)
        var haltSent = false
        if let c = controller, c.isConnected {
            haltSent = true
            c.sendCommand("SIGNAL", arguments: ["HALT"], data: nil) { codes, _, stop in
                // Observers are handed EVERY complete reply, async 650 events
                // included, and this block sits at the HEAD of the list — so it must
                // match the 250 explicitly. The old `return true` for any reply both
                // ended on the first stray event and SWALLOWED it from the
                // persistent event tap.
                guard codes.first?.intValue == 250 else { return false }
                stop.pointee = true   // one-shot: stop observing after the reply
                haltAcked.signal()
                return true
            }
        }
        // Delivery only: Tor answers 250 BEFORE it starts shutting down ("send DONE
        // first, in case the signal makes us shut down"), so the state write is
        // covered by the thread wait below. The reply lands on TORController's own
        // serial control queue, never on main, so this cannot deadlock. Not acked ⇒
        // an unauthenticated control connection (see above), where HALT is refused
        // and waiting for a shutdown that will never come is pure stall.
        let acked = haltSent &&
            haltAcked.wait(timeout: .now() + TorManager.haltAckTimeoutSec) == .success
        if haltSent { torLog("stop: HALT acked=\(acked)") }
        let dyingThread = thread
        controller?.disconnect()
        controller = nil
        thread = nil
        dyingThread?.cancel()
        // THE state flush. tor_main() runs tor_cleanup() — and therefore
        // or_state_save() — on its way out, so `isFinished` on the Tor thread is a
        // precise "guards + cached consensus are on disk" signal, and there is no
        // control-port command that forces a state save (SAVECONF writes torrc, not
        // state): a clean shutdown is the only lever. Bounded by [stopDeadline], so
        // this whole teardown costs at most stopConfirmTimeoutSec even when Tor is
        // wedged. Previously ONLY the discarding teardown waited (inside
        // wipeWorkingDirectory); the ordinary preserving one — every lock, every
        // background — did not wait at all, which is the bug.
        // `haltSent`, not `acked`: HALT only goes out on an AUTHENTICATED control
        // connection, so a late 250 (TORController's serial queue under scheduler
        // pressure at background time) still means Tor IS shutting down and WILL
        // write its state — skipping the wait here re-created the "guards never
        // persisted" bug this block fixes. Bounded by
        // stopDeadline either way.
        if haltSent { awaitThreadExit(dyingThread, until: stopDeadline, reason: "stop") }
        state = .disconnected
        socksPort = 0
        started = false
        // No bootstrap is in flight any more: a later re-anchor must fall back to
        // the full watchdog window rather than subtracting a dead run's elapsed.
        startedAtUptime = 0
        // threadEverCreated stays latched, so if Tor ever ran, this process can
        // never start it again — flag it so the process is recycled when next
        // invisible. (stop() before any start() — Tor never ran — stays clean.)
        if threadEverCreated { noteRelaunchRequired() }
        torLog("Tor stopped, state=disconnected")
        if discardingState || !TorManager.preservesStateAcrossLaunches {
            // The un-killable tor_main can outlive this call and rewrite the dir
            // (see the HALT note above), so a discarding teardown also arms the
            // atexit backstop that deletes it as the process's last act.
            TorManager.armExitWipe()
            wipeWorkingDirectory(confirming: dyingThread)
        } else {
            // ORDINARY teardown: keep guards + cached consensus, and re-assert
            // NSFileProtectionComplete over everything Tor wrote this session
            // (belt to the inherit-from-directory braces applied in start()).
            TorManager.applyDataProtection(to: TorManager.workingDirPath())
            // The auth cookie and the control socket are per-session material, not
            // reusable state — drop them even on the preserving path.
            TorManager.purgeSessionEphemera(in: TorManager.workingDirPath())
        }
    }

    /// Wipes the Tor working dir on the DISCARDING teardowns only: an emergency
    /// wipe, a terminal Tor failure (markThreadDead is NOT one — see there), and
    /// the simulator, whose pid-suffixed path is never reused. The ordinary
    /// lock/background/close path deliberately preserves it — parity with Android
    /// `TorManager.stopAndDiscardState()` vs `stop()`.
    ///
    /// Delete in TWO passes. First an EAGER delete so a process kill
    /// during the confirm-wait can never leave the working dir on disk (the
    /// regression a delete-last order created). Then, if a dying thread was
    /// passed, a bounded settle-wait on it reporting `isFinished` (it returns
    /// quickly once the HALT stop() sends lands and tor_run_main returns) followed
    /// by a SECOND delete, so a still-terminating tor_main that recreated files
    /// right after the eager delete leaves nothing behind (the race Android guards
    /// with waitFor()/destroyForcibly(); iOS has no forcible-kill for a TorThread).
    /// Bounded so the main actor is never blocked longer than `stopConfirmTimeoutSec`.
    private func wipeWorkingDirectory(confirming dyingThread: TorThread?) {
        let dir = TorManager.workingDirPath()
        // Delete EAGERLY, BEFORE the confirm-wait below.
        // That wait can be pre-empted by a process kill (force-quit from the App
        // Switcher, power-off) — if the delete were the LAST step it would never
        // run and the full working dir (control_auth_cookie, entry-guard state,
        // cached consensus/descriptors) would survive on disk. Deleting first
        // closes that window immediately. A teardown that reaches here is terminal
        // (the process self-recycles via relaunchRequired → exit(0) on the next
        // background) or a wipe, so we never need to preserve these files — the
        // NEXT process re-bootstraps cold, which is exactly the once-only retry a
        // corrupt preserved dir needs. NOTE: this is BEST-EFFORT. If HALT was
        // not honoured (unauthenticated teardown — see stop()), tor_main is still
        // alive and will rewrite the dir after both deletes here; that residue is only
        // truly gone at process exit, wiped by the armExitWipe() atexit hook.
        try? FileManager.default.removeItem(atPath: dir)
        // A still-terminating tor_main can recreate
        // files right after the eager delete above. CONFIRM it actually stopped —
        // bounded so the main actor is never blocked longer than
        // stopConfirmTimeoutSec (the HALT stop() sends normally makes this
        // near-instant) — then delete AGAIN so nothing recreated survives.
        if let t = dyingThread {
            // Normally instant: stop() already awaited this thread before calling
            // here. Kept because this method is also reachable from the
            // terminal-failure teardowns, where HALT was never honoured.
            awaitThreadExit(t, until: Date().addingTimeInterval(TorManager.stopConfirmTimeoutSec),
                            reason: "working-dir wipe")
            try? FileManager.default.removeItem(atPath: dir)
        }
    }

    /// Blocks the caller until tor_main has RETURNED (`isFinished`) or [deadline]
    /// passes. Returning from tor_main means tor_cleanup() — and with it
    /// or_state_save() — has completed, which is what makes the preserved working
    /// dir actually carry this session's entry guards into the next launch.
    /// Cheap poll rather than KVO: the wait is sub-second in practice and the
    /// caller is on its way to exit(0).
    private func awaitThreadExit(_ dyingThread: TorThread?, until deadline: Date, reason: String) {
        guard let t = dyingThread, !t.isFinished else { return }
        while !t.isFinished && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.02)
        }
        torLog("\(reason): tor thread finished=\(t.isFinished)")
    }

    /// Upper bound on how long stop() waits for tor_main to terminate — for the
    /// guard-state flush on every teardown, and before wiping the working dir on
    /// the discarding ones. Comparable to Android's waitFor budget;
    /// the HALT signal normally makes termination near-instant, so this cap is
    /// only hit if HALT was not honoured.
    private static let stopConfirmTimeoutSec: TimeInterval = 2.0

    /// Upper bound on the SIGNAL HALT acknowledgement wait inside [stop]. Counted
    /// INSIDE [stopConfirmTimeoutSec] (the deadline is taken before the send), so
    /// an ordinary `.background` teardown can never block longer than that total.
    private static let haltAckTimeoutSec: TimeInterval = 0.5

    /// One-time guard for [armExitWipe]. Touched only from the main actor, so the
    /// unsynchronised read/write is safe.
    private static var exitWipeArmed = false

    /// Whether Tor's working dir survives between launches.
    ///
    /// TRUE on device (2026-08-01): a cold Tor reports
    /// `Bootstrapped 100%` in ~7 s and then fails to complete an onion rendezvous
    /// for MINUTES, so wiping on every start/stop made each relaunch re-pay a full
    /// cold descriptor/guard/consensus fetch — while a warm daemon reached the
    /// onion on every probe. Wiping also RE-SAMPLED entry guards on every launch,
    /// which is an anonymity cost in its own right: guards exist to be sticky.
    /// The price is that `<Caches>/tor` now shows prior Tor use in an AFU
    /// image; it is mitigated by NSFileProtectionComplete (see
    /// [applyDataProtection]) and unchanged at BFU, and every wipe path still
    /// destroys it (`stop(discardingState: true)` + `IosAppController.deleteTorData`).
    ///
    /// FALSE on the simulator, where [workingDirPath] is pid-suffixed (`sun_path`
    /// is 104 bytes, so the control socket cannot live in the sandbox) and so is
    /// never reused anyway — wiping there keeps the host's /tmp clean.
    static var preservesStateAcrossLaunches: Bool {
        #if targetEnvironment(simulator)
        return false
        #else
        return true
        #endif
    }

    /// Per-session files that must NOT be inherited by the next launch, cleared
    /// even on the preserving path.
    ///
    /// `control_auth_cookie` is the load-bearing one: [connectControlChannel] reads it
    /// and AUTHENTICATEs with it, and every auth failure on that path is TERMINAL for
    /// the process (tor_main runs once — there is no re-auth). A stale cookie read
    /// before the fresh daemon rewrote it would therefore wedge the launch into a
    /// relaunch-required loop — and P4a's length check does NOT catch that case (a
    /// stale cookie is a full 32 bytes), so this purge remains the only defence.
    /// `cp` is our control socket: Tor unlinks and re-binds it, but a leftover socket
    /// file with no listener only costs connect retries — and, since P4b now polls for
    /// that file's appearance, a leftover would also let the poll fire early (bounded,
    /// self-healing: the connect throws and retries). Neither is reusable state; both
    /// are also auth material worth not leaving on disk.
    nonisolated static func purgeSessionEphemera(in dir: String) {
        for name in ["control_auth_cookie", "cp"] {
            try? FileManager.default.removeItem(atPath: "\(dir)/\(name)")
        }
    }

    /// NSFileProtectionComplete + backup exclusion for the Tor working dir and
    /// everything in it — the same hardening `IosVaultDatabase.protectDbFiles`
    /// applies to the vault, now that this state
    /// outlives the session and is worth protecting at rest.
    ///
    /// Complete (not the CompleteUntilFirstUserAuthentication default) is safe
    /// here because Tor only ever runs while the DEVICE is unlocked: [start] is
    /// gated on the app being active with protected data available, and every
    /// `.background` either stops the daemon at once or — the bounded keep-alive
    /// (2026-10-23, AppState "Bounded Tor keep-alive") — keeps it at most for
    /// the background-task budget and ends that window on
    /// `protectedDataWillBecomeUnavailable`, well inside the ~10 s the OS takes
    /// to evict the Class-A keys after a device lock. So the dir is never touched
    /// while locked; `removeItemAtPath` on the wipe paths does not need the
    /// contents and works regardless.
    ///
    /// Applied to the directory FIRST in [start] (new files inherit their
    /// directory's class) and re-applied over the contents on teardown, since
    /// inheritance is not a contract we want to be the only line of defence.
    nonisolated static func applyDataProtection(to dir: String) {
        let fm = FileManager.default
        var paths = [dir]
        if let children = fm.enumerator(atPath: dir)?.allObjects as? [String] {
            paths.append(contentsOf: children.map { "\(dir)/\($0)" })
        }
        for path in paths {
            try? fm.setAttributes([.protectionKey: FileProtectionType.complete],
                                  ofItemAtPath: path)
            var url = URL(fileURLWithPath: path)
            var values = URLResourceValues()
            values.isExcludedFromBackup = true
            try? url.setResourceValues(values)
        }
    }

    /// Register a process-exit hook that wipes the Tor working
    /// directory as the process's LAST act. tor_main is an un-forcibly-killable
    /// NSThread (see `threadEverCreated`); on the terminal-failure teardown paths
    /// where SIGNAL HALT is not honoured (unauthenticated control channel — see
    /// stop()), it keeps rewriting the working dir for the rest of the foreground
    /// session, past stop()'s best-effort wipe. We deliberately do NOT exit(0)
    /// mid-foreground (the app stays visible with an honest "close and reopen" hint —
    /// an abrupt disappearance would read as a crash and break the deniability/UX
    /// design), so the residue is bounded instead by the self-recycle exit(0) that
    /// ContentView fires on the next `.background` (immediately: a discarding
    /// teardown latches relaunchRequired, which the bounded keep-alive never
    /// keeps). `exit(0)` runs C `atexit` handlers,
    /// so wiping here guarantees whatever the live daemon wrote is deleted as the
    /// process dies — whatever branch got us there, authenticated or not. This is the
    /// backstop the best-effort wipe in stop()/wipeWorkingDirectory() cannot provide
    /// while tor_main is still alive. Idempotent (registered once per process).
    ///
    /// Armed from the DISCARDING teardowns only, NOT from start() as it once was:
    /// the working dir is now preserved across launches, and an unconditional
    /// atexit delete would destroy it on exactly the exit(0) self-recycle that is
    /// the most common relaunch — silently undoing the whole change. Registering
    /// it at the moment a discard is requested keeps the backstop for the case it
    /// was written for (a live tor_main rewriting the dir after the wipe) and only
    /// for that case.
    static func armExitWipe() {
        if exitWipeArmed { return }
        exitWipeArmed = true
        // Non-capturing (C-convention) handler: it references only a `nonisolated`
        // static path helper and the global FileManager, so it can run on whatever
        // thread calls exit(). Foundation/FileManager are still live at atexit time.
        _ = atexit {
            try? FileManager.default.removeItem(atPath: TorManager.workingDirPath())
        }
    }

    /// The Tor working-directory path (data dir + control socket + auth cookie).
    /// `nonisolated static` so the [armExitWipe] atexit handler can compute it off the
    /// main actor without touching instance state; every instance path uses it too,
    /// so the teardown wipes and the atexit backstop agree on the exact path that gets wiped.
    nonisolated static func workingDirPath() -> String {
        #if targetEnvironment(simulator)
        // Short absolute path under /tmp (sun_path is limited to 104 bytes; the
        // sandboxed Caches dir is too long for a control socket on the simulator);
        // pid-suffixed so two simulators on one host don't collide.
        return "/tmp/rt-\(getpid())"
        #else
        return "\(NSSearchPathForDirectoriesInDomains(.cachesDirectory, .userDomainMask, true).first ?? "")/tor"
        #endif
    }

    /// Confirm the live SOCKS listener over Tor's AUTHENTICATED
    /// control socket (cookie-auth over a UNIX-domain socket at a Tor-owned path),
    /// rather than trusting a loopback SOCKS5 greeting a local app could spoof.
    /// A squatter can `accept()` a freed `auto` port and answer `05 00`, but it
    /// cannot impersonate the control socket — so this authenticates that
    /// 127.0.0.1:<port> is genuinely THIS process's Tor. Calls back (on main) with
    /// the port Tor currently reports, or nil if the control connection is down
    /// (Tor dead), the reply is unparseable, or it doesn't answer within the
    /// timeout. Fail-closed: nil ⇒ caller treats Tor as gone.
    ///
    /// An EMPTY answer is retried (up to [socksReadbackAttempts], inside the same
    /// overall timeout) rather than reported as nil: it is far more often the
    /// vendored controller pairing this GETINFO with a stray async event than a
    /// dead daemon — see socksReadbackAttempts. The caller's reaction here is
    /// markThreadDead() (relaunch-required, a forced app restart for the user),
    /// so a false negative is expensive; a genuinely dead control socket still
    /// answers nothing at all and times out exactly as before.
    func confirmSocksPortViaControl(timeoutMs: Int = 3000,
                                    completion: @escaping (UInt16?) -> Void) {
        guard let controller, controller.isConnected else { completion(nil); return }
        var settled = false
        let finish: (UInt16?) -> Void = { port in
            DispatchQueue.main.async {
                guard !settled else { return }
                settled = true
                completion(port)
            }
        }
        attemptSocksPortConfirm(attempt: 1, finish: finish)
        // A dead control socket may never deliver a reply — bound the wait.
        DispatchQueue.main.asyncAfter(deadline: .now() + .milliseconds(timeoutMs)) {
            finish(nil)
        }
    }

    private func attemptSocksPortConfirm(attempt: Int, finish: @escaping (UInt16?) -> Void) {
        guard let controller, controller.isConnected else { finish(nil); return }
        controller.getInfoForKeys(["net/listeners/socks"]) { values in
            if let port = values.first.flatMap({ TorManager.parseSocksListenerPort($0) }) {
                finish(port)
                return
            }
            guard attempt < TorManager.socksReadbackAttempts else {
                finish(nil)
                return
            }
            hopToMain(after: TorManager.socksReadbackRetryDelaySec) { [weak self] in
                self?.attemptSocksPortConfirm(attempt: attempt + 1, finish: finish)
            }
        }
    }

    #if DEBUG
    /// e2e-only (the `--test-tor-keepalive-unbounded` suspend-survival probe,
    /// AppState): does this process's tor_main thread still exist and run? A
    /// read of NSThread state only — never a decision input in any build.
    var threadAliveForProbe: Bool {
        guard let t = thread else { return false }
        return t.isExecuting && !t.isFinished
    }
    #endif

    /// The resume-path liveness check found the Tor thread gone (the control
    /// socket no longer confirms the published SOCKS port — iOS killed the
    /// thread during a background suspend). Latch the process as
    /// relaunch-required; see `relaunchRequired`.
    func markThreadDead() {
        torLog("markThreadDead: Tor thread confirmed dead — relaunch required")
        // Same one-shot scoring as stop(). This path is the OS killing the
        // embedded thread during a background suspend, which is the single most
        // common relaunch cause — and the reason dwell is FOREGROUND-only: the
        // suspended hours between the last foreground moment and this detection
        // must not count as the user waiting.
        settleBootstrapAttempt(reason: "markThreadDead")
        state = .disconnected
        noteRelaunchRequired()
        // `socksPort` is CURRENT-VALUE state: consumers read it synchronously to
        // decide whether a Tor transport exists (AppState's wiring + the push
        // registration paths all gate on `> 0`). A dead thread has no listener, so
        // leaving the last value published here would hand every one of them a
        // stale port that resolves to POSIX 61 — or to whatever local
        // process re-bound that freed `auto` port. stop() already zeroes it; this
        // terminal path must too.
        socksPort = 0
        // Deliberately NOT a discard (changed 2026-08-01). iOS killing the
        // embedded Tor thread during a background suspend is the single MOST
        // common way this app relaunches — precisely the "ordinary restart" whose
        // guard + consensus state we now keep. Nothing here indicates a corrupt
        // dir, and Tor writes its state atomically, so the next process reuses it.
        // Re-assert protection over whatever the dead thread left, and drop the
        // per-session auth cookie / control socket.
        TorManager.applyDataProtection(to: TorManager.workingDirPath())
        TorManager.purgeSessionEphemera(in: TorManager.workingDirPath())
    }

    /// Latches [relaunchRequired] and narrates it ONCE per process into the live
    /// connection-log panel. All three latch sites (a refused second start(), a
    /// stop() after Tor ever ran, and markThreadDead) route here: they describe
    /// the same terminal condition — this process can never produce a working Tor
    /// again — and the user-visible consequence (close and reopen) is identical,
    /// so a second line would add noise, not information. `TorManager` is the
    /// process-lifetime singleton, so the instance latch IS a process latch.
    private func noteRelaunchRequired() {
        relaunchRequired = true
        guard !relaunchLineEmitted else { return }
        relaunchLineEmitted = true
        ConnectionLog.shared.append(
            kind: ConnectionLog.Kind.tor,
            text: "tor relaunch required",
            code: ConnectionLog.Code.torRelaunchLatched
        )
    }

    /// One-shot guard for the line above (never for the latch itself).
    private var relaunchLineEmitted = false

    /// LIGHTER recovery than an app relaunch: ask Tor for FRESH circuits (SIGNAL
    /// NEWNYM) when the relay has been unreachable for a while. Each SwiftTorHttp
    /// request opens a NEW stream (Connection: close), so the next probe rides a
    /// new circuit — often clearing a wedged .onion rendezvous (the relay is up;
    /// our circuit is bad, e.g. under multi-device Tor contention) WITHOUT tearing
    /// down the bootstrapped daemon (in-process re-init is impossible — the only
    /// heavier option is a full app relaunch). No-op if the control channel isn't
    /// up. Tor coalesces rapid NEWNYMs, so a caller may fire this every few
    /// reachability misses safely.
    ///
    /// Returns whether the command was actually HANDED TO the control channel —
    /// false means the channel isn't up, i.e. NEWNYM is unavailable for this
    /// session (Android parity: `TorManager.requestNewCircuit` returns the same
    /// distinction, and both ladders use it to stop spending rungs on a lever
    /// that cannot fire). NOT a delivery/`250` confirmation: the reply is
    /// observed asynchronously. `@discardableResult` — the pre-existing callers
    /// deliberately ignore it.
    @discardableResult
    func requestNewCircuit() -> Bool {
        guard let controller, controller.isConnected else {
            torLog("requestNewCircuit: control channel down — skipping NEWNYM")
            return false
        }
        torLog("requestNewCircuit: SIGNAL NEWNYM (requesting fresh circuits)")
        // Bootstrap-stall rung spacing (TorBootstrapStall.NEWNYM_SPACING_MS).
        lastNewnymAtUptime = ProcessInfo.processInfo.systemUptime
        controller.sendCommand("SIGNAL", arguments: ["NEWNYM"], data: nil) { [weak self] codes, _, stop in
            // Same shape as the HSFETCH observer: this block sits at the HEAD of
            // the observer list and is handed every complete reply, async 650
            // events included — pass those through to the persistent tap and end
            // only on THIS command's reply. (It used to stop on the first reply of
            // any kind, which could swallow one event and miss the 250.)
            guard let code = codes.first?.intValue, code != 650 else { return false }
            stop.pointee = true
            if code == 250 {
                hopToMain { self?.onNewnymAccepted() }
            }
            return true
        }
        return true
    }

    /// Installed by AppState before every start(): called on main right after an
    /// app-fired NEWNYM got its `250`, whichever rung fired it, so the current
    /// transport aborts its in-flight probe / batch peek and re-probes at once
    /// (`IosAppController.noteNewCircuitRequested`). Android sibling: the
    /// `onNewCircuitAccepted` constructor argument of TorManager.kt.
    var onNewCircuitAccepted: (() -> Void)?

    /// A NEWNYM this app sent was accepted. Tor has purged the client's HS state:
    /// the pending descriptor fetches are cancelled and the descriptor cache is
    /// gone, so the hedge's in-flight count and episode start over
    /// (`DescriptorHedge.noteNewnym`) — its session BUDGET does not. Android
    /// sibling: `TorManager.onNewnymAccepted`, same order.
    private func onNewnymAccepted() {
        disarmDescriptorHedge()
        descriptorHedge?.noteNewnym()
        // Pending fetches were cancelled by Tor; good/bad HSDirs are KEPT.
        TorManager.hsDirLedger.noteNewnym()
        // NEWNYM killed every circuit: drop circuit tracking, guard 2 s.
        TorManager.hsCircuitWatchdog.noteNewnym()
        // NEWNYM purged the descriptor cache: re-race the relay's addresses (the
        // current winner stays the base URL until the new race decides). No-op
        // for a single address. Android sibling: onNewnymAccepted, same order.
        TorManager.relayRace.noteTorHsStateReset()
        startRelayAddressRace()
        onNewCircuitAccepted?()
    }

    // MARK: - Several onion addresses: the descriptor race (2026-10-23)
    //
    // Decision: the SHARED `RelayAddressRace` (process-wide — tor_main runs once
    // per process, and the race describes its descriptor cache). Once per Tor HS
    // state (connected / accepted NEWNYM) one bare `HSFETCH <addr>` per configured
    // address goes out at once; the first `HS_DESC RECEIVED` (fed by
    // TorControlEventTap on Tor's queue) makes that address the session's
    // `RelayConfig.BASE_URL`. A single address makes all of this a no-op. Android
    // sibling: TorManager.kt startRelayAddressRace.

    /// The relay's descriptor race. `nonisolated` because the tap classifies on
    /// Tor's control queue (the Kotlin class is lock-guarded).
    nonisolated static var relayRace: RelayAddressRace { RelayEndpoints.shared.race }

    /// Sends the race's HSFETCHes. Needs the control channel (HS_DESC is in the
    /// first SETEVENTS); called right before `.connected` is published and after
    /// an accepted NEWNYM; idempotent per Tor HS state. Never logs an address — the
    /// race writes its own fixed phrases.
    @discardableResult
    func startRelayAddressRace() -> Bool {
        let race = TorManager.relayRace
        guard race.isRacing, started, !relaunchRequired,
              let controller, controller.isConnected else { return false }
        var sent = false
        for address in race.beginRace() {
            if requestHsDescriptorFetch(address: address) { sent = true }
        }
        return sent
    }

    /// Bounded Tor keep-alive, WARM RETURN (AppState.endTorKeepAliveOnForeground):
    /// the kept daemon's descriptor race is left EXACTLY as it is when it was
    /// decided — the winner's descriptor is in Tor's in-RAM cache, and a refetch
    /// would only add HSDir load and delay the first probe. Only a race the
    /// current Tor HS state never decided (no RECEIVED for any address — the
    /// fetches failed or were still pending when the app left) is reset and run
    /// again. A single address is "always decided" (nothing to race); Tor's own
    /// fetch-on-demand covers it, as on every connect. Never logs an address.
    @discardableResult
    func rerunUndecidedRelayAddressRace() -> Bool {
        let race = TorManager.relayRace
        guard race.isRacing, !race.decidedThisState(), started, !relaunchRequired,
              let controller, controller.isConnected else { return false }
        race.noteTorHsStateReset()
        return startRelayAddressRace()
    }

    // MARK: - Descriptor hedge (2026-10-12)
    //
    // The earlier bounded HSDir hedge. Decision: the SHARED `DescriptorHedge`
    // (session-scoped — AppState installs `controller.descriptorHedge` before every
    // start()): the first `HS_DESC REQUESTED` for the relay's onion with no
    // RECEIVED opens an episode; 1 s later a BARE `HSFETCH <onion>` overlaps the
    // pending fetch (Tor keeps its HSDir selection and its recently-asked filter);
    // 4 s after that one pinned re-request (HsDirLedger) may follow. ≤ 2 fetches in
    // flight (counted from REQUESTED events), ≤ 4 hedge HSFETCHes per session,
    // never replenished. Here only the ONE timer and the command. Android
    // sibling: TorManager.kt onRelayDescriptorEvent / armDescriptorHedge /
    // checkDescriptorHedge.

    /// Every configured v3 onion address of the relay in HSFETCH form (empty for
    /// a non-onion relay — the hedge then never arms). Compared against the
    /// control events only — NEVER logged. `nonisolated` because the tap
    /// classifies on Tor's control queue.
    nonisolated static var relayHsFetchAddresses: [String] { relayRace.hsFetchAddresses }

    /// Installed by AppState before every start(): the SESSION's hedge
    /// (`IosAppController.descriptorHedge`). nil = inert.
    var descriptorHedge: DescriptorHedge?

    /// Installed by AppState before every start(): has the session had a relay
    /// answer yet? The hedge acts only before it. nil = inert.
    var descriptorHedgeAnsweredGate: (() -> Bool)?

    /// Installed by AppState before every start(): descriptor-stage early recovery
    /// (`DescriptorHedge.Decision.stageStalled`) — the session spends the NEWNYM
    /// through its shared early-NEWNYM gate (`AppState.fireDescriptorStageNewnym`).
    /// nil = inert. Android sibling: the `onDescriptorStageStalled` constructor
    /// argument of TorManager.kt.
    var onDescriptorStageStalled: (() -> Void)?

    /// The armed check, or nil. Replaced (never stacked) on every re-arm.
    private var descriptorHedgeItem: DispatchWorkItem?

    /// Hedge input from `TorControlEventTap` (hopped to main, Tor's order kept):
    /// one `HS_DESC` REQUESTED / RECEIVED / FAILED of the relay's onion, as the
    /// action's ordinal (an Int crosses the hop, not the Kotlin enum).
    func noteRelayDescriptorAction(_ ordinal: Int) {
        guard let hedge = descriptorHedge else { return }
        let action: RelayDescriptorEvent.Action
        switch ordinal {
        case 0: action = .requested
        case 1: action = .received
        default: action = .failed
        }
        hedge.observe(action: action, nowMs: DescriptorHedge.companion.nowMs())
        armDescriptorHedge(hedge)
    }

    /// (Re-)arms the single check from `DescriptorHedge.msUntilNextCheck`; nil
    /// there = nothing to wait for until the next event.
    private func armDescriptorHedge(_ hedge: DescriptorHedge) {
        disarmDescriptorHedge()
        guard started, !relaunchRequired,
              let next = hedge.msUntilNextCheck(nowMs: DescriptorHedge.companion.nowMs())
        else { return }
        // The item re-reads the hedge on main rather than capturing the Kotlin
        // object (not Sendable) in a @Sendable block.
        let item = DispatchWorkItem { [weak self] in
            MainActor.assumeIsolated {
                guard let self else { return }
                self.descriptorHedgeItem = nil
                guard let current = self.descriptorHedge else { return }
                self.checkDescriptorHedge(current)
            }
        }
        descriptorHedgeItem = item
        DispatchQueue.main.asyncAfter(deadline: .now() + Double(max(0, next.int64Value)) / 1000.0, execute: item)
    }

    private func disarmDescriptorHedge() {
        descriptorHedgeItem?.cancel()
        descriptorHedgeItem = nil
    }

    /// A check is due: ask the shared `DescriptorHedge.due` (it charges the session
    /// budget for whatever it hands out), send that HSFETCH, re-arm. FIRST = bare;
    /// SECOND = the pinned sequence (stall booked → pin → 551/552 → plain, the
    /// plain retry charged too). The phrases are Android's, word for word (same
    /// Kotlin helpers).
    private func checkDescriptorHedge(_ hedge: DescriptorHedge) {
        guard started, !relaunchRequired, let gate = descriptorHedgeAnsweredGate else { return }
        let d = hedge.due(nowMs: DescriptorHedge.companion.nowMs(),
                          relayAnswered: gate(),
                          hedgeEnabled: DescriptorHedge.companion.isHedgeEnabled())
        DescriptorHedge.companion.logDecision(d: d)
        if d.stageStalled {
            onDescriptorStageStalled?()
        }
        if let stage = d.stage {
            // Several addresses: the next unresolved one while the race is open,
            // else the winner (one address: slot 1, as before).
            let slot = TorManager.relayRace.hedgeTargetSlot()
            let target = TorManager.relayRace.hsFetchAddressAt(slot: slot)
            if stage == DescriptorHedge.Stage.first {
                if !requestHsDescriptorFetch(address: target) {
                    torLog("descriptor hedge — HSFETCH unavailable (control channel down)")
                }
                DescriptorHedge.companion.logSent(stage: stage, spent: d.spent)
            } else {
                // The stalled HSDir(s) become "bad" BEFORE the pin is chosen, so a
                // pinned directory that itself stalled is never chosen again
                // (HsDirLedger, shared with Android). `server` is SENSITIVE:
                // written into the command, never logged.
                TorManager.hsDirLedger.noteStallFired()
                let ledger = TorManager.hsDirLedger.forSlot(slot: slot)
                let server = ledger.pinnedServerArgument()
                let pinned = server != nil
                let sent = requestHsDescriptorFetch(address: target, serverArgument: server, onReply: { [weak self] code in
                    guard pinned else { return }
                    if RelayDescriptorWatchdog.shared.isPinRejectedReply(code: Int32(code)) {
                        // 551/552: that HSDir left the consensus / is no longer an
                        // HSDir. Forget it; the plain retry is one more charged
                        // HSFETCH. Android sibling: checkDescriptorHedge, same order.
                        ledger.dropPin()
                        HsDirLedger.companion.logPinDropped()
                        if hedge.tryChargeRetry() {
                            self?.requestHsDescriptorFetch(address: target)
                        }
                    } else if code == 250 {
                        HsDirLedger.companion.logPinned()
                    }
                })
                if !sent {
                    torLog("descriptor hedge — HSFETCH unavailable (control channel down)")
                }
                DescriptorHedge.companion.logSent(stage: stage, spent: d.spent)
            }
        }
        armDescriptorHedge(hedge)
    }

    /// Asks Tor to fetch the relay's hidden-service descriptor NOW (`HSFETCH
    /// <address>`) on the COMMAND connection. Android sibling:
    /// `TorManager.requestHsDescriptorFetch`. Returns whether the command was
    /// HANDED TO the control channel (same contract as `requestNewCircuit`); the
    /// reply is observed asynchronously and only logged.
    ///
    /// The address comes from `RelayDescriptorWatchdog.hsFetchAddress` (strict
    /// 56-char base32 — no CR/LF/space can reach this authenticated channel) and
    /// is NEVER logged.
    ///
    /// [serverArgument] pins the fetch to one HSDir (`SERVER=$<40 hex>` from the
    /// shared `HsDirLedger.pinnedServerArgument`, re-validated here because it goes
    /// onto the authenticated channel); SENSITIVE — never logged. [onReply] gets
    /// Tor's reply code on main.
    /// [address] (2026-10-23): which of the relay's addresses, in HSFETCH form —
    /// nil = the session's current one (slot 1 for a single address, i.e. the old
    /// behaviour). Re-validated (strict 56-char base32) before it reaches the
    /// authenticated channel.
    @discardableResult
    func requestHsDescriptorFetch(address: String? = nil, serverArgument: String? = nil, onReply: (@MainActor (Int) -> Void)? = nil) -> Bool {
        guard let controller, controller.isConnected else { return false }
        let race = TorManager.relayRace
        guard let address = address ?? race.hsFetchAddressAt(slot: race.currentSlot()),
              TorManager.isValidHsFetchAddress(address) else { return false }
        var arguments = [address]
        if let serverArgument {
            guard TorManager.isValidServerArgument(serverArgument) else { return false }
            arguments.append(serverArgument)
        }
        controller.sendCommand("HSFETCH", arguments: arguments, data: nil) { codes, _, stop in
            // This block sits at the HEAD of the observer list and is handed every
            // complete reply, async 650 events included — so pass events through
            // to the persistent tap and end only on THIS command's reply (250 or a
            // 5xx), exactly like the HALT observer in stop().
            guard let code = codes.first?.intValue, code != 650 else { return false }
            stop.pointee = true
            torLog("requestHsDescriptorFetch: HSFETCH -> \(code == 250 ? "250 OK" : "rejected (\(code))")")
            if let onReply {
                hopToMain { onReply(code) }
            }
            return true
        }
        return true
    }

    /// Per-PROCESS HSDir memory (tor_main runs once per process, so it dies with
    /// the Tor process), ONE LEDGER PER CONFIGURED ADDRESS (2026-10-23 — each has
    /// its own HSDir set). Fed by TorControlEventTap on Tor's control queue, read
    /// on main — the Kotlin class is lock-guarded. Kept across NEWNYM on purpose.
    nonisolated(unsafe) static let hsDirLedger = HsDirLedgerSet(slots: relayRace.slotCount)

    /// The only shape an HSFETCH address may have: v3, 56 base32 chars, no
    /// `.onion` (Android sibling: TorManager.kt V3_ADDRESS).
    nonisolated static func isValidHsFetchAddress(_ s: String) -> Bool {
        s.utf8.count == 56 && s.utf8.allSatisfy { ($0 >= 0x61 && $0 <= 0x7A) || ($0 >= 0x32 && $0 <= 0x37) }
    }

    // MARK: - Hung onion-circuit rung (2026-10-08)
    //
    // An intro circuit LAUNCHED and not BUILT within 6 s, or an `introduction
    // complete` with no `rendezvous joined` within 8 s → `CLOSECIRCUIT` that one
    // circuit so Tor retries it (next intro point / fresh rendezvous point) — no
    // NEWNYM, no budget of the NEWNYM rungs. Decision: the SHARED
    // `HsCircuitWatchdog` (fed by TorControlEventTap on Tor's queue); here only the
    // timer and the command. Android sibling: TorManager.kt onHsCircuitEvent /
    // checkHsCircuits / closeCircuit.

    /// Per-PROCESS (tor_main runs once per process). Lock-guarded Kotlin class:
    /// observed on Tor's control queue, decided on main. Circuit ids inside are
    /// never logged.
    nonisolated(unsafe) static let hsCircuitWatchdog = HsCircuitWatchdog()

    /// Installed by AppState before every start(): has the session had a relay
    /// answer yet? The rung acts only before it. nil = inert.
    var hsCircuitAnsweredGate: (() -> Bool)?

    /// From the tap (hopped to main): the watchdog armed a deadline.
    func scheduleHsCircuitCheck(afterMs ms: Int64) {
        let delay = Double(max(0, ms)) / 1000.0
        hopToMain(after: delay) { [weak self] in self?.checkHsCircuits() }
    }

    /// A deadline passed: ask the shared decision, send the closes it hands out,
    /// re-schedule for whatever is still armed. Fixed phrases only — the
    /// Android sibling logs the identical ones (same Kotlin helpers).
    private func checkHsCircuits() {
        guard started, !relaunchRequired, let gate = hsCircuitAnsweredGate else { return }
        let watchdog = TorManager.hsCircuitWatchdog
        let decision = watchdog.due(relayAnsweredThisSession: gate())
        var streamClosed = false
        for closure in decision.closures {
            HsCircuitWatchdog.companion.logClosing(kind: closure.kind)
            closeCircuit(closure.commandArgument())
            if closure.kind == .stream { streamClosed = true }
        }
        if decision.budgetSpentNow {
            HsCircuitWatchdog.companion.logBudgetSpent()
        }
        if decision.channelKick {
            // One beat later: TORController matches replies to the NEWEST observer,
            // so the CLOSECIRCUITs just sent must have their replies before the
            // kick's own commands and readback go out.
            hopToMain(after: TorManager.channelKickSettleSec) { [weak self] in self?.kickGuardChannels() }
        }
        // STREAM rule: the closed circuit carried the probe's (or the peek's)
        // stream, which now fails FAST — book it like a NEWNYM abort (re-probe at
        // once, no bookkeeping) so a watchdog close never breaks the cold rung's
        // evidence run. Same hook as the NEWNYM path; the NEWNYM ledgers are NOT
        // touched. Android sibling: TorManager.kt checkHsCircuits.
        if streamClosed { onNewCircuitAccepted?() }
        if let next = watchdog.msUntilNextDeadline() {
            scheduleHsCircuitCheck(afterMs: next.int64Value)
        }
    }

    /// `CLOSECIRCUIT <id>` on the command connection. The id is re-validated
    /// (digits only — it reaches the authenticated channel) and NEVER logged.
    /// `250` = closed; `552 Unknown circuit` = already gone — never retried.
    private func closeCircuit(_ circuitId: String) {
        guard HsCircuitWatchdog.companion.isValidCircuitId(id: circuitId),
              let controller, controller.isConnected else { return }
        controller.sendCommand("CLOSECIRCUIT", arguments: [circuitId], data: nil) { codes, _, stop in
            // Same reply discipline as HSFETCH / NEWNYM: pass async 650s through.
            guard let code = codes.first?.intValue, code != 650 else { return false }
            stop.pointee = true
            if code != 250 {
                torLog("circuit close not applied (\(code == 552 ? "already gone" : "refused"))")
            }
            return true
        }
    }

    // MARK: - Guard-channel kick (C4, 2026-10-09)
    //
    // Decision: the shared `HsCircuitWatchdog` (two closes on one first hop, or the
    // close budget spent with another stall; 1 per Tor process; >= 10 s after a
    // NEWNYM; before the first relay answer). Here: `SETCONF DisableNetwork=1` and
    // `=0` — every OR connection, the wedged guard channel included, is closed and
    // re-opened to the SAME guards (guards, consensus, descriptors and identity are
    // kept; tor_main keeps running) — then `GETINFO net/listeners/socks`, because
    // the re-enable re-binds `SocksPort auto` on a NEW port. Every Tor client
    // follows the move through the shared `SocksPortRedirect` (resolved per
    // request in PlatformHttpClient.ios.kt), so `socksPort` is deliberately NOT
    // re-published: the transport sink must not re-wire anything. Fixed phrases
    // only; no port is ever logged. Android sibling: TorManager.kt
    // kickGuardChannels.

    private nonisolated static let channelKickSettleSec: TimeInterval = 1.0
    private nonisolated static let channelKickReadbackAttempts = 3
    private nonisolated static let channelKickReadbackRetrySec: TimeInterval = 0.5

    /// Counts the two SETCONF replies, which may arrive in either handler (see
    /// kickStalledBootstrap); touched on main only.
    private final class KickReplies {
        var received = 0
        var ok = 0
    }

    private func kickGuardChannels() {
        toggleNetworkWhileConnected(forNetworkRestore: false)
    }

    /// The guard-channel kick body. `forNetworkRestore` = `kickForNetworkRestore`'s
    /// call: it writes the restore phrase instead of the watchdog's and reports a
    /// skip by returning false instead of the watchdog's skip line. The watchdog's
    /// gates live in `HsCircuitWatchdog.due` and are not consulted or spent here.
    @discardableResult
    private func toggleNetworkWhileConnected(forNetworkRestore: Bool) -> Bool {
        guard started, !relaunchRequired else { return false }
        let oldPort = Int32(socksPort)
        guard oldPort > 0, let controller, controller.isConnected else {
            if !forNetworkRestore {
                HsCircuitWatchdog.companion.logKick(phrase: HsCircuitWatchdog.companion.CHANNEL_KICK_SKIP_PHRASE)
            }
            return false
        }
        if forNetworkRestore {
            NetworkRestoreKick.companion.logKickSent()
        } else {
            HsCircuitWatchdog.companion.logKick(phrase: HsCircuitWatchdog.companion.CHANNEL_KICK_PHRASE)
        }
        // Streams in flight die with their channels: abort them now (booked like a
        // NEWNYM abort, never as fast failures), and block the old port so nothing
        // connects to it while it is closed.
        onNewCircuitAccepted?()
        SocksPortRedirect.shared.beginMove(oldPort: oldPort)
        let replies = KickReplies()
        let onReply: (Int) -> Void = { [weak self] code in
            hopToMain {
                replies.received += 1
                if code == 250 { replies.ok += 1 }
                if replies.received == 2 { self?.finishChannelKick(oldPort: oldPort, bothApplied: replies.ok == 2) }
            }
        }
        // Order-agnostic handlers, exactly like kickStalledBootstrap.
        for value in ["DisableNetwork=1", "DisableNetwork=0"] {
            controller.sendCommand("SETCONF", arguments: [value], data: nil) { codes, lines, stop in
                guard let code = codes.first?.intValue, code != 650, lines.count == 1 else { return false }
                stop.pointee = true
                onReply(code)
                return true
            }
        }
        return true
    }

    // MARK: - Network-restore kick (2026-10-25)
    //
    // AppState's NWPathMonitor saw the default network come back (decision: the
    // shared `NetworkRestoreKick` — baseline, 2 s debounce, 15 s rate limit). One
    // `SETCONF DisableNetwork=1` / `=0` so Tor reopens its OR connections now
    // instead of waiting out its own guard retry schedule (chain:push Case A:
    // first GUARD_UP ~10 min after the restore). Through the two existing toggle
    // paths, chosen by state, so the SOCKS listener move is handled as they handle
    // it: connected → the guard-channel kick body (in-flight streams aborted via
    // onNewCircuitAccepted, the move followed through SocksPortRedirect);
    // bootstrapping before the port readback → the bootstrap re-kick's two
    // commands. Neither rung's budget or gate is spent or consulted. Returns nil
    // when the toggle was handed to Tor, else why not (AppState logs it). Android
    // sibling: TorManager.kt kickForNetworkRestore.

    func kickForNetworkRestore() -> NetworkRestoreKick.SkipReason? {
        guard started else { return .torNotRunning }
        guard !relaunchRequired else { return .relaunchRequired }
        guard let controller, controller.isConnected else { return .controlDown }
        if state == .connected {
            return toggleNetworkWhileConnected(forNetworkRestore: true) ? nil : .portHandout
        }
        // The port is (being) handed out — moving it now would strand the app.
        guard !socksReadbackStarted else { return .portHandout }
        sendNetworkToggle(label: "network-restore kick")
        // The percent stood still because the network was gone: restart the stall
        // clock so the rung does not close, seconds from now, the connections this
        // toggle just reopened. Its kick count and spacing are untouched.
        if bootstrapStallKickEnabled {
            bootStallChangedAtUptime = ProcessInfo.processInfo.systemUptime
            armBootStall()
        }
        NetworkRestoreKick.companion.logKickSent()
        return nil
    }

    /// `SETCONF DisableNetwork=1` then `=0` from one main-actor turn, with the
    /// order-agnostic reply handling (and the one re-enable retry) of
    /// kickStalledBootstrap. No budget, no connection-log line — callers write theirs.
    private func sendNetworkToggle(label: String) {
        guard let controller, controller.isConnected else { return }
        for value in ["DisableNetwork=1", "DisableNetwork=0"] {
            controller.sendCommand("SETCONF", arguments: [value], data: nil) { codes, lines, stop in
                guard let code = codes.first?.intValue, code != 650, lines.count == 1 else { return false }
                stop.pointee = true
                torLog("\(label): SETCONF reply -> \(code == 250 ? "250 OK" : "rejected")")
                if code != 250 { hopToMain { TorManager.shared.retryNetworkReEnable() } }
                return true
            }
        }
    }

    private func finishChannelKick(oldPort: Int32, bothApplied: Bool) {
        torLog("guard-channel kick: SETCONF replies -> \(bothApplied ? "250 OK" : "not both applied")")
        // A refused re-enable would leave the network off for this process (no
        // in-process restart on iOS): one idempotent retry.
        if !bothApplied { retryNetworkReEnable() }
        readBackMovedSocksPort(oldPort: oldPort, attempt: 1)
    }

    private func readBackMovedSocksPort(oldPort: Int32, attempt: Int) {
        guard let controller, controller.isConnected else {
            concludeChannelKick(oldPort: oldPort, newPort: nil)
            return
        }
        controller.getInfoForKeys(["net/listeners/socks"]) { values in
            // The shared parser (127.0.0.1 listeners only) reads the reply's line
            // shape, so hand it the value in that shape.
            let lines = values.map { "250-net/listeners/socks=\($0)" }
            let parsed = SocksPortRedirect.shared.parseGetinfoSocksPort(replyLines: lines)?.int32Value
            hopToMain { [weak self] in
                guard let self else { return }
                if parsed == nil, attempt < TorManager.channelKickReadbackAttempts {
                    hopToMain(after: TorManager.channelKickReadbackRetrySec) { [weak self] in self?.readBackMovedSocksPort(oldPort: oldPort, attempt: attempt + 1) }
                    return
                }
                self.concludeChannelKick(oldPort: oldPort, newPort: parsed)
            }
        }
    }

    private func concludeChannelKick(oldPort: Int32, newPort: Int32?) {
        if let newPort, SocksPortRedirect.shared.completeMove(oldPort: oldPort, newPort: newPort) {
            if newPort != oldPort {
                HsCircuitWatchdog.companion.logKick(phrase: HsCircuitWatchdog.companion.SOCKS_MOVED_PHRASE)
            }
        } else {
            // Fail CLOSED: the old port stays blocked — requests fail fast and never
            // reach a squatter. iOS has no in-process restart; the stalled UI and
            // the manual Reconnect / relaunch own it from here.
            HsCircuitWatchdog.companion.logKick(phrase: HsCircuitWatchdog.companion.SOCKS_LOST_PHRASE)
        }
        // New channel epoch: the close budget is renewed (bounded — one kick per
        // Tor process). Android sibling: TorManager.kt, same line.
        if TorManager.hsCircuitWatchdog.noteChannelKick() {
            HsCircuitWatchdog.companion.logBudgetRenewed()
        }
        // A request that slipped into the gap is abandoned too, then re-probed on
        // the moved port.
        onNewCircuitAccepted?()
    }

    /// `SERVER=$` + exactly 40 upper-case hex — the only shape that may reach the
    /// authenticated control channel (Android: TorManager.SERVER_ARGUMENT).
    nonisolated static func isValidServerArgument(_ s: String) -> Bool {
        let prefix = "SERVER=$"
        guard s.hasPrefix(prefix) else { return false }
        let hex = s.dropFirst(prefix.count)
        return hex.count == 40 && hex.allSatisfy { ("0"..."9").contains($0) || ("A"..."F").contains($0) }
    }

    // MARK: - Bootstrap-stall rung (2026-10-06)
    //
    // The bootstrap percent standing still for `TorBootstrapStall.STALL_MS` (20 s)
    // inside the ladder (5 % <= p < 100 %) → `SETCONF DisableNetwork=1` then
    // `SETCONF DisableNetwork=0`, back to back on the command connection:
    // every OR / directory connection is closed and the stalled directory fetch is
    // relaunched on a fresh one; guards, consensus and state are kept, tor_main
    // keeps running. This is the ONLY bootstrap rescue iOS has — it cannot restart
    // Tor in-process. Shared decision: `TorBootstrapStall.msUntilKick` (≤ 2 per
    // process — tor_main runs once — never within 10 s of a NEWNYM). Phrases
    // and codes are Android's (`TorBootstrapStall.kickLine` / `skipLine`).
    //
    // THE SOCKS PORT MOVES: DisableNetwork closes the SOCKS listener and the
    // re-enable re-binds `SocksPort auto` on a NEW port. iOS learns its port only
    // at CIRCUIT_ESTABLISHED (readBackSocksPort), so the kick is refused once that
    // readback has started or `.connected` is published — everything here runs on
    // main, the readback is dispatched to main, and Tor answers commands in order,
    // so a readback that follows a kick always reads the re-bound listener.
    // Android sibling: TorManager.kt noteBootstrapProgressForStall / kickStalledBootstrap.

    /// Set by AppState before every start() (see installDescriptorHedge's
    /// sibling, AppState.installBootstrapStallKick). A switch, not a gate: a
    /// bootstrap below 100 % cannot have produced a relay answer, so the session
    /// has no input to give. false = inert.
    var bootstrapStallKickEnabled = false

    private var bootStallItem: DispatchWorkItem?
    private var bootStallPctHighest = 0
    private var bootStallChangedAtUptime: TimeInterval = 0
    private var bootStallLastKickAtUptime: TimeInterval = 0   // 0 = never
    private var bootStallKicksFired = 0
    /// Uptime of the last NEWNYM handed to the control channel; 0 = never.
    private var lastNewnymAtUptime: TimeInterval = 0
    /// readBackSocksPort has started: the port is being handed out — no kick.
    private var socksReadbackStarted = false

    /// Called from the bootstrap-progress observer (on main) with every PROGRESS.
    /// Only an INCREASE of the highest percent is progress; it re-arms the timer,
    /// and 100 % cancels it.
    private func noteBootstrapProgressForStall(_ progress: Int) {
        guard bootstrapStallKickEnabled, started, !relaunchRequired else { return }
        guard progress > bootStallPctHighest else { return }
        bootStallPctHighest = progress
        bootStallChangedAtUptime = ProcessInfo.processInfo.systemUptime
        armBootStall()
    }

    private func bootStallWaitMs() -> Int64 {
        let now = ProcessInfo.processInfo.systemUptime
        let ms: (TimeInterval) -> Int64 = { Int64(((now - $0) * 1000).rounded(.down)) }
        return TorBootstrapStall.shared.msUntilKick(
            percent: Int32(bootStallPctHighest),
            msSinceProgress: ms(bootStallChangedAtUptime),
            msSinceLastKick: bootStallLastKickAtUptime == 0 ? TorBootstrapStall.shared.NEVER : ms(bootStallLastKickAtUptime),
            msSinceLastNewnym: lastNewnymAtUptime == 0 ? TorBootstrapStall.shared.NEVER : ms(lastNewnymAtUptime),
            kicksFired: Int32(bootStallKicksFired)
        )
    }

    private func armBootStall() {
        disarmBootStall()
        let wait = bootStallWaitMs()
        guard wait != TorBootstrapStall.shared.NO_KICK else { return }
        let item = DispatchWorkItem { [weak self] in
            MainActor.assumeIsolated {
                guard let self else { return }
                self.bootStallItem = nil
                let now = self.bootStallWaitMs()
                if now == TorBootstrapStall.shared.NO_KICK { return }
                if now > 0 { self.armBootStall(); return }
                self.kickStalledBootstrap()
            }
        }
        bootStallItem = item
        DispatchQueue.main.asyncAfter(deadline: .now() + Double(wait) / 1000.0, execute: item)
    }

    private func disarmBootStall() {
        bootStallItem?.cancel()
        bootStallItem = nil
    }

    /// The kick: `SETCONF DisableNetwork=1` then `SETCONF DisableNetwork=0`, two
    /// sequential commands from one main-actor turn. "Fired" = handed to
    /// the control channel (the same contract as requestNewCircuit /
    /// requestHsDescriptorFetch); a channel that is down is a SKIP — not counted,
    /// and not retried until the percent moves (no retry storm).
    private func kickStalledBootstrap() {
        guard bootstrapStallKickEnabled, started, !relaunchRequired else { return }
        // The port is (being) handed out — moving it now would strand the app.
        guard !socksReadbackStarted, state != .connected else { return }
        let percent = bootStallPctHighest
        guard let controller, controller.isConnected else {
            torLog("bootstrap re-kick: control channel down — skipped")
            ConnectionLog.shared.append(
                kind: ConnectionLog.Kind.stall,
                text: TorBootstrapStall.shared.skipLine(percent: Int32(percent)),
                code: ConnectionLog.Code.torBootKickSkip
            )
            return
        }
        // Stamped BEFORE either reply can arrive: the budget is spent the moment
        // the commands are handed to the control channel.
        bootStallKicksFired += 1
        bootStallLastKickAtUptime = ProcessInfo.processInfo.systemUptime
        // Two ordinary commands, back to back from this one main-actor turn;
        // TORController serialises its writes, so they leave in order (Tor may run
        // one main-loop turn with the network disabled in between — harmless).
        // Each handler takes ONE single-line non-650 reply. TORController hands a
        // reply to the NEWEST observer first, so these two may receive each
        // other's reply: the handlers are therefore order-agnostic — ANY refused
        // reply triggers one `DisableNetwork=0` retry, which is a no-op when the
        // network is already enabled (a refused `=1`).
        controller.sendCommand("SETCONF", arguments: ["DisableNetwork=1"], data: nil) { codes, lines, stop in
            guard let code = codes.first?.intValue, code != 650, lines.count == 1 else { return false }
            stop.pointee = true
            torLog("bootstrap re-kick: SETCONF reply -> \(code == 250 ? "250 OK" : "rejected")")
            if code != 250 { hopToMain { TorManager.shared.retryNetworkReEnable() } }
            return true
        }
        controller.sendCommand("SETCONF", arguments: ["DisableNetwork=0"], data: nil) { codes, lines, stop in
            guard let code = codes.first?.intValue, code != 650, lines.count == 1 else { return false }
            stop.pointee = true
            torLog("bootstrap re-kick: SETCONF reply -> \(code == 250 ? "250 OK" : "rejected")")
            // A refused re-enable would leave the network disabled for the rest of
            // this process (no in-process restart on iOS): retry it once.
            if code != 250 { hopToMain { TorManager.shared.retryNetworkReEnable() } }
            return true
        }
        torLog("bootstrap re-kick sent at \(percent)% (\(bootStallKicksFired)/\(Int(TorBootstrapStall.shared.MAX_KICKS)))")
        ConnectionLog.shared.append(
            kind: ConnectionLog.Kind.stall,
            text: TorBootstrapStall.shared.kickLine(percent: Int32(percent), n: Int32(bootStallKicksFired)),
            code: ConnectionLog.Code.torBootKick
        )
        // The second (last) kick needs a fresh STALL_MS with no progress.
        armBootStall()
    }

    /// One retry of `SETCONF DisableNetwork=0` after any refused kick reply (see
    /// kickStalledBootstrap). Idempotent: a no-op when the network is enabled.
    private func retryNetworkReEnable() {
        guard started, let controller, controller.isConnected else { return }
        controller.sendCommand("SETCONF", arguments: ["DisableNetwork=0"], data: nil) { codes, lines, stop in
            guard let code = codes.first?.intValue, code != 650, lines.count == 1 else { return false }
            stop.pointee = true
            torLog("bootstrap re-kick: re-enable retry -> \(code == 250 ? "250 OK" : "rejected")")
            return true
        }
    }

    // MARK: - Private

    /// How often the control socket is probed for existence before the first
    /// connectControlChannel() (P4b). Short enough that a fast bootstrap saves most of the
    /// old fixed 1.0s, long enough that the poll costs a handful of stat() calls.
    private static let controlSocketPollIntervalSec: TimeInterval = 0.2

    /// HARD upper bound on that poll — the same 1.0s the old unconditional sleep used,
    /// so this change can never delay the first connect attempt beyond what shipped.
    /// LOAD-BEARING: at this ceiling connectControlChannel() is called even if the socket
    /// never appeared, because only connectControlChannel()'s own exhaustion branches latch
    /// relaunchRequired (and thus the process self-recovery). See the call site.
    private static let controlSocketPollCeilingSec: TimeInterval = 1.0

    /// P4b: wait for Tor to bind its control socket, then connect — re-arming itself on
    /// the main queue every [controlSocketPollIntervalSec] until either the socket
    /// appears or [controlSocketPollCeilingSec] elapses, whichever comes first. BOTH
    /// outcomes call connectControlChannel(); the fallback is deliberate, not a fallthrough
    /// (see the call site in start()). Exactly one connect happens: every branch here
    /// routes through the one-shot [fireControllerConnect], and a tick that fires never
    /// schedules a successor.
    private func awaitControlSocketThenConnect(socketPath: String, deadline: Date) {
        guard !controllerConnectTriggered else { return }

        if FileManager.default.fileExists(atPath: socketPath) {
            fireControllerConnect(reason: "control socket appeared")
            return
        }

        let remaining = deadline.timeIntervalSinceNow
        guard remaining > 0 else {
            // HARD FALLBACK at the ceiling: connect anyway. If the socket genuinely
            // never comes up, connectControlChannel()'s bounded retries end in
            // stop(discardingState: true) + relaunchRequired, which is what drives the
            // self-recovery relaunch. Never turn this into a give-up.
            fireControllerConnect(
                reason: "control socket still absent after \(TorManager.controlSocketPollCeilingSec)s — connecting anyway (fallback)"
            )
            return
        }

        // Never overshoot the ceiling: the last tick lands exactly on the deadline.
        let nextTick = min(TorManager.controlSocketPollIntervalSec, remaining)
        hopToMain(after: nextTick) { [weak self] in
            self?.awaitControlSocketThenConnect(socketPath: socketPath, deadline: deadline)
        }
    }

    /// One-shot entry into connectControlChannel() for this Tor run — see
    /// [controllerConnectTriggered]. Idempotent, so the poll-success and the
    /// ceiling-fallback branches can never both start a connect chain.
    private func fireControllerConnect(reason: String) {
        guard !controllerConnectTriggered else { return }
        controllerConnectTriggered = true
        torLog("\(reason), connecting controller...")
        connectControlChannel()
    }

    /// Tor's `AUTHENTICATION_COOKIE_LEN` (control_auth.c): control_auth_cookie is
    /// exactly 32 bytes. Any other length is a partial read of a file Tor is still
    /// writing — see the guard in connectControlChannel().
    private static let controlAuthCookieLength = 32

    private func connectControlChannel(attempt: Int = 1) {
        guard let controller else {
            torLog("connectControlChannel: controller is nil — aborting")
            return
        }

        let torDir = TorManager.workingDirPath()
        let files = (try? FileManager.default.contentsOfDirectory(atPath: torDir)) ?? []
        torLog("[attempt \(attempt)/20] tor dir files: \(files.joined(separator: ", "))")

        let controlSocketPath = URL(fileURLWithPath: torDir).appendingPathComponent("cp").path
        let socketExists = FileManager.default.fileExists(atPath: controlSocketPath)
        torLog("[attempt \(attempt)/20] control socket exists: \(socketExists), controller.isConnected: \(controller.isConnected)")

        do {
            if !controller.isConnected {
                try controller.connect()
            }
        } catch {
            if attempt < 20 {
                torLog("[attempt \(attempt)/20] connect failed: \(String(describing: type(of: error))) — retrying in 1s")
                hopToMain(after: 1.0) { [weak self] in
                    self?.connectControlChannel(attempt: attempt + 1)
                }
            } else {
                LogBuffer.shared.append(level: "E", tag: "Tor", message: "giving up after \(attempt) connect attempts")
                // Terminal — the thread exists but its control socket
                // never came up, so this process can never retry start(). Route
                // through stop() so its working dir is wiped + relaunchRequired
                // latched, instead of leaving <Caches>/tor on disk until the next
                // launch.
                // The control channel is DOWN, so no HALT is sent and
                // tor_main keeps running — stop()'s wipe is best-effort only. The
                // live-daemon residue is closed by the armExitWipe() atexit hook when
                // ContentView's self-recycle exit(0)s on the next `.background`.
                stop(discardingState: true)
            }
            return
        }

        torLog("control socket connected on attempt \(attempt)")

        // Authenticate with cookie
        let cookieURL = URL(fileURLWithPath: torDir).appendingPathComponent("control_auth_cookie")
        let cookieExists = FileManager.default.fileExists(atPath: cookieURL.path)
        torLog("cookie file exists: \(cookieExists)")

        // P4a: `Data(contentsOf:)` returns whatever bytes are on disk RIGHT NOW — a
        // cookie caught mid-write, while Tor is still creating its 32-byte
        // control_auth_cookie, reads SHORT and would be sent to AUTHENTICATE as if it
        // were the secret. AUTHENTICATE is one-shot (TORController.authenticateWithData
        // stops observing on the first OK/515 reply) and failing it here is TERMINAL:
        // both auth branches below run stop(discardingState: true), which WIPES the
        // preserved Tor state dir, and an unauthenticated control socket
        // means the HALT it sends is rejected, leaving tor_main un-killable for the rest
        // of the process (the relaunch-required class). So a wrong-length read is NEVER
        // authenticated — it takes EXACTLY the bounded cookie retry below, which is what
        // absorbs the partial-write race (and the earlier connect that P4b now allows).
        let cookieBytes = try? Data(contentsOf: cookieURL)
        guard let cookie = cookieBytes, cookie.count == TorManager.controlAuthCookieLength else {
            let why = cookieBytes.map {
                "wrong length (\($0.count)B, want \(TorManager.controlAuthCookieLength)B — partial write)"
            } ?? "not readable"
            // Bound this retry like the connect-throw branch
            // above. A control socket that opens but never yields a readable cookie
            // otherwise loops here forever, leaving the UI stuck at bootstrapping(0)
            // with no relaunch hint (startRelayCheck only runs after authenticate()).
            if attempt < 20 {
                torLog("[attempt \(attempt)/20] cookie \(why) — retrying in 0.5s")
                hopToMain(after: 0.5) { [weak self] in
                    self?.connectControlChannel(attempt: attempt + 1)
                }
            } else {
                LogBuffer.shared.append(level: "E", tag: "Tor", message: "giving up — cookie \(why) after \(attempt) attempts")
                // Terminal — cookie never became readable, only a
                // relaunch recovers. Wipe the working dir via stop() (also latches
                // relaunchRequired) rather than leaving <Caches>/tor on disk until
                // the next launch.
                // The control channel is connected but we NEVER
                // authenticated (no readable cookie), so stop()'s HALT is rejected
                // server-side and tor_main keeps running — stop()'s wipe is
                // best-effort only. The live-daemon residue is closed by the
                // armExitWipe() atexit hook when ContentView self-recycles (exit(0))
                // on the next `.background`.
                stop(discardingState: true)
            }
            return
        }

        torLog("authenticating with cookie (\(cookie.count) bytes)...")
        // Explicit `completion:` label so Swift binds to the completion-handler
        // overload rather than the auto-imported async form (a bare trailing
        // closure resolves to `authenticate(withData:) async` and errors).
        controller.authenticate(with: cookie, completion: { [weak self] success, error in
            guard let self else { return }
            // Surface the failure instead of leaving state stuck
            // at bootstrapping(0), and GATE ON `success` — error==nil/success==false
            // previously fell through to observeProgress as if authenticated.
            // Both auth-failure exits are TERMINAL for the process (tor_main runs
            // once; there is no re-auth path) — latch relaunchRequired alongside.
            if let error {
                LogBuffer.shared.append(level: "E", tag: "Tor", message: "auth failed: \(String(describing: type(of: error)))")
                // Terminal (tor_main runs once, no re-auth path) — wipe
                // its working dir via stop() (also latches relaunchRequired).
                // Dispatched to main so it runs outside this Tor auth callback.
                // AUTHENTICATE failed, so the HALT stop() sends over the
                // still-connected control socket is REJECTED server-side and tor_main
                // keeps running — stop()'s wipe is best-effort only. The live-daemon
                // residue is closed by the armExitWipe() atexit hook when ContentView
                // self-recycles (exit(0)) on the next `.background`.
                hopToMain { self.stop(discardingState: true) }
                return
            }
            guard success else {
                LogBuffer.shared.append(level: "E", tag: "Tor", message: "auth failed (success=false, no error)")
                // Terminal — same teardown as the auth-error branch
                // above, and likewise UNauthenticated: stop()'s HALT is rejected,
                // tor_main keeps running, and the armExitWipe() atexit hook is what
                // actually clears the live-daemon residue at the exit(0) self-recycle.
                hopToMain { self.stop(discardingState: true) }
                return
            }
            torLog("authenticated successfully, observing bootstrap progress...")
            // Tor has answered on its control port, so tor_main has long since run
            // init_logging(): add_callback_log's mutex assert cannot fire now, and
            // the call is thread-safe under that same mutex from this callback
            // queue. Only the pre-authentication bootstrap lines are missed (the
            // control-event tap covers those as coded ConnectionLog lines).
            TorManager.installTorDaemonLogCallback()
            hopToMain {
                self.observeProgress()
            }
        })
    }

    private func observeProgress() {
        guard controller != nil else {
            torLog("observeProgress: controller is nil")
            return
        }
        // ORDER IS LOAD-BEARING, and the whole post-auth sequence is STRICTLY
        // SERIALIZED: TORController has no command queue — it answers each reply
        // with the observer that was added LAST — so two control commands in
        // flight at once get each other's replies. Every step below therefore
        // waits for the previous one (or its timeout) before sending:
        //   1. GETINFO consensus/valid-after  (directory freshness at start)
        //   2. SETEVENTS <core set> + the persistent raw-650 tap
        //   3. the two original bootstrap observers
        //   4. once the circuit-established readback is answered: SETEVENTS <guard
        //      set = core + ORCONN> then the STARTUP KICK (sendStartupKick);
        //      the 0.75 s timer → armGuardChannelEvents stays as the backstop
        //   5. (later, at .connected) SETEVENTS <full set> — see upgradeToFullEventSet
        queryConsensusAge(attempt: 1) { [weak self] in
            guard let self, let controller = self.controller else { return }
            self.armControlEventTap(on: controller) { [weak self] in
                self?.registerBootstrapObservers()
            }
        }
    }

    /// The LOW-RATE control events subscribed before Tor is connected.
    ///
    /// STATUS_CLIENT is MANDATORY in this list and must stay first-class: Tor's
    /// SETEVENTS REPLACES the whole subscription, so a list without it silently
    /// stops bootstrap progress AND CIRCUIT_ESTABLISHED — i.e. this app's entire
    /// notion of "Tor is up", including the SOCKS port readback — while
    /// everything still looks healthy from the outside.
    /// `nonisolated`: read from inside Tor's own (non-main) reply blocks.
    private nonisolated static let controlEventsCore = [
        "STATUS_CLIENT",     // bootstrap ladder + circuit established/lost + dir info
        "STATUS_GENERAL",    // clock skew / clock jumps (silent onion killers)
        "NETWORK_LIVENESS",  // Tor's own "the network went away"
        // HS_DESC from the FIRST subscription (2026-10-08), not only from the
        // .connected upgrade: the session's first descriptor fetch follows
        // .connected within milliseconds and its REQUESTED/RECEIVED name the HSDir
        // HsDirLedger pins re-fetches to, so it must not race that SETEVENTS. It
        // is NOT chatty pre-connect — no onion request can exist before the SOCKS
        // port is read back at .connected — so it cannot disturb the pre-connect
        // GETINFO observers the staged subscription protects.
        "HS_DESC",
    ]

    /// The core set plus ORCONN, subscribed as soon as the two pre-connect
    /// GETINFOs are out of the way — see armGuardChannelEvents (C2a).
    ///
    /// STATUS_CLIENT is still first-class here for the reason above: SETEVENTS
    /// REPLACES the set, so every stage of this staircase must carry it.
    private nonisolated static let controlEventsGuard = controlEventsCore + [
        "ORCONN",   // the TLS channel to each guard, underneath every circuit
    ]

    /// The guard set plus the CHATTY onion classes, subscribed only once Tor is
    /// connected — see upgradeToFullEventSet for why the split exists.
    private nonisolated static let controlEventsFull = controlEventsGuard + [
        // (HS_DESC — the v3 descriptor fetch — is already in controlEventsCore.)
        "CIRC",     // intro / rendezvous circuits
        // The onion HANDSHAKE (2026-10-06): Tor reports intro sent / acked and
        // rendezvous joined ONLY as CIRC_MINOR PURPOSE_CHANGED — never as a
        // plain CIRC — so without this the timeline could not tell an intro-side
        // stall from a rendezvous-side one. Low-rate, and armed only here, after
        // .connected, like the rest of the chatty onion classes.
        "CIRC_MINOR",
        "STREAM",   // the request itself, riding the rendezvous circuit
        "GUARD",    // entry-guard up/down/dropped
    ]

    /// Upper bound on waiting for the SETEVENTS reply before registering the
    /// bootstrap observers regardless. The arming must NEVER be able to hold up
    /// (or break) the connect: a control channel that does not answer this is
    /// already failing, and connectControlChannel's own terminal branches — not this
    /// wait — are what recover from that.
    private static let eventTapArmTimeoutSec: TimeInterval = 2.0

    /// Same bound for the consensus-age question (step 1 of the chain).
    private static let consensusQueryTimeoutSec: TimeInterval = 2.0

    /// Tor answers `552 Unrecognized key` for `consensus/valid-after` until it
    /// has actually loaded a consensus, which a COLD daemon has not yet done at
    /// authentication time. One retry, late enough to have one by then.
    private static let consensusRetryDelaySec: TimeInterval = 5.0

    /// Asks Tor how old the consensus it is using is, and narrates the BUCKET
    /// (never the timestamp) as a single TOR line.
    ///
    /// WHY (2026-09-14): a production connect bootstrapped in 0.5 s off preserved
    /// state and then spent 155 s failing to reach the onion. A warm daemon with
    /// a STALE directory looks exactly like a healthy warm one in every other
    /// signal the panel has, so the age is the thing that separates those two
    /// stories on a real user's device.
    ///
    /// Runs FIRST in the post-auth chain, while no other control command is in
    /// flight — see observeProgress. [next] is called exactly once, on the answer
    /// or on [consensusQueryTimeoutSec], and never depends on the answer being
    /// good: this question must not be able to delay the connect.
    private func queryConsensusAge(attempt: Int, then next: @escaping () -> Void) {
        guard let controller, controller.isConnected else {
            next()
            return
        }
        var settled = false
        let finish: ([String]?) -> Void = { values in
            DispatchQueue.main.async { [weak self] in
                guard !settled else { return }
                settled = true
                self?.noteConsensusAge(values?.first, attempt: attempt)
                next()
            }
        }
        controller.getInfoForKeys(["consensus/valid-after"]) { values in finish(values) }
        DispatchQueue.main.asyncAfter(deadline: .now() + TorManager.consensusQueryTimeoutSec) {
            finish(nil)
        }
    }

    /// Emits the consensus-age line, or schedules the single retry. Exactly one
    /// line reaches the panel per process: the age if either attempt reads it,
    /// "unknown" if neither does.
    private func noteConsensusAge(_ raw: String?, attempt: Int) {
        let now = Int(Date().timeIntervalSince1970)
        if let raw, let line = TorControlEventParser.consensusAgeLine(validAfter: raw, nowEpochSeconds: now) {
            torLog("consensus age read on attempt \(attempt)")
            TorControlEventTap.shared.emit(line)
            return
        }
        guard attempt == 1 else {
            torLog("consensus age unavailable after the retry — narrating unknown")
            TorControlEventTap.shared.emit(TorControlEventParser.consensusAgeUnknownLine())
            return
        }
        // 552 / no answer: a cold daemon has no consensus yet. Retry once, and
        // do NOT block anything on it — the chain has already moved on.
        hopToMain(after: TorManager.consensusRetryDelaySec) { [weak self] in
            self?.queryConsensusAge(attempt: 2, then: {})
        }
    }

    /// Subscribes to [controlEventsCore] and installs a PERSISTENT raw-`650`
    /// observer that feeds `TorControlEventTap`, then hands control to [next] on
    /// the main queue. Armed once per Tor run, right after the controller
    /// authenticates, and it lives until stop() drops the controller.
    ///
    /// WHY IT IS A RAW OBSERVER AND NOT addObserverForStatusEvents: the two
    /// existing observers only ever see STATUS_* events, and BOTH are removed the
    /// moment CIRCUIT_ESTABLISHED arrives (see registerBootstrapObservers) —
    /// deliberately, so nothing keeps updating the bootstrap percent or re-reads
    /// the SOCKS port afterwards. Everything this change exists to show (HSDir
    /// descriptor fetch → intro → rendezvous → first stream) happens AFTER that
    /// point, so the panel needs a tap that outlives them. That removal stays
    /// exactly as it was; this tap is additive and has no side effects beyond
    /// appending log lines.
    ///
    /// WHY THE ORDER MATTERS: `addObserverForCircuitEstablished` issues its own
    /// `SETEVENTS STATUS_CLIENT` unless the controller already knows STATUS_CLIENT
    /// is subscribed, and SETEVENTS replaces the whole set — so registering it
    /// before this would leave a live daemon publishing nothing but STATUS_CLIENT.
    /// Going through `listenForEvents` (rather than only the raw sendCommand) is
    /// what updates that bookkeeping, which is why both are sent here.
    ///
    /// FAILURE IS NEVER FATAL: any failure or silence ends in one SYSTEM line and
    /// the ordinary observer registration, where the controller re-subscribes
    /// STATUS_CLIENT by itself. The panel loses the onion-phase lines; the app
    /// connects exactly as before.
    private func armControlEventTap(on controller: TorController, then next: @escaping () -> Void) {
        var settled = false
        // Whether the SUBSCRIPTION itself took (as opposed to the tap install
        // being confirmed): a subscribed daemon still feeds the panel, so the
        // timeout below must not claim otherwise. Written and read on main only.
        var subscribed = false
        let noteSubscribed: () -> Void = { DispatchQueue.main.async { subscribed = true } }
        let proceed: (Bool) -> Void = { armed in
            DispatchQueue.main.async {
                guard !settled else { return }
                settled = true
                if !armed {
                    torLog("control event tap: SETEVENTS unconfirmed — continuing without the onion-phase lines")
                    ConnectionLog.shared.append(
                        kind: ConnectionLog.Kind.system,
                        text: "control events unavailable"
                    )
                }
                next()
            }
        }

        // `TorController` is not Sendable but the reply block below is, so the
        // controller travels in an explicit box. Safe by construction: the only
        // thing that block does with it is sendCommand, which just writes to the
        // control channel and hands the observer to the controller's own serial
        // control queue — the exact call TORController itself makes from its
        // reply callbacks (getInfoForKeys, resetConnection).
        let boxed = UncheckedBox(controller)

        // Explicit `completion:` label so Swift binds to the completion-handler
        // overload rather than the auto-imported async form (same reason as
        // authenticate(with:completion:) above).
        controller.listen(forEvents: TorManager.controlEventsCore, completion: { success, _ in
            guard success else {
                proceed(false)
                return
            }
            // Re-send the SAME set through the raw command purely to get a
            // PERSISTENT observer into the controller's block list: it keeps the
            // observer until the block sets `stop`, and every 650 reply is
            // dispatched to it. The block never sets `stop` and always returns
            // false, so it stays for the life of the controller and never
            // consumes an event the status observers still need — including the
            // command replies it is deliberately transparent to.
            boxed.value.sendCommand("SETEVENTS", arguments: TorManager.controlEventsCore, data: nil) { codes, lines, _ in
                guard let first = lines.first,
                      let text = String(data: first, encoding: .utf8) else { return false }
                if codes.first?.intValue == 650 {
                    TorControlEventTap.shared.handle(replyLine: text)
                } else {
                    // The `250 OK` for THIS command: the raw form has no
                    // completion handler, and this is the only signal that the
                    // tap is installed and nothing is left in flight — which is
                    // what makes it safe to register the bootstrap observers
                    // (whose own GETINFO must not race a pending reply).
                    proceed(true)
                }
                return false
            }
            torLog("control event tap armed")
            noteSubscribed()
        })

        // Backstop: never let a silent control channel hold the bootstrap
        // observers. `subscribed` keeps the SYSTEM line honest — if SETEVENTS
        // itself succeeded and only the tap's own reply went missing, events are
        // still flowing and the panel is not "unavailable".
        DispatchQueue.main.asyncAfter(deadline: .now() + TorManager.eventTapArmTimeoutSec) {
            proceed(subscribed)
        }
    }

    /// The two ORIGINAL status observers: bootstrap percent and
    /// circuit-established (which also reads the SOCKS port back and publishes
    /// `.connected`). Unchanged except for the ConnectionLog tags — only the call
    /// site moved, behind the event-tap arming above.
    private func registerBootstrapObservers() {
        guard let controller else {
            torLog("registerBootstrapObservers: controller is nil")
            return
        }

        torLog("registering bootstrap progress observer...")

        progressObserver = controller.addObserver(forStatusEvents: {
            [weak self] (type, severity, action, arguments) -> Bool in
            #if DEBUG
            let summary = arguments?.map { "\($0.key)=\($0.value)" }.joined(separator: " ") ?? "none"
            #else
            let summary = ""
            #endif
            if let progressStr = arguments?["PROGRESS"],
               let progress = Int(progressStr) {
                let tag = arguments?["TAG"] ?? ""
                let summaryText = arguments?["SUMMARY"] ?? ""
                hopToMain {
                    self?.state = .bootstrapping(progress: progress)
                    // HIGHEST, not latest: Tor's bootstrap percent can step
                    // backwards (a failed guard/consensus attempt re-reports an
                    // earlier phase), and the self-heal's shape gate asks "how far
                    // did this daemon ever get", not "where did it happen to be
                    // when the user left". RAM only — persisted at most once, at
                    // teardown, and only for a run that actually scored a failure.
                    if let self = self, progress > self.highestBootstrapPercent {
                        self.highestBootstrapPercent = progress
                    }
                    // Bootstrap-stall rung: every PROGRESS (TAG and SUMMARY are
                    // not read). Android sibling: TorManager.noteBootstrapProgressForStall.
                    self?.noteBootstrapProgressForStall(progress)
                    // tag only in the LogBuffer line; SUMMARY prose is free text (may carry
                    // relay addresses) so it stays os_log-only in DEBUG.
                    torLog("bootstrap \(progress)% — \(tag)")
                    torLogLocal("bootstrap summary: \(summaryText)")
                    // Live connection-log panel (ConnectionLog.kt, commonMain —
                    // Android sibling: TorManager.kt's `Bootstrapped N%` parse).
                    // TAG only: it is a token from Tor's own fixed bootstrap
                    // ladder, while SUMMARY is free prose that a future Tor could
                    // widen (it already interpolates relay addresses in some
                    // builds) — so the panel keeps the phase name and the percent,
                    // and the prose stays in the DEBUG-gated torLog above.
                    // The CODE is the mapped phase GROUP (C2b): every bootstrap
                    // line used to carry the single `torBootstrapTag`, so a
                    // 70-125 s stall inside the bootstrap was unattributable in
                    // the connect timeline, where only the code travels. The
                    // table is `TorBootstrapPhase` in commonMain — the SAME one
                    // Android's log-tail producer calls, so the two platforms
                    // cannot drift — and an unknown tag keeps the old catch-all.
                    ConnectionLog.shared.append(
                        kind: ConnectionLog.Kind.tor,
                        text: "bootstrap \(progress)% \(tag)",
                        code: TorBootstrapPhase.shared.codeFor(tag: tag)
                    )
                }
                return true
            }
            // type/severity/action only reach LogBuffer (uploaded under Debug mode).
            // The KEY=VALUE args (CLOCK_SKEW SKEW=, SOURCE=, ...) are a per-device
            // quasi-identifier channel: os_log, DEBUG builds only.
            torLog("status event: type=\(type) severity=\(severity) action=\(action)")
            torLogLocal("status event args: \(summary)")
            return false
        })

        torLog("registering circuit established observer...")

        circuitObserver = controller.addObserver(forCircuitEstablished: {
            [weak self] established in
            torLog("circuit callback: established=\(established)")
            if !established {
                // The registration-time `status/circuit-established` readback has been
                // answered, so the control channel is quiet: fire the startup kick
                // (once per process — see sendStartupKick).
                hopToMain { self?.sendStartupKick() }
            }
            if established {
                // Through the tap's emitter, NOT straight to ConnectionLog: the
                // raw-650 tap narrates STATUS_CLIENT CIRCUIT_ESTABLISHED with the
                // same phrase and the same code, and this callback ALSO fires from
                // the registration-time `status/circuit-established` readback — the
                // shared de-dupe window is what keeps the panel at one line.
                TorControlEventTap.shared.emit(
                    TorLogLine(kind: .tor, text: "circuit established", code: .circuitOk)
                )
            }
            guard let self, established else { return }
            // With `SocksPort auto`, Tor chose the port — ask the control port
            // for the ACTUAL listener (net/listeners/socks) instead of trusting a
            // pre-chosen constant. This is the port MessageManager will dial, so it
            // must be Tor's real, freshly-bound listener. If the readback fails we
            // stay disconnected rather than publishing a bogus/guessed port.
            hopToMain { self.readBackSocksPort() }
            if let po = self.progressObserver {
                controller.removeObserver(po)
                self.progressObserver = nil
            }
            if let co = self.circuitObserver {
                controller.removeObserver(co)
                self.circuitObserver = nil
            }
        })

        // Stage 2 of the event staircase: widen to ORCONN now that both
        // observers (and the GETINFO the circuit-established one issues at
        // registration) have been sent. See armGuardChannelEvents.
        hopToMain(after: TorManager.guardChannelEventDelaySec) { [weak self] in
            self?.armGuardChannelEvents()
        }
    }

    /// How long after the bootstrap observers are registered ORCONN is added to
    /// the subscription. Not a tuning knob: it exists to let the GETINFO that
    /// `addObserverForCircuitEstablished` issues at registration time
    /// (`status/circuit-established`, vendored and NOT retryable — an empty
    /// answer REMOVES the observer and the session then never connects) settle
    /// on a quiet control channel first. A local AF_UNIX round trip is
    /// sub-millisecond; three quarters of a second is three orders of magnitude
    /// of margin, and the phase this buys visibility into lasts 45 s+.
    private static let guardChannelEventDelaySec: TimeInterval = 0.75

    /// Subscribes to [controlEventsGuard] — the core set PLUS ORCONN — while Tor
    /// is still bootstrapping.
    ///
    /// WHY: ORCONN was already in [controlEventsFull], but that set is armed only
    /// once Tor reports connected, i.e. strictly AFTER the phase the iOS cold
    /// tail actually stalls in (cold Tor → first circuit p90 139.5 s, and the
    /// slow timelines stall before ENOUGH_DIR_INFO). Android's event reader
    /// subscribes ORCONN from the moment the SOCKS listener line appears —
    /// mid-bootstrap — so the guard-channel phase was visible there and invisible
    /// here, which is exactly backwards given where the two tails sit. A
    /// LAUNCHED with no CONNECTED after it is the signature of a stalled channel
    /// to a relay, and it is visible in no other event family.
    ///
    /// WHY NOT SIMPLY IN THE CORE SET: the core set is armed BEFORE two GETINFOs
    /// the connect cannot lose (the consensus-age question and, more seriously,
    /// the un-retryable one inside `addObserverForCircuitEstablished`), and every
    /// subscribed class widens the window in which a stray async `650` is handed
    /// to a pending GETINFO's observer instead — see socksReadbackAttempts. This
    /// staircase keeps both of those on the narrowest subscription this app has
    /// ever run them on, and pays 0.75 s for it.
    ///
    /// STATUS_CLIENT stays in the list: SETEVENTS REPLACES the subscription, and
    /// a set without it kills bootstrap progress and CIRCUIT_ESTABLISHED.
    /// Failure is never fatal — the panel loses the ORCONN lines, nothing else.
    private func armGuardChannelEvents() {
        guard !guardEventSetArmed, !fullEventSetArmed,
              let controller, controller.isConnected else { return }
        guardEventSetArmed = true
        controller.listen(forEvents: TorManager.controlEventsGuard, completion: { success, _ in
            torLog("control event tap: guard-channel set \(success ? "armed" : "REFUSED — or-connection lines unavailable")")
        })
    }

    private var guardEventSetArmed = false

    /// STARTUP KICK (2026-10-26, connect-time lever): one no-op
    /// `SETCONF DisableNetwork=0` as soon as the post-auth control sequence is quiet.
    ///
    /// WHY: Tor arms a fixed ONE-SECOND timer when it enters its main loop and runs
    /// none of its periodic events before it fires — including the one that builds
    /// the first circuit (`mainloop.c` `initialize_periodic_events_cb`, annotated by
    /// Tor itself "for backward-compatibility reasons; it might not actually be
    /// necessary"). Any successful SETCONF rescans the periodic events at once
    /// (`config.c` `set_options` → `periodic_events_on_new_options` →
    /// `periodic_event_enable` → `mainloop_event_activate`), so re-asserting the
    /// already-enabled network launches the first guard connection within
    /// milliseconds instead of ~1.05 s later. Prod debug sessions showed a flat
    /// 1.04–1.09 s between "authenticated successfully" and the first "or
    /// connection launched" in 10/10 iOS cold starts; the same on Android.
    ///
    /// SAFE: the value does not change, so no guard or circuit reset and no SOCKS
    /// rebind (Tor Browser sends the same command right after auth). Fail-safe: a
    /// refused or lost reply leaves Tor's own timer to fire as before.
    ///
    /// ORDER: TORController has no command queue, so this runs only after the
    /// readback GETINFO inside `addObserverForCircuitEstablished` has been answered
    /// (the `established=false` callback). ORCONN is armed FIRST — the kick launches
    /// the guard connection at once and the panel's "or connection launched" line
    /// needs the guard set live — and the SETCONF goes out from that SETEVENTS'
    /// completion. The 0.75 s timer in registerBootstrapObservers stays as the
    /// backstop for a kick that never fires (armGuardChannelEvents is idempotent).
    private var startupKickSent = false

    private func sendStartupKick() {
        guard !startupKickSent, started, !relaunchRequired, !socksReadbackStarted,
              state != .connected, let controller, controller.isConnected else { return }
        startupKickSent = true
        // Boxed for the @Sendable closure below; sendCommand reply blocks run on
        // TorController's private queue, never on the main actor.
        let boxed = UncheckedBox(controller)
        let sendKick: @Sendable () -> Void = {
            boxed.value.sendCommand("SETCONF", arguments: ["DisableNetwork=0"], data: nil) { codes, lines, stop in
                guard let code = codes.first?.intValue, code != 650, lines.count == 1 else { return false }
                stop.pointee = true
                torLog("startup kick: SETCONF DisableNetwork=0 -> \(code == 250 ? "250 OK" : "rejected")")
                return true
            }
        }
        if guardEventSetArmed || fullEventSetArmed {
            sendKick()
            return
        }
        guardEventSetArmed = true
        controller.listen(forEvents: TorManager.controlEventsGuard, completion: { success, _ in
            torLog("control event tap: guard-channel set \(success ? "armed" : "REFUSED — or-connection lines unavailable")")
            sendKick()
        })
    }

    /// How many times the SOCKS-listener readback is attempted before the
    /// terminal teardown, and how long between tries.
    ///
    /// RETRIES EXIST BECAUSE OF A VENDORED-CONTROLLER RACE, not because Tor is
    /// flaky: TORController hands each complete reply to the NEWEST observer
    /// first, and `getInfoForKeys`' observer accepts whatever arrives — including
    /// an async `650` event that lands between our GETINFO and Tor's answer. That
    /// observer then reports an EMPTY value set and removes itself. One stray
    /// event therefore used to read as "Tor has no SOCKS listener" and took the
    /// TERMINAL branch below (daemon torn down, working dir wiped,
    /// relaunch-required latched) on a perfectly healthy daemon. Subscribing to
    /// more event classes for the connection log makes that window matter more,
    /// so the readback is now retried instead of trusted first-shot. The real
    /// failure — a daemon with no listener — simply fails all three.
    /// `nonisolated`: read from inside Tor's own (non-main) reply blocks.
    private nonisolated static let socksReadbackAttempts = 3
    private nonisolated static let socksReadbackRetryDelaySec: TimeInterval = 0.25

    /// Reads Tor's REAL SOCKS listener back over the authenticated control socket
    /// and publishes `.connected`. See [socksReadbackAttempts] for the retry.
    private func readBackSocksPort(attempt: Int = 1) {
        // From here the port is being handed out: the bootstrap-stall kick (which
        // re-binds the SOCKS listener) is refused for the rest of the process.
        socksReadbackStarted = true
        disarmBootStall()
        guard let controller, controller.isConnected else {
            torLog("SOCKS listener readback: control channel down — staying disconnected")
            stop(discardingState: true)
            return
        }
        controller.getInfoForKeys(["net/listeners/socks"]) { values in
            let parsed = values.first.flatMap { TorManager.parseSocksListenerPort($0) }
            hopToMain { [weak self] in
                guard let self else { return }
                guard let port = parsed, port > 0 else {
                    if attempt < TorManager.socksReadbackAttempts {
                        torLog("SOCKS listener readback empty on attempt \(attempt)/\(TorManager.socksReadbackAttempts) (values=\(values)) — retrying")
                        hopToMain(after: TorManager.socksReadbackRetryDelaySec) { [weak self] in
                            self?.readBackSocksPort(attempt: attempt + 1)
                        }
                        return
                    }
                    torLog("FAILED to read SOCKS listener port from control port (values=\(values)) — staying disconnected")
                    // Terminal — the readback failed and start()
                    // can't run again. Tear the (bootstrapped) daemon down + wipe
                    // its working dir via stop(); it sends HALT over the still-
                    // connected control socket so tor_main exits cleanly and the
                    // wipe sticks, and latches relaunchRequired. stop() also
                    // removes the observers (already removed synchronously by the
                    // circuit callback). This block is dispatched to main, so
                    // stop() runs outside the Tor callback.
                    // UNLIKE the connect/cookie/auth-failure branches,
                    // this path is reached only AFTER a successful authenticate(),
                    // so the control connection is authenticated and HALT is
                    // genuinely honoured here — tor_main does stop. (The
                    // armExitWipe() atexit backstop still covers it regardless.)
                    self.stop(discardingState: true)
                    return
                }
                self.socksPort = port
                // Several onion addresses (2026-10-23): begin the descriptor race
                // BEFORE publishing .connected, so the pre-unlock warm-up (armed by
                // that publication) always finds it begun and waits for its winner.
                // HS_DESC is in the FIRST SETEVENTS (controlEventsCore), so no
                // RECEIVED can be missed. No-op for a single address.
                self.startRelayAddressRace()
                self.state = .connected
                // Break the cross-launch failure streak HERE (see
                // noteBootstrapConnected): a force-quit right after a healthy
                // connect must not carry a stale streak into the next launch.
                // Writes nothing when the streak is already 0.
                self.noteBootstrapConnected()
                torLog("CONNECTED — SOCKS5 on port \(port)")
                ConnectionLog.shared.append(
                    kind: ConnectionLog.Kind.tor,
                    text: "connected - SOCKS5 listener on port \(port)",
                    code: ConnectionLog.Code.socksReady
                )
                // No connect haptic — the ring going solid is the only signal needed.
                // Only NOW widen the event subscription to the chatty classes —
                // see upgradeToFullEventSet.
                self.upgradeToFullEventSet()
            }
        }
    }

    /// One-shot: widens the control-event subscription from the guard set to
    /// [controlEventsFull] once Tor is connected.
    ///
    /// WHY IT IS STAGED. The onion-phase classes (HS_DESC / CIRC / CIRC_MINOR /
    /// STREAM / GUARD) are CHATTY — dozens of events while circuits are being built — and
    /// every async event that lands while one of the vendored controller's
    /// `getInfoForKeys` observers is pending answers that GETINFO with an empty
    /// value set (see socksReadbackAttempts). Two of those GETINFOs sit on the
    /// critical pre-connect path, and one of them lives INSIDE
    /// `addObserverForCircuitEstablished` (vendored, not ours to retry) where an
    /// empty answer REMOVES the circuit-established observer — a session that
    /// then never connects at all. Keeping the pre-connect subscription at the
    /// low-rate classes holds that risk near what it has always been, and there
    /// is nothing onion-shaped to narrate before Tor is connected anyway: the
    /// rendezvous work (descriptor → intro → rendezvous → stream) all happens
    /// after this point, which is exactly the phase this tap exists to show.
    /// (ORCONN is the one exception, added mid-bootstrap by
    /// armGuardChannelEvents — the guard channel is precisely what the cold
    /// pre-connect stall is made of, and it is low-rate.)
    private func upgradeToFullEventSet() {
        guard !fullEventSetArmed, let controller, controller.isConnected else { return }
        fullEventSetArmed = true
        controller.listen(forEvents: TorManager.controlEventsFull, completion: { success, _ in
            torLog("control event tap: full event set \(success ? "armed" : "REFUSED — onion-phase lines unavailable")")
        })
    }

    private var fullEventSetArmed = false

    /// Parse the port out of a Tor `net/listeners/socks` GETINFO value, e.g.
    /// `"127.0.0.1:52384"` (optionally quoted, and possibly several
    /// space-separated listeners including an IPv6 one). Prefer the 127.0.0.1
    /// listener — that is the only address MessageManager dials.
    // `nonisolated`: a pure parser (no actor state) so the Tor control-port callbacks —
    // which run OFF the main actor — can call it without the main-actor-isolation warning
    // that TorManager being @MainActor otherwise imposes on its static members.
    nonisolated static func parseSocksListenerPort(_ raw: String) -> UInt16? {
        let cleaned = raw.replacingOccurrences(of: "\"", with: "")
        for token in cleaned.split(separator: " ") {
            let s = String(token)
            if let r = s.range(of: "127.0.0.1:"),
               let p = UInt16(s[r.upperBound...]) {
                return p
            }
        }
        // Fallback: take the port after the LAST colon of the first token
        // (covers an unexpected single-listener format without a 127.0.0.1 prefix).
        if let first = cleaned.split(separator: " ").first,
           let portStr = first.split(separator: ":").last,
           let p = UInt16(portStr) {
            return p
        }
        return nil
    }

}

// MARK: - Tor Connection State

/// The published Tor state. No `failed` case (Android's ConnectionState has one):
/// terminal failure on iOS is the separate `relaunchRequired` latch plus
/// `.disconnected`, and the SOCKS port is the separate `@Published socksPort`.
enum TorConnectionState: Equatable {
    case disconnected
    case bootstrapping(progress: Int)  // 0–100
    case connected
}

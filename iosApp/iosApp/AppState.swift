import SwiftUI
import UIKit
import UserNotifications
import Combine
import Darwin
import Network
@preconcurrency import shared

// ---------------------------------------------------------------------------
// AppState — ObservableObject that owns the Kotlin IosAppController.
//
// A single instance is created in RunApp and injected into the SwiftUI
// environment. All screens read vault and messaging state from here.
//
// Tor integration:
//   • TorManager.shared owns the embedded Tor daemon lifecycle.
//   • AppState observes TorManager.state and forwards it to the UI.
//   • When Tor reaches .connected, the SOCKS port is passed to
//     IosAppController.connectTor() which creates a proxied MessageManager.
// ---------------------------------------------------------------------------

/// Hop from a foreign thread (Kotlin callback, Tor control queue, Network.framework)
/// onto the main actor. Literally `DispatchQueue.main.async { MainActor.assumeIsolated(body) }`:
/// same queue ordering as a plain main-queue hop (so it stays ordered with the
/// Combine `.receive(on: DispatchQueue.main)` sinks), plus a runtime check that the
/// body really runs on the main actor. Do NOT swap for `Task { @MainActor in }`,
/// which reorders relative to those sinks.
func hopToMain(_ body: @escaping @MainActor () -> Void) {
    DispatchQueue.main.async { MainActor.assumeIsolated(body) }
}

/// `hopToMain` after [delay] seconds (`DispatchQueue.main.asyncAfter`).
func hopToMain(after delay: TimeInterval, _ body: @escaping @MainActor () -> Void) {
    DispatchQueue.main.asyncAfter(deadline: .now() + delay) { MainActor.assumeIsolated(body) }
}

/// Outcome of a PIN-change attempt, mapped from the shared module's string code.
enum ChangePinOutcome {
    case success
    case wrongCurrent   // current PIN didn't unlock either vault
}

/// Opt-in push (docs/RELAY_SPEC.md). Plain UserDefaults key — like
/// EulaConsent, this is a UI/consent preference, not vault key material.
/// LEGACY key — no longer read by `pushEnabled`, kept only as the one-time
/// forward-fold migration source into `NotifLevelPreference` below (the fold is
/// Kotlin's `IosAppController.foldLegacyPushPreference`, read by `pushEnabled`'s
/// getter) and as the still-live UserDefaults key that
/// `setPushEnabled`/`clearWipeResidue` also touch.
enum PushPreference {
    static let storageKey = "push_tier2_enabled"
}

/// `pushEnabled`'s real backing store: a Swift-side mirror of the shared
/// `NotificationLevel`/`NotificationLevelStore` model (commonMain, key
/// `"notif_level"`; `com.vg.run.NotificationLevel` / `NotificationLevelStore`
/// in `shared/src/commonMain/kotlin/com/vg/run/NotificationLevel.kt`).
///
/// Reads go through Kotlin (`IosAppController.foldLegacyPushPreference`, the
/// one copy of the legacy fold); the Settings switch still WRITES the level here
/// via plain UserDefaults (`persistNotifLevel`). The key (`"notif_level"`) and the
/// values (`"off"` / `"vendor_push"`) are identical to
/// `NotificationLevel.storageValue` / `NotificationLevelStore.KEY`, so both sides
/// read the same entry.
enum NotifLevelPreference {
    static let storageKey = "notif_level"
    static let vendorPush = "vendor_push"
    static let off = "off"
}

/// "A Settings opt-out's relay-side `DELETE /inbox/{id}/push` has not been
/// confirmed for every inbound-text inbox yet" (2026-08-11 — proven on
/// hardware: a single best-effort DELETE died on a slow Tor circuit, the
/// result was swallowed, and the relay kept dispatching contentless wakes for
/// an opted-out device forever). Armed BEFORE the first DELETE attempt of the
/// opt-out path (`unregisterCurrentInboxesBestEffort(retryingForOptOut:
/// true)`); cleared only once a full pass succeeds for EVERY ref — in-session,
/// or by `sweepPendingPushDeregistrationIfNeeded` on a later session's
/// control-poll cadence — and only by a pass that is still the NEWEST opt-out
/// (`pushDeregGeneration` — two ladders can overlap, and an older one must
/// never disarm what a newer one armed). A BARE BOOLEAN by design (2026-07-30 — the
/// change that deleted Android's (inboxId, readCap) cap mirror): never inbox
/// ids or read capabilities outside the vault; the sweep re-enumerates
/// `allInboundTextInboxes` from the OPEN vault instead. The wipe paths never
/// arm it (a wiped install has no vault left for the sweep to enumerate) and
/// `clearWipeResidue()` removes it. Mirrors Android
/// `SecurePrefs."push_dereg_pending"`.
enum PushDeregPending {
    static let storageKey = "pushDeregPending"
}

/// LEGACY plaintext UserDefaults store for the privacy-respecting in-app
/// store-review nudge (`ReviewPromptPolicy.kt` in commonMain — the single
/// pure decision function BOTH platforms call directly, same idiom as
/// `BuildFlagsKt.assertKdfBuildIntegrity` in RunApp.swift). These
/// counters now live in the encrypted
/// vault's `_meta` singleton (`ReviewPromptPolicyKt.readReviewPromptState` /
/// `recordReviewPromptUnlock` / `markReviewPromptShown`, same `review_prompt_v1`
/// packed-string shape `UpdateNudge.kt` already uses for `update_nudge_v1`) —
/// an AFU (filesystem-image) extraction could previously read the first-unlock
/// wall-clock timestamp and the total unlock count straight off disk, no vault
/// credential needed. What remains in THIS enum exists ONLY to migrate an
/// existing pre-fix install's history into the vault once, on its first
/// unlock after upgrading — see `recordUnlock(vault:)` below. `clearWipeResidue()`
/// still deletes these three keys on every wipe path too (defense in depth for
/// an install that is wiped before ever unlocking again post-upgrade). Mirrors
/// Android `SecurePrefs`' LEGACY `review_*` keys (RunViewModel.kt / SecurePrefs.kt).
enum ReviewPromptStore {
    static let firstUnlockAtKey = "reviewFirstUnlockAt"
    static let unlockCountKey = "reviewUnlockCount"
    static let promptedKey = "reviewPrompted"

    /// Legacy snapshot — a fresh (or already-migrated) install reads
    /// (nil, 0, false). Used ONLY as [recordUnlock]'s migration fallback.
    private static func readLegacy() -> (firstUnlockAt: Int64?, unlockCount: Int32, alreadyPrompted: Bool) {
        let defaults = UserDefaults.standard
        let firstUnlockAt: Int64? = defaults.object(forKey: firstUnlockAtKey) != nil
            ? Int64(defaults.integer(forKey: firstUnlockAtKey))
            : nil
        return (
            firstUnlockAt,
            Int32(defaults.integer(forKey: unlockCountKey)),
            defaults.bool(forKey: promptedKey)
        )
    }

    /// Deletes only the three legacy keys — `removeObject` on an absent key is
    /// a no-op, so this is safe to call unconditionally. Only called from
    /// [recordUnlock] AFTER the vault write is confirmed to have landed —
    /// never delete unread-back state.
    private static func clearLegacy() {
        let defaults = UserDefaults.standard
        defaults.removeObject(forKey: firstUnlockAtKey)
        defaults.removeObject(forKey: unlockCountKey)
        defaults.removeObject(forKey: promptedKey)
    }

    /// Called once per successful unlock ([AppState.unlock] /
    /// [AppState.recoverWithCode]) — folds an existing pre-fix legacy snapshot
    /// in exactly once (`ReviewPromptPolicyKt.recordReviewPromptUnlock` only
    /// consults [legacyFallback] when the vault has no `review_prompt_v1` row
    /// yet, so an upgrading install's real history is preserved rather than
    /// restarted), persists the updated counters into the vault's `_meta`
    /// singleton, and deletes the legacy UserDefaults keys ONLY once that
    /// vault write is CONFIRMED to have landed (the `Bool` return).
    static func recordUnlock(vault: VaultDatabase) {
        let legacy = readLegacy()
        let legacyState = ReviewPromptVaultState(
            firstUnlockAt: legacy.firstUnlockAt.map { KotlinLong(value: $0) },
            unlockCount: legacy.unlockCount,
            alreadyPrompted: legacy.alreadyPrompted
        )
        let wrote = ReviewPromptPolicyKt.recordReviewPromptUnlock(
            vault: vault,
            now: Int64(Date().timeIntervalSince1970 * 1000),
            legacyFallback: legacyState
        )
        if wrote {
            clearLegacy()
        }
    }
}

/// Opt-out relay-DELETE retry schedule: 4 total attempts, ~5/15/45 s between
/// them, per still-failing inbox, extended after a network restore by up to
/// `PushRegistration.DEREG_RESTORE_GRACE_MS` (shared). File-scope (not AppState statics) so the
/// detached retry task reads them with no actor hop. Mirror of Android
/// `RunViewModel.PUSH_DEREG_MAX_ATTEMPTS`/`PUSH_DEREG_BACKOFF_MS` — keep the
/// two schedules identical.
private let pushDeregMaxAttempts = 4
private let pushDeregBackoffSeconds: [UInt64] = [5, 15, 45]
/// Per retry: how long the opt-out ladder waits for a transport that is
/// momentarily absent before deferring to the sweep. Mirror of Android
/// `RunViewModel.PUSH_DEREG_TRANSPORT_WAIT_MS` (16c01dcd).
private let pushDeregTransportWaitSeconds = 60

/// The opt-out ladder's backoff, ended early when [epoch] moves off [sinceEpoch]
/// (a network-restore kick, 2026-10-25). Sliced sleep so the wake lands within
/// ~0.25 s. Returns true iff woken. Android sibling:
/// `PushRegistration.awaitBackoffOrWake`.
private func awaitDeregBackoffOrRestore(seconds: UInt64, sinceEpoch: Int, epoch: () async -> Int) async -> Bool {
    if await epoch() != sinceEpoch { return true }
    let deadline = ProcessInfo.processInfo.systemUptime + Double(seconds)
    while true {
        let left = deadline - ProcessInfo.processInfo.systemUptime
        if left <= 0 { return false }
        try? await Task.sleep(nanoseconds: UInt64(min(0.25, left) * 1_000_000_000))
        if await epoch() != sinceEpoch { return true }
    }
}

/// Tri-state result of an unlock attempt, mirroring IosAppController's
/// UNLOCK_* codes (Kotlin Int). The distinction is security-load-bearing: only
/// `.denied` is a wrong-PIN guess that counts toward the brute-force budget /
/// emergency wipe. `.error` is a transient open failure on a CORRECT PIN (or an
/// attempt that couldn't be evaluated) and MUST be retried without counting —
/// otherwise transient I/O can wipe real data.
/// Mirrors IosAppController's UNLOCK_* codes (companion); pinned by UnlockCodeParitySourceTest.
enum UnlockOutcome: Int {
    case opened = 0
    case denied = 1
    case error  = 2
    /// Correct credential, but the Secure Enclave key that wraps the DB key is
    /// permanently gone (removing the device passcode purges it). Never counts
    /// toward the wipe budget — and retrying the same PIN can never work, so the
    /// UI must offer the recovery code. Mirrors `UNLOCK_RECOVERY_REQUIRED`.
    case recoveryRequired = 3
}

/// In-app update nudge — store-install gate (update-nudge plan, decision 3):
/// only a genuine App Store install gets the "Open App Store" button;
/// everything else (TestFlight, ad-hoc, debug, sideloaded) is info-only, no
/// egress. No existing environment check elsewhere in the codebase to reuse
/// (`TipStore.swift` has none).
enum StoreInstall {
    /// App Store Connect → App Information → Apple ID; bundle id `com.vg.run`.
    static let appStoreId = "6762006510"
    static let appStoreURL = URL(string: "https://apps.apple.com/app/id\(appStoreId)")!

    /// e2e-only override, armed ONLY from RunApp.swift's `#if DEBUG`
    /// `--test-force-store-install` launch-arg parsing (Android sibling:
    /// TestHooks.handleTestForceStoreInstall / RunViewModel.isPlayInstall).
    /// A simulator/sideloaded debug build has no real App Store receipt to
    /// satisfy the check below, so without this the store ("Open App Store")
    /// two-button variant could never be exercised there. Stays false on
    /// every ordinary debug run; a release binary's `isAppStoreInstall` below
    /// takes the `#else` branch, which never references this var at all, so
    /// its mere existence changes nothing about a real install's behavior.
    static var debugForceStoreInstall = false

    /// Fail-closed, POSITIVE match. `appStoreReceiptURL` is non-nil for
    /// TestFlight too (last path component `"sandboxReceipt"`), so the gate
    /// must check the exact expected name — `!= "sandboxReceipt"` would be
    /// wrong here: `nil != "sandboxReceipt"` is `true` in Swift, which would
    /// hand the store button to a sideloaded build with no receipt URL at all.
    /// `appStoreReceiptURL` is still populated on iOS 26; `AppTransaction.shared`
    /// is deliberately not used here because it may hit the network.
    static let isAppStoreInstall: Bool = {
        #if DEBUG
        return debugForceStoreInstall
        #else
        guard let url = Bundle.main.appStoreReceiptURL,
              FileManager.default.fileExists(atPath: url.path),
              url.lastPathComponent == "receipt" else {
            return false
        }
        return true
        #endif
    }()
}

@MainActor
final class AppState: ObservableObject {

    // Immutable, thread-safe Kotlin controller. Marked nonisolated so the
    // intentional off-main calls (PBKDF2/SQLCipher in unlock/setup, run on a
    // background queue per CR-1) don't trip main-actor isolation warnings.
    nonisolated(unsafe) let controller: IosAppController
    /// The transport half of the published state (Tor mirror, external-proxy status,
    /// bootstrap-stall hints + their watchdog). See AppState+TransportStatus.swift.
    let transport: TransportStatus
    /// Re-publishes each child object's change as AppState's own (installChildForwarders).
    private var childForwarders: [AnyCancellable] = []
    private var inactivityCrypto: CryptoProvider

    private var torCancellable: AnyCancellable?
    private var portCancellable: AnyCancellable?
    private var relaunchCancellable: AnyCancellable?
    private var relayCheckTask: Task<Void, Never>?
    private var controlPollTask: Task<Void, Never>?
    /// Bumped by every lock() / emergencyWipe(): the token a detached poll sweep
    /// captures at start and re-checks before each main-actor write
    /// ([isPollSessionCurrent]). Main actor only; RAM only.
    private var sessionGeneration: UInt64 = 0
    /// Debug-mode periodic log upload (DebugLogUploader.kt) — see
    /// [startDebugLogLoop]/[stopDebugLogLoop]. Same session-scoped shape as
    /// [relayCheckTask]/[controlPollTask].
    var debugLogTask: Task<Void, Never>?
    /// The ONE-SHOT "connect" flush fired from [checkRelayReachability] after a
    /// 2-8 s jitter. Held for the same reason [debugLogTask] is: it was
    /// previously an unowned detached Task, so a lock / wipe / consent-OFF
    /// during its sleep window could not cancel it and it woke up afterwards to
    /// upload a session that no longer existed. Cancelled everywhere the
    /// periodic loop is ([stopDebugLogLoop]), and it re-checks `debugMode`
    /// after the sleep as a second gate.
    var debugLogConnectTask: Task<Void, Never>?
    private var protectedDataObserver: NSObjectProtocol?

    // MARK: - Speculative (launch-time) Tor start — connect-speed lever 2
    //
    // Tor used to start inside unlock(), so its whole 10-60 s bootstrap sat
    // INSIDE the user's measured wait. It now starts as soon as the app is
    // active and protected data is available, so the bootstrap overlaps
    // credential entry — Android parity (RunViewModel.startSpeculativeTor).
    // Nothing about the vault, keys or unlock changes: see startSpeculativeTor.

    /// One-shot latch: this process has already asked TorManager to start
    /// speculatively. `TorManager.start()` is itself idempotent (it refuses a
    /// second call), so this is the outer of two guards, not the only one.
    private var speculativeTorStarted = false
    /// `UIApplication.didBecomeActiveNotification` token, held only until the
    /// speculative start actually fires.
    private var activationObserver: NSObjectProtocol?
    /// Second `protectedDataDidBecomeAvailableNotification` token, distinct from
    /// [protectedDataObserver] (which is one-shot for the LAUNCH SECURITY CHECKS
    /// and is removed by them). Held only until the speculative start fires.
    private var speculativeProtectedDataObserver: NSObjectProtocol?
    /// The launch security checks (orphaned-credential / 7-day inactivity /
    /// reinstall-over-Keychain wipes) have RUN. Tor must never start ahead of a
    /// pending launch-time wipe — `AppState.emergencyWipe`'s Tor teardown is
    /// deliberately not on those paths ("inappropriate before Tor has started"),
    /// and that comment must stay true.
    private var launchSecurityChecksDone = false

    /// One-shot latch for the PRE-UNLOCK rendezvous warm-up (lever 1). At most
    /// once per SESSION: tor_main runs once per process, and the only second
    /// session a process can host is a warm return inside the bounded Tor
    /// keep-alive window, which re-arms this (adoptKeptTor). See
    /// [warmRendezvousIfPreUnlock].
    private var rendezvousWarmupFired = false

    /// `ProcessInfo.systemUptime` at the FIRST `.connected` of this session's
    /// Tor, or nil while Tor has never connected. Feeds TWO telemetry fields
    /// off two different anchors: the `tor` phase split (lever 5), differenced
    /// against [connectStartUptime], and the `boot` field (2026-09-11),
    /// differenced against `TorManager.shared.startedAtUptime` at the send
    /// site. Never reset by a lock — same reasoning as [connectStartUptime]; a
    /// warm keep-alive session re-stamps it at adoption (Tor was already up, so
    /// that session's `tor` is 0 and its `boot` is omitted).
    private var torConnectedUptime: TimeInterval?
    // Set while startTorOrDirect() is authenticating a CACHED (possibly stale) SOCKS
    // port over Tor's control socket — the guard against a loopback-port squatter.
    // The current-value wiring paths (the CombineLatest sink and the health loop's
    // self-heal) must not wire that unauthenticated port behind the confirmation's
    // back; both branches of the confirmation clear this before they act.
    private var cachedPortAuthenticationInFlight = false

    // MARK: - Bounded Tor keep-alive after backgrounding (2026-10-23)
    //
    // See the "Bounded Tor keep-alive" section further down and
    // BackgroundTorKeepAlive.kt (commonMain) for the decision logic.

    /// THE single state flag the exit decision is taken against (main actor
    /// only). Token-based, so a deadline that a foreground return outlived is
    /// refused even when it is delivered late.
    private let torKeepAlive = BackgroundTorKeepAlive()
    /// The UIApplication background task that bounds the window; `.invalid`
    /// whenever no keep-alive is running.
    private var torKeepAliveTask: UIBackgroundTaskIdentifier = .invalid
    /// The scheduled end of the window (or the budget re-read) on the main queue.
    private var torKeepAliveDeadlineWork: DispatchWorkItem?
    /// The token of the CURRENT arm (meaningless while not keeping) — what the
    /// device-lock observer hands the deadline.
    private var torKeepAliveToken: Int64 = BackgroundTorKeepAlive.companion.NO_TOKEN
    /// Process-lifetime `protectedDataWillBecomeUnavailable` /
    /// `protectedDataDidBecomeAvailable` observers. PERMANENT (installed in
    /// init), not per arm: on a power-button lock the will-become-unavailable
    /// notification can arrive BEFORE the scene reaches `.background`, and a
    /// per-arm observer would miss it and keep Tor for the whole window on a
    /// locked device.
    private var torKeepAliveDeviceLockObservers: [NSObjectProtocol] = []
    /// A device lock is under way (will-become-unavailable seen, no
    /// did-become-available since): the keep-alive refuses to start and a
    /// running one ends.
    private var deviceLockPending = false
    /// The window line of the CURRENT keep-alive (fixed text + two numbers),
    /// re-emitted into the new session's panel on a warm return.
    private var torKeepAliveWindowLine: String?
    /// The tier half of the gate from this session's AUTHENTICATED read at
    /// unlock (`startTorOrDirect`), the fallback when the live read at
    /// backgrounding is Unreadable. false = no unlock this session ⇒ refuse.
    /// Android sibling: RunViewModel.sessionTierAllowsKeepAlive.
    private var sessionTierAllowsKeepAlive = false
    /// This session ADOPTED a Tor kept from the previous one: it started no Tor
    /// process, so the `boot` telemetry field is omitted (Android: no
    /// armBootStamp for an adopted instance) rather than measured from the
    /// first session's TorManager.startedAtUptime.
    private var warmTorSession = false
    /// `systemUptime` of the lock() that ended the LAST UNLOCKED session of this
    /// process (nil = no unlocked session yet). The keep-alive's ABSOLUTE residue
    /// cap is measured from here, not per background stretch: a warm return
    /// re-arms a fresh budget window on the next `.background`, so without this a
    /// user tapping back inside every window could keep the unlocked session's
    /// freed-heap residue alive indefinitely. A new unlock moves it on its own
    /// next lock().
    private var lastUnlockedSessionLockUptime: TimeInterval?
    /// `systemUptime` at which the current keep-alive's residue cap runs out
    /// (nil = no unlocked session to bound), fixed at arm time; the window
    /// scheduled after the budget re-reads is min(budget window, this − now).
    private var torKeepAliveResidueDeadlineUptime: TimeInterval?
    /// `systemUptime` of the current keep-alive's arm (log/probe only).
    private var torKeepAliveBackgroundedAtUptime: TimeInterval?

    #if DEBUG
    /// e2e-only MEASUREMENT switch (`--test-tor-keepalive-unbounded`, set by
    /// RunApp.init inside its `#if DEBUG` block): the keep-alive bypasses its
    /// residue cap and tier gate and never tears down on the window / expiration
    /// deadline — the process suspends with Tor kept — so
    /// tests/adhoc/tor-suspend-survival.spec.ts can measure whether a SUSPENDED
    /// process's Tor survives long backgrounds. Device lock and wipes still tear
    /// down. Compiled out of release: there is no release path to it.
    static var testUnboundedTorKeepAlive = false
    /// The machine-readable result of the last warm-return suspend probe (fixed
    /// keys, numbers only), exposed by ContentView's DEBUG-only
    /// `tor_suspend_probe` element. nil until the first probed warm return.
    @Published var torSuspendProbeSummary: String?
    private var torSuspendProbe: TorSuspendProbe?
    private var torSuspendProbeSeq = 0
    #endif

    /// True only in the DEBUG `--test-tor-keepalive-unbounded` measurement mode.
    private var torKeepAliveUnbounded: Bool {
        #if DEBUG
        return AppState.testUnboundedTorKeepAlive
        #else
        return false
        #endif
    }

    #if DEBUG
    // DEBUG-ONLY throwaway test seam: one-shot guard so --test-seed-contacts=<N>
    // (see seedTestContactsIfRequested) seeds the fake contacts only once per
    // process, not on every re-unlock. Compiled out of Release entirely.
    private var didSeedTestContacts = false
    #endif

    /// Registers the seven Kotlin→Swift bridge holders. Idempotent, and the
    /// ONLY place the registration order lives (load-bearing:
    /// Kotlin commonMain calls these holders synchronously while constructing
    /// crypto / DB / HTTP, so every holder must be set before the first
    /// `KeyValueStore()` / `IosAppController()`). Called from TWO sites:
    /// `RunApp.init()` — first statement, before `DebugMode.applyAtStartup`
    /// reads the Keychain — and `AppState.init()` below, where it used to be
    /// inlined. The RunApp call is the one that matters for startup order:
    /// `@StateObject var appState = AppState()` is an `@autoclosure`, so
    /// SwiftUI constructs the AppState lazily when the scene mounts, NOT
    /// while the App struct's property defaults are applied. Until 2026-09-22
    /// the startup debug-mode read therefore ran with a nil KeychainBridge,
    /// threw "not registered", and was folded to OFF on EVERY launch — the
    /// "two-read split" that kept the debug-log stream silent on production
    /// phones (the loop's rescue line was the only thing keeping it alive).
    static func registerBridges() {
        // Keychain is the idempotence sentinel even though it is set 4th (after
        // AesGcm/X25519/Argon2): registration is synchronous on main, so a
        // partially-registered state is never observable by a second caller.
        if KeychainBridgeHolder.shared.bridge != nil { return }
        AesGcmBridgeHolder.shared.bridge = SwiftAesGcm()
        X25519BridgeHolder.shared.bridge = SwiftX25519()
        Argon2BridgeHolder.shared.bridge = SwiftArgon2()
        KeychainBridgeHolder.shared.bridge = KeychainHelper.shared
        DatabaseBridgeHolder.shared.factory = SwiftDatabaseBridgeFactory()
        HttpBridgeHolder.shared.bridge = SwiftTorHttp()
        // Lever B (forensic hardening): the Secure-Enclave auth-bound DB-key
        // bridge. Registered before IosAppController like the other holders —
        // IosDbKeyProtector reads it lazily, but keep the registration with its
        // peers so the load-bearing bridge order stays in one place.
        SecureEnclaveBridgeHolder.shared.bridge = SecureEnclaveHelper.shared
    }

    /// init() step: re-publish each child's change as AppState's own, so views that
    /// observe AppState keep invalidating exactly as before (a child's @Published
    /// fires in willSet; the forward is synchronous). One entry per child.
    private func installChildForwarders() {
        childForwarders = [transport.objectWillChange]
            .map { $0.sink { [weak self] _ in self?.objectWillChange.send() } }
    }

    init() {
        // Register bridges BEFORE creating controller — CryptoProvider needs AesGcm,
        // IosVaultDatabase needs DatabaseBridge. Normally already done by
        // RunApp.init(); harmless no-op then (see registerBridges).
        AppState.registerBridges()
        controller = IosAppController()
        transport = TransportStatus()
        // Initialise inactivityCrypto up-front so all stored properties are
        // assigned before any string interpolation reads `self.*` below.
        // It may be reassigned after an emergency wipe further down.
        inactivityCrypto = CryptoProvider()
        // Every stored property is set from here on, and nothing below has written
        // published state yet (runLaunchSecurityChecks can wipe → torState).
        installChildForwarders()
        // Debug mode's persisted choice — see the @Published declaration above.
        // Never throws.
        debugMode = controller.isDebugModeEnabled()
        // Relay URL is compiled into the shared module from relay.properties
        // at the repo root. Simulator override (localhost:8080) is handled
        // inside RelayConfig.ios.kt via SIMULATOR_DEVICE_NAME env detection.
        isDeviceCompromised = IntegrityCheck.isCompromised
        // Only the negative (expected) outcome is logged — the positive one is a
        // rare-state fingerprint bit that must not appear in a release-uploadable
        // log (Debug mode can upload redacted LogBuffer lines in RELEASE builds).
        if !isDeviceCompromised {
            LogBuffer.shared.append(level: "D", tag: "AppState", message: "integrity check passed")
        }

        // The launch security checks (orphaned-credential wipe + 7-day
        // inactivity wipe) decrypt with the Keychain device key. That key is
        // unreadable while the device is locked, and iOS can launch this
        // process before first unlock (prewarm / after reboot). Running the
        // checks in that state used to mis-read "locked" as "key gone" and
        // wipe the vault. So drive the UI from the key-free isConfigured()
        // flag now, and only run the key-dependent checks once protected data
        // is available (immediately if it already is, otherwise on unlock).
        // (Under the NSFileProtectionComplete entitlement the UserDefaults plist
        // backing isConfigured() is itself lock-gated, so it too can read false
        // on a locked launch — the same deferral re-drives the UI on unlock, so
        // the user never sees the transient mis-state.)
        isConfigured = vaultPresent()
        if UIApplication.shared.isProtectedDataAvailable {
            runLaunchSecurityChecks()
        } else {
            LogBuffer.shared.append(level: "W", tag: "AppState", message: "launched with protected data unavailable (device locked) — deferring launch security checks")
            observeProtectedDataAvailable()
        }

        // The hooks and sinks, in this order (each documents itself).
        installVaultSessionRetiredHook()
        subscribeTorState()
        subscribeSocksPortAndUnlock()
        installMoveHooks()
        subscribeRelaunchRequired()

        // Connect-speed lever 2 — LAST, after every sink above is live, so a Tor
        // that connects fast still lands in a fully-wired AppState. Normally a
        // no-op right here (a launching scene is not yet `.active`); it arms the
        // activation observer that does the real work. See
        // startSpeculativeTorIfReady for the gates.
        armSpeculativeTorStart()

        // Bounded Tor keep-alive: the device-lock observers must exist BEFORE any
        // `.background` (a power-button lock can post will-become-unavailable first).
        observeDeviceLockForTorKeepAlive()

        // Network-restore kick (2026-10-25): process-lifetime, like TorManager.shared.
        startNetworkRestoreMonitor()
    }

    /// init() step: lock on a mid-session vault-handle retirement (see the body).
    private func installVaultSessionRetiredHook() {
        // Review 2026-08-03: VaultSelector CLOSED the live vault handle
        // mid-session — a SQLCipher re-key on a credential tier upgrade did not
        // verifiably commit, so the handle's codec write context can no longer
        // be trusted (see VaultDatabase.rekey's kdoc / VaultSelector.
        // retireRekeyedVaultHandle). The only safe continuation is the locked
        // state: lock() cancels the pollers, closes/nulls the (already-closed —
        // idempotent) handle and scrubs session state, and the next unlock's
        // rotation reconcile reopens under whichever key really holds the file.
        // Fires on the change-credential background queue — hop to main for the
        // MainActor teardown. Parity with Android's MainActivity collector.
        controller.onVaultSessionRetired = { [weak self] in
            hopToMain {
                guard let self, self.isUnlocked else { return }
                LogBuffer.shared.append(level: "W", tag: "AppState",
                    message: "vault handle retired after a failed re-key — forcing lock")
                self.lock()
            }
        }
    }

    /// init() step: mirror TorManager.state into [torState] (+ stall retract,
    /// connect-time anchor and pre-unlock warm-up on `.connected`).
    private func subscribeTorState() {
        torCancellable = TorManager.shared.$state
            .receive(on: DispatchQueue.main)
            .sink { [weak self] newState in
                let desc: String
                switch newState {
                case .disconnected: desc = "disconnected"
                case .bootstrapping(let p): desc = "bootstrapping(\(p)%)"
                case .connected: desc = "connected"
                }
                LogBuffer.shared.append(level: "D", tag: "AppState", message: "Tor state → \(desc)")
                self?.transport.torState = newState
                // Bootstrap landed (possibly minutes after the watchdog fired) —
                // retract the stall hint and disarm. Auto-recovery: AddContactView's
                // .onReceive(appState.transport.$torState) re-fires startMint off this same
                // .connected transition.
                if case .connected = newState {
                    guard let self else { return }
                    self.transport.clearTorBootstrapStall()
                    // Phase-split telemetry anchor (lever 5): the FIRST .connected
                    // of this session only. TorManager publishes .connected once
                    // per process, but latch anyway — this number must describe the
                    // bootstrap the user actually waited on.
                    if self.torConnectedUptime == nil {
                        self.torConnectedUptime = ProcessInfo.processInfo.systemUptime
                    }
                    // Pre-unlock rendezvous warm-up (lever 1). No-op once the vault
                    // is open — the health probe owns the relay from there.
                    self.warmRendezvousIfPreUnlock()
                }
            }
    }

    /// init() step: the load-bearing CombineLatest(`$socksPort`, `$isUnlocked`)
    /// transport wiring (see the body for why both publishers are combined).
    private func subscribeSocksPortAndUnlock() {
        // Wire the MessageManager whenever BOTH conditions currently hold: Tor has a
        // live SOCKS port AND the vault is unlocked.
        //
        // This deliberately combines the two publishers instead of sinking
        // `$socksPort` alone. `socksPort` is published EXACTLY ONCE per process
        // (TorManager removes its circuit observer after the first
        // `net/listeners/socks` readback), so a lone `$socksPort` sink that declined
        // to act — because `isUnlocked` happened to be false at that instant — never
        // got another chance: `@Published` replays its current value to a NEW
        // subscriber, but this subscriber lives for the whole process and simply
        // dropped the value. The port is CURRENT-VALUE state, not an event, and the
        // readiness predicate depends on a second piece of state we were not
        // observing. CombineLatest re-evaluates the predicate against the CURRENT
        // port whenever `isUnlocked` flips, so whichever input becomes true last
        // still wires the transport (root cause of the post-resume "isRelayReachable
        // wedged false / zero requests reach the relay" hang, 2026-07-20).
        portCancellable = Publishers.CombineLatest(TorManager.shared.$socksPort, $isUnlocked)
            .receive(on: DispatchQueue.main)
            .removeDuplicates { $0 == $1 }
            .sink { [weak self] port, unlocked in
                LogBuffer.shared.append(level: "D", tag: "AppState", message: "socksPort → \(port), isUnlocked=\(unlocked)")
                guard let self, port > 0, unlocked else { return }
                // Never wire behind the back of an in-flight control-socket
                // authentication of a CACHED port — see
                // cachedPortAuthenticationInFlight — and never wire a port whose
                // Tor is known dead.
                guard !self.cachedPortAuthenticationInFlight,
                      !TorManager.shared.relaunchRequired else { return }
                self.wireRelayTransport(socksPort: port, reason: "port/unlock state")
            }
    }

    /// init() step: "Move to new device" quiesce / resume hooks.
    private func installMoveHooks() {
        // "Move to new device" (docs/device-move.md D2) — the two halves of
        // MoveSessionControl that only the Swift layer can perform. Kotlin
        // invokes them from a BACKGROUND coroutine, so hop to main here, exactly
        // like installVaultSessionRetiredHook's onVaultSessionRetired.
        //
        // quiesce stops the CONTACT-FACING loops only: the control poll (which
        // RECEIVES, and a receive advances the Double Ratchet — docs/device-move.md
        // fact 5) and the unread prime. The relay-reachability loop and Tor are
        // deliberately LEFT RUNNING: a frozen phone still has to peek its own
        // transfer inbox every 10 s to notice the new phone draining it, and to
        // prove "undrained" before a cancel is allowed. The durable half of the
        // gate lives in commonMain (createSessionManagers wraps the transport
        // provider in isMoveFrozen), so this is belt-and-braces, not the boundary.
        //
        // DELIBERATE DIVERGENCE from Android's moveQuiesceSession, which also
        // cancels its relay-check job: Android re-wires its MessageManager from the
        // torState collector, so cancelling costs it nothing. On iOS
        // `checkRelayReachability(selfHeal:)` is the ONLY loop that can re-wire an
        // ABSENT transport (`$socksPort` publishes exactly once per process), and a
        // frozen phone with no transport can neither peek nor prove a cancel. It is
        // safe to leave running: the push re-registration / dereg sweep live in the
        // CONTROL poll (cancelled above), and everything the reachability loop still
        // does is a relay-root probe plus two one-shot local nudges.
        controller.onMoveQuiesce = { [weak self] in
            hopToMain {
                guard let self else { return }
                LogBuffer.shared.append(level: "W", tag: "Move", message: "quiescing the contact-facing session")
                self.controlPollTask?.cancel()
                self.controlPollTask = nil
                self.unreadCounts = [:]
                self.groupUnreadCounts = [:]
            }
        }
        controller.onMoveResume = { [weak self] in
            hopToMain {
                guard let self, self.isUnlocked else { return }
                LogBuffer.shared.append(level: "D", tag: "Move", message: "resuming the contact-facing session after a cancelled move")
                self.isMoveFrozen = false
                self.startControlPoll()
                self.startUnreadPrime()
            }
        }
    }

    /// init() step: the Tor-dead latch → connect phase + transport-lost note.
    private func subscribeRelaunchRequired() {
        // Tor-dead latch → drive the connect phase so the UI stops saying
        // "Connecting…" the moment the dead thread is detected (previously the
        // dead path never started the reachability loop, so the phase stayed
        // .connecting forever and the stalled hint could never appear).
        relaunchCancellable = TorManager.shared.$relaunchRequired
            .receive(on: DispatchQueue.main)
            .sink { [weak self] required in
                guard required, let self else { return }
                LogBuffer.shared.append(level: "W", tag: "AppState", message: "Tor relaunch required — surfacing close-and-reopen hint")
                self.relayConnectPhase = .relaunchRequired
                #if DEBUG
                // Suspend-survival probe (measurement mode): reflect the latch.
                self.publishTorSuspendProbe()
                #endif
                // The one POSITIVE Tor-death signal iOS has (Android: the Failed/Idle
                // branches before `messageManager = null`): a send in flight on this
                // transport stops after its current attempt and parks as
                // TRANSPORT_FAILED instead of re-POSTing at a dead port. iOS never
                // replaces a live manager outside lock()/wipe (both scrub), so there
                // is no other noteTransportLost site. NO scrubInMemory here — the
                // parked sends must survive for the re-drive.
                self.controller.messageManager?.noteTransportLost()
                // .relaunchRequired OUTRANKS the bootstrap-stall hint: the honest
                // advice is now "close and reopen", not "try another network".
                // Drop the weaker hint (and its pending watchdog) so no surface can
                // render both.
                self.transport.clearTorBootstrapStall()
            }
    }

    /// Does a vault exist by EITHER measure — credential store or database file?
    ///
    /// Drives `isConfigured`, i.e. whether ContentView shows unlock or first-run
    /// setup. `controller.isConfigured()` alone is not safe for that decision: it
    /// reads the UserDefaults plist, which under NSFileProtectionComplete is
    /// itself lock-gated and can read empty on a locked/prewarm launch (see the
    /// note in `init`). Landing on setup in that state is destructive — completing
    /// it provisions over the real vault — so the filesystem, which has no such
    /// failure mode, gets a vote.
    ///
    /// Used ONLY for routing. The wipe decisions below deliberately keep reading
    /// `controller.isConfigured()` directly: they are about CREDENTIAL state
    /// (orphaned verifier, inactivity window), and widening them to "a file
    /// exists" would change which vaults get wiped — the opposite of the goal.
    private func vaultPresent() -> Bool {
        controller.isConfigured() || controller.vaultFileExists()
    }

    /// PROVISION-1 sibling of Android `PinSetupScreen.provisionAndFinish`
    /// (PinSetupScreen.kt, "provision refused — vault already present"): after a
    /// FAILED provision, route to unlock if a vault database is sitting there.
    ///
    /// The provision guard throws `ExistingVaultException` — surfaced across the
    /// non-@Throws bridge as a plain `false` — whenever a vault file exists while
    /// the credential store reads unconfigured. Retrying setup against that guard
    /// loops forever, because the guard is doing its job; the destination the user
    /// actually needs is the unlock screen, which is also the only place the
    /// explicit "Erase and start over" escape hatch lives
    /// (`orphanedVaultFile()` / `erase_orphaned_vault_button`).
    ///
    /// Rare by design since PROVISION-1: a provision that fails now rolls its own
    /// `run.db` back, so the retry meets a clean slate. This covers the residue
    /// that rollback cannot guarantee — an unlink that itself failed, or an install
    /// that upgraded INTO this build already carrying the stale file.
    ///
    /// Returns true when it routed, so the caller skips its shake-and-retry.
    func routeToUnlockIfVaultPresent() -> Bool {
        guard controller.vaultFileExists() else { return false }
        LogBuffer.shared.append(level: "W", tag: "Setup",
                                message: "provision refused — vault already present; routing to unlock instead of setup")
        isConfigured = true
        return true
    }

    /// Orphaned-credential wipe + 7-day inactivity wipe. Both decrypt with the
    /// Keychain device key, so this must run only when protected data is
    /// available (the device has been unlocked at least once since boot).
    private func runLaunchSecurityChecks() {
        // The iOS Keychain SURVIVES app uninstall, so a reinstall
        // lands on the previous install's device key, credential verifier, wrapped
        // DB key, counters, SE key and (plaintext) block list — post-seizure
        // PIN-brute-force material and proof-of-prior-use, contradicting the
        // "uninstalling deletes all data" promise. The app sandbox (UserDefaults)
        // IS wiped on uninstall, so a MISSING install sentinel + PRESENT Keychain
        // vault items ⇒ a reinstall over surviving Keychain: purge it before setup.
        // A genuinely fresh install has neither and just plants the sentinel; a
        // normal launch has the sentinel and skips. (The sentinel key is
        // deliberately NOT in IosUserDefaultsKeys.all, so an in-app emergency wipe
        // — same install — leaves it, and the next launch correctly skips.)
        let installSentinel = "run_install_sentinel_v1"
        let defaults = UserDefaults.standard
        if defaults.object(forKey: installSentinel) == nil {
            // Same reasoning as the branch below, but UNCONDITIONAL: the Tor
            // bootstrap breadcrumb lives in the Keychain, which survives an
            // uninstall, and it is proof-of-prior-Tor-use plus a day-granularity
            // "recently used" signal. The purge below only fires when the surviving
            // Keychain still looks configured; a fresh sandbox over a previously
            // WIPED install would otherwise carry this record forward. Resetting
            // the failure streak on a genuine fresh install costs nothing — the
            // evidence re-accumulates in five relaunches if the problem is real.
            TorBootstrapBreadcrumbStore.erase()
            // External SOCKS proxy setting: a Keychain row too, so it would
            // otherwise SURVIVE an uninstall and silently route a fresh install's
            // traffic to a proxy chosen in a previous one (and stand as
            // proof-of-prior-use). Same unconditional reset. Runs before any
            // ExternalProxyMode.resolve(): Tor can only start after these checks.
            _ = IosExternalProxyStore.shared.clear()
            if controller.isConfigured() {
                LogBuffer.shared.append(level: "W", tag: "AppState", message: "fresh sandbox over surviving Keychain (reinstall) — purging orphaned Keychain material")
                wipeDiag("AppState.reinstall-over-surviving-keychain")
                controller.emergencyWipe()
                clearWipeResidue()   // EULA flag + wipediag.txt breadcrumb
                BlockStore.clear()
                // ZERO the in-RAM copy of the 32-byte root
                // device key before dropping the provider. `controller.emergencyWipe()`
                // wipes the CONTROLLER's provider, not this one, and reassigning the
                // property alone just drops the last reference — Kotlin/Native then
                // frees the key bytes UNZEROED, in a process this path deliberately
                // keeps alive on the setup screen. Same ordering as `lock()` and the
                // full `emergencyWipe()`. Latent on this branch today (the key is not
                // loaded before this point), fixed uniformly so a future reordering
                // cannot reopen it.
                inactivityCrypto.wipeKey()
                inactivityCrypto = CryptoProvider()
            }
            defaults.set(true, forKey: installSentinel)
        }

        let configured = controller.isConfigured()
        LogBuffer.shared.append(level: "D", tag: "AppState", message: "launch checks: configured=\(configured)")
        // If stored credentials exist but can't be decrypted (orphaned from a
        // previous install with a different Keychain key), wipe them so the
        // user sees setup instead of a PIN screen that rejects every PIN.
        if configured && !controller.vaultSelector.credentialsReadable() {
            wipeDiag("AppState.orphaned-credentials (credentialsReadable()==false at launch check)")
            LogBuffer.shared.append(level: "W", tag: "AppState", message: "orphaned credentials detected — wiping")
            controller.emergencyWipe()
            clearWipeResidue()   // EULA flag + wipediag.txt breadcrumb
            // These launch paths call the controller
            // wipe directly (not the full AppState.emergencyWipe, which stops Tor
            // etc. — inappropriate before Tor has started), so clear BlockStore
            // here too. Otherwise the plaintext blocked-contact-ID list in the
            // Keychain (UserSafety) survives an orphaned-credential / 7-day wipe.
            BlockStore.clear()
            // emergencyWipe deleted the Keychain device key; recreate
            // inactivityCrypto so it isn't left referencing a destroyed key (and
            // a later InactivityWipe.touch() re-encrypts with a fresh one) —
            // mirrors the 7-day path below.
            // Zero the old key material FIRST — see the reinstall branch
            // above. Reassignment alone frees it unzeroed.
            inactivityCrypto.wipeKey()
            inactivityCrypto = CryptoProvider()
        }
        isConfigured = vaultPresent()

        // 7-day inactivity wipe — before showing the PIN screen. -1 = the stored
        // protection level is UNREADABLE right now (a transient device-key
        // outage — Keychain glitch, or the device locked mid-call): SKIP the
        // check this launch — applying the shorter default window to an
        // unreadable gentler tier would early-wipe the vault (the check
        // re-arms as soon as the level reads again).
        //
        // A DAMAGED blob (one flipped byte, AEAD-invalid) is NOT in that
        // bucket: the device key WORKS
        // and only the stored value failed AEAD verification — positive
        // tamper evidence — so inactivityThresholdMs() yields MAXIMUM's 7-day
        // window instead of -1, and this launch runs the check below rather
        // than skipping it. Mirrors IosAppController.inactivityThresholdMs()
        // and Android InactivityWipe.kt's matching fix.
        let inactivityThresholdMs = controller.inactivityThresholdMs()
        if isConfigured && inactivityThresholdMs < 0 {
            LogBuffer.shared.append(level: "W", tag: "AppState", message: "protection level unreadable — inactivity check skipped this launch")
        } else if isConfigured && InactivityWipe.isExpired(crypto: inactivityCrypto, thresholdMs: inactivityThresholdMs) {
            wipeDiag("AppState.inactivity-window-expired (threshold=\(inactivityThresholdMs)ms)")
            LogBuffer.shared.append(level: "W", tag: "AppState", message: "7-day inactivity wipe triggered")
            controller.emergencyWipe()
            clearWipeResidue()   // EULA flag + wipediag.txt breadcrumb (the unattended self-wipe most needs it)
            InactivityWipe.clear()
            BlockStore.clear()  // Clear the Keychain block-list on this wipe path too
            isConfigured = false
            // emergencyWipe deleted the old Keychain key; recreate so a later
            // InactivityWipe.touch() during unlock() encrypts with a fresh key.
            // This is the branch where it MATTERS today —
            // InactivityWipe.isExpired(crypto: inactivityCrypto) just above loaded
            // the 32-byte root device key into this provider to make the decision,
            // so without this wipeKey() the reassignment hands an unzeroed copy back
            // to the allocator in a process that then sits on the setup screen.
            inactivityCrypto.wipeKey()
            inactivityCrypto = CryptoProvider()
        } else if isConfigured {
            LogBuffer.shared.append(level: "D", tag: "AppState", message: "inactivity wipe check passed")
        }

        // Lever 2 gate: every launch-time wipe decision is now behind us, so Tor
        // may start. Kicking it from HERE (not only from the activation
        // notification) is what covers the deferred path — a launch while the
        // DEVICE was locked runs these checks from
        // protectedDataDidBecomeAvailable, by which time the app is usually
        // already active and no further activation notification is coming.
        //
        // On the ordinary path this call is made from `init`, before the Tor/port
        // sinks below it are attached, and can therefore start Tor "early" if the
        // scene is somehow already active. That is safe by the same property the
        // whole file leans on: `$state` and `$socksPort` are @Published
        // CURRENT-VALUE state, replayed to each new subscriber — a sink attached
        // a few lines later still sees the bootstrap it missed.
        launchSecurityChecksDone = true
        startSpeculativeTorIfReady()
    }

    /// Runs the deferred launch checks once, the first time protected data
    /// becomes available — i.e. the user unlocks the device after the app was
    /// launched while locked (prewarm / after reboot).
    private func observeProtectedDataAvailable() {
        protectedDataObserver = NotificationCenter.default.addObserver(
            forName: UIApplication.protectedDataDidBecomeAvailableNotification,
            object: nil, queue: .main
        ) { [weak self] _ in
            Task { @MainActor in
                guard let self else { return }
                if let token = self.protectedDataObserver {
                    NotificationCenter.default.removeObserver(token)
                    self.protectedDataObserver = nil
                }
                LogBuffer.shared.append(level: "D", tag: "AppState", message: "protected data now available — running deferred launch checks")
                self.runLaunchSecurityChecks()
            }
        }
    }

    // -----------------------------------------------------------------------
    // Speculative (launch-time) Tor start — connect-speed lever 2
    //
    // Android parity: RunViewModel.startSpeculativeTor, which starts Tor when the
    // PIN screen mounts. Both exist for the same measured reason: a cold Tor
    // bootstrap is 7-13 s warm and 20-60 s cold, and it used to sit ENTIRELY
    // inside the wait the user experiences as "connecting to the relay", because
    // iOS only called startTorOrDirect() from unlock().
    //
    // What this deliberately does NOT change:
    //  - The transport is still wired ONLY when BOTH a SOCKS port exists AND the
    //    vault is unlocked. That predicate lives in the CombineLatest(port,
    //    isUnlocked) sink in init() and is untouched — a pre-unlock port simply
    //    sits in `socksPort` until isUnlocked flips, which is precisely the
    //    current-value behaviour that sink was rewritten to guarantee.
    //  - Nothing vault-, key- or credential-shaped happens earlier. No
    //    MessageManager, no relay health loop, no control poll, no unread prime,
    //    no push registration: every one of those needs an OPEN vault, and none
    //    of them can exist before there is one.
    //  - Teardown: Tor stops where it always stopped (lock() when not `.active`,
    //    ContentView's `.background` branch, the discarding stop in
    //    emergencyWipe), and relaunchRequired → exit(0) recycles the process —
    //    EXCEPT that since the bounded keep-alive (2026-10-23, "Bounded Tor
    //    keep-alive" below) a healthy Connected Tor outlives `.background` by
    //    the background-task budget, pre-unlock included: leaving the PIN screen
    //    and returning inside the window reuses the speculative Tor; otherwise the
    //    window's deadline stops it, which latches relaunchRequired and recycles
    //    the process while invisible — tor_main runs once per process, so a
    //    recycle is the only way back.
    //  - The telemetry anchor stays at unlock (see startTorOrDirect). The
    //    bootstrap now overlaps credential entry, so counting it would be
    //    counting how fast the user types.
    // -----------------------------------------------------------------------

    /// Arms the launch-time Tor start: fires NOW if the app is already active,
    /// otherwise on the first `didBecomeActive`.
    ///
    /// ACTIVE — not merely "launched" — is load-bearing. iOS starts this process
    /// without ever showing it (app prewarm, background launch), and `tor_main`
    /// may be created ONCE PER PROCESS: a bootstrap burned in an invisible
    /// process that iOS then suspends — killing the Tor thread — would hand the
    /// user a `relaunchRequired` app on their first real open, which is the exact
    /// production wedge the relaunch latch exists to paper over. `.active` also
    /// implies the device is unlocked, which is the other half of the gate.
    private func armSpeculativeTorStart() {
        // Current-value first: a scene that is already active sends no further
        // didBecomeActive, so waiting for one would wait forever.
        startSpeculativeTorIfReady()
        guard !speculativeTorStarted, activationObserver == nil else { return }
        activationObserver = NotificationCenter.default.addObserver(
            forName: UIApplication.didBecomeActiveNotification,
            object: nil, queue: .main
        ) { [weak self] _ in
            Task { @MainActor in
                self?.startSpeculativeTorIfReady()
            }
        }
    }

    /// The four gates, all re-read as CURRENT-VALUE state at call time (the
    /// discipline `portCancellable` had to learn): whichever becomes true LAST
    /// starts Tor, because every one of them calls back into here.
    private func startSpeculativeTorIfReady() {
        guard !speculativeTorStarted else { return }
        // An in-session wipe latched this process onto the deniability cover /
        // setup screen. Never start a daemon into that.
        guard !wipedThisSession else { return }
        // Never ahead of a pending launch-time wipe: those paths call
        // controller.emergencyWipe() directly BECAUSE Tor has not started yet
        // (AppState.emergencyWipe's Tor teardown is "inappropriate before Tor has
        // started" — keep that true).
        guard launchSecurityChecksDone else { return }
        guard UIApplication.shared.applicationState == .active else { return }
        // The Tor working dir is NSFileProtectionComplete (TorManager.start →
        // applyDataProtection): starting before protected data is available would
        // have Tor read and write files the kernel will not hand over. Same gate,
        // same reason, as the launch security checks above.
        guard UIApplication.shared.isProtectedDataAvailable else {
            observeProtectedDataForSpeculativeTor()
            return
        }
        startSpeculativeTor()
    }

    /// Starts Tor and NOTHING else.
    ///
    /// Deliberately does not arm the bootstrap watchdog: its hint ("this network
    /// may be blocking it") is meaningless on the PIN screen, which never renders
    /// it. The only pre-unlock governors are TorManager's own bootstrap timeout
    /// and its cross-launch stuck-bootstrap self-heal — the right amount of
    /// autonomy for a window with no user-visible surface. The watchdogs arm at
    /// unlock, RE-ANCHORED onto the bootstrap they inherit (see
    /// TransportStatus.reanchoredDelaySec). Android sibling: RunViewModel.startSpeculativeTor.
    private func startSpeculativeTor() {
        speculativeTorStarted = true
        disarmSpeculativeTorObservers()
        guard RelayConfig.shared.isTorRequired else {
            // Clearnet dev/simulator relay: nothing to start here. That branch of
            // startTorOrDirect() builds a MessageManager, which needs an OPEN
            // vault, so it stays where it is — at unlock. Android's
            // startSpeculativeTor gates on the same predicate.
            return
        }
        // External SOCKS proxy mode: no embedded Tor in this process at all — no
        // speculative start, no hedge/hook/gate/kick installs. TorManager.start()
        // refuses on the same predicate (the hard control); this is the early,
        // quiet exit. The proxy itself is probed at unlock (startTorOrDirect).
        // An UNREADABLE setting also lands here (fail closed); the unlock-time
        // path re-resolves it.
        guard ExternalProxyMode.shared.mayStartEmbeddedTor() else {
            LogBuffer.shared.append(level: "D", tag: "AppState",
                message: "speculative Tor skipped — external proxy mode or setting unreadable")
            return
        }
        LogBuffer.shared.append(level: "D", tag: "AppState",
            message: "starting Tor speculatively (pre-unlock) — bootstrap overlaps credential entry")
        installDescriptorHedge()
        installNewCircuitHook()
        installHsCircuitGate()
        installBootstrapStallKick()
        TorManager.shared.start()
        // Same read-back as startTorOrDirect(): start() computes it before
        // returning, and the unlock-time call re-reads the identical value from a
        // refused start. Copy only; nothing is gated on it.
        transport.refreshRebootHint()
    }

    /// Second, INDEPENDENT protected-data observer. [protectedDataObserver] is
    /// one-shot for the launch security checks and removes itself; this one is
    /// held only until the speculative start fires. Both are registered on the
    /// same notification, and the launch-checks one was registered first, so on
    /// the deferred path it runs first and its own tail kick usually starts Tor
    /// before this ever fires — this covers the ordering rather than relying on it.
    private func observeProtectedDataForSpeculativeTor() {
        guard speculativeProtectedDataObserver == nil else { return }
        LogBuffer.shared.append(level: "D", tag: "AppState",
            message: "speculative Tor deferred — protected data unavailable")
        speculativeProtectedDataObserver = NotificationCenter.default.addObserver(
            forName: UIApplication.protectedDataDidBecomeAvailableNotification,
            object: nil, queue: .main
        ) { [weak self] _ in
            Task { @MainActor in
                self?.startSpeculativeTorIfReady()
            }
        }
    }

    /// Drops both one-shot tokens the moment the start has happened (or has been
    /// decided against) — they exist only to reach that point.
    private func disarmSpeculativeTorObservers() {
        if let token = activationObserver {
            NotificationCenter.default.removeObserver(token)
            activationObserver = nil
        }
        if let token = speculativeProtectedDataObserver {
            NotificationCenter.default.removeObserver(token)
            speculativeProtectedDataObserver = nil
        }
    }

    // -----------------------------------------------------------------------
    // Pre-unlock rendezvous warm-up — connect-speed lever 1
    // -----------------------------------------------------------------------

    /// Fires ONE best-effort, fire-and-forget `GET {relay base url}/` the moment
    /// Tor reports Connected while the vault is still LOCKED, so the onion
    /// descriptor fetch and the rendezvous circuits exist before the user
    /// finishes their PIN.
    ///
    /// Why this is the expensive half of a cold connect: Tor's
    /// "Bootstrapped 100%" is a FALSE ready signal, and v3 hidden-service
    /// descriptors are never cached on disk — every new Tor process re-fetches
    /// one (HSDir lookup → intro circuit ∥ rendezvous circuit → the service's own
    /// circuit to the rendezvous point) before a single byte can flow. Until now
    /// that phase could only begin AFTER unlock, because the health probe hangs
    /// off MessageManager, which is constructed with the opened vault. A bare
    /// `GET /` needs no vault, no capability and no secret — only the onion
    /// address the app already compiles in — so the object graph, not any
    /// security property, was what held it back. Tor keeps the resulting circuit
    /// reusable for MaxCircuitDirtiness (10 min), so the post-unlock health probe
    /// rides it and answers in ~1 RTT.
    ///
    /// THE REQUEST ITSELF LIVES IN commonMain (`RelayWarmup.warmAttempt`, reached
    /// via `IosAppController.warmRelayRendezvous`) — the same object Android drives,
    /// so the URL, the 25 s per-attempt budget, the "answered at all" test, the
    /// one-retry rule and both ConnectionLog phrases cannot drift between the
    /// platforms. It goes out over
    /// `PlatformHttpClient(socksPort)`, i.e. SwiftTorHttp's SOCKS5h path, exactly
    /// like every other relay call from this app. Everything this method owns is
    /// the WHEN:
    ///  - At most ONCE per Tor instance (tor_main runs once per process, so once
    ///    per process) — plus, since the rotation, at most ONE further attempt after a
    ///    `SIGNAL NEWNYM`, and only when the first burned its whole budget
    ///    (`rotateAndRetryWarmup`).
    ///  - Only while LOCKED. Once the vault is open this IS the health probe, and
    ///    that probe is unchanged.
    ///  - Never after an in-session wipe.
    ///
    /// And what it deliberately does NOT do: no latch, no unbounded retry, no UI, no
    /// connect-phase change, and it does not move the reveal gate — contacts stay
    /// hidden until the SESSION's own transport answers. The relay sees one more
    /// anonymous `GET /` (which it answers 404) per launch, a few seconds earlier
    /// than it would have anyway; the network already watches this app bootstrap
    /// Tor at launch. Nothing logged names an identifier or the onion host.
    private func warmRendezvousIfPreUnlock() {
        guard !rendezvousWarmupFired else { return }
        // Post-unlock the health probe owns the relay; pre-unlock nothing else does.
        // Narrated (not silent) because the panel otherwise shows a gap where the
        // warm-up's own two lines would be, and "the user was already in" is the
        // answer to "why didn't it warm up?". Fires at most once per session —
        // this method is only reached on Tor's single `.connected` transition
        // and on a bounded keep-alive warm return (adoptKeptTor), which happens
        // with the vault locked (the lock ran at `.background`).
        guard !isUnlocked else {
            ConnectionLog.shared.append(
                kind: ConnectionLog.Kind.relay,
                text: "warm-up skipped: unlocked first",
                code: ConnectionLog.Code.warmupSkipped
            )
            return
        }
        guard !wipedThisSession else { return }
        // Never in external proxy mode (unreachable anyway: this hangs off the
        // embedded Tor's .connected, which never happens there).
        guard !ExternalProxyMode.shared.isExternalThisProcess else { return }
        // Also checked Kotlin-side; kept here so the latch below is not spent on a
        // configuration that has nothing to warm.
        guard RelayRoutingKt.relayRoutesViaTor() else { return }
        let port = TorManager.shared.socksPort
        guard port > 0 else {
            ConnectionLog.shared.append(
                kind: ConnectionLog.Kind.relay,
                text: "warm-up skipped: tor not ready",
                code: ConnectionLog.Code.warmupSkipped
            )
            return
        }
        rendezvousWarmupFired = true
        // Returns immediately: the blocking GET runs on the controller's own
        // background scope, which lock() / emergencyWipe() already cancel.
        //
        // `onRotateDue` fires — on that background scope — only
        // when the attempt FAILED having burned (almost) its whole budget and a
        // retry is still allowed. The decision is the shared
        // `RelayWarmup.shouldRotateAndRetry`, evaluated Kotlin-side so Android's
        // sibling cannot drift from it; the NEWNYM itself has to happen here
        // because `TorManager` is main-actor isolated.
        controller.warmRelayRendezvous(socksPort: Int32(port), retriesUsed: 0, onRotateDue: { [weak self] in
            // Arrives on the controller's background scope; TorManager and every
            // field this touches are main-actor isolated (same hop as
            // `onVaultSessionRetired`).
            hopToMain {
                guard let self else { return }
                self.rotateAndRetryWarmup(socksPort: port)
            }
        })
    }

    /// Hands TorManager the SESSION's descriptor hedge and its gate before every
    /// start() (idempotent — re-assigning the same objects is harmless, and
    /// start() itself refuses a second run). The hedge is
    /// `controller.descriptorHedge` (one per IosAppController = one per session,
    /// its budget never replenished by a NEWNYM); the gate is the session's "relay
    /// answered" latch (`controller.relayAnsweredForCircuitWatchdog`). Pre-unlock
    /// included — a stalled warm-up fetch is the same stall the first probe would
    /// wait on. Android sibling: the `descriptorHedge` / `descriptorHedgeAnswered`
    /// constructor arguments in RunViewModel.
    private func installDescriptorHedge() {
        TorManager.shared.descriptorHedge = controller.descriptorHedge
        TorManager.shared.onDescriptorStageStalled = { [weak self] in
            self?.fireDescriptorStageNewnym()
        }
        TorManager.shared.descriptorHedgeAnsweredGate = { [weak self] in
            guard let self else { return true }   // no session: inert
            return self.controller.relayAnsweredForCircuitWatchdog(
                relayAnsweredThisSession: self.relayAnsweredThisSession
            )
        }
    }

    /// Hands TorManager the NEWNYM-accepted hook before every start()
    /// (idempotent): after ANY app-fired `SIGNAL NEWNYM` got its `250` — warm-up
    /// rotation, cold rung, warm rung, sustained/stall rung — the current
    /// transport aborts its in-flight health probe / batch peek (SwiftTorHttp
    /// cancels its open transport connection) and re-probes at once instead of sitting out a
    /// 20 s budget on a retired circuit (`MessageManager.noteNewCircuitRequested`).
    /// Android sibling: the `onNewCircuitAccepted` constructor argument in
    /// RunViewModel. Runs on main; the abort itself never blocks.
    /// Hands TorManager the hung onion-circuit rung's gate before every start()
    /// (idempotent): the rung closes a hung intro / rendezvous circuit only BEFORE
    /// the session's first relay answer (`HsCircuitWatchdog`, shared with Android).
    /// Android sibling: the `hsCircuitAnswered` constructor argument in
    /// RunViewModel.
    private func installHsCircuitGate() {
        TorManager.shared.hsCircuitAnsweredGate = { [weak self] in
            guard let self else { return true }   // no session: inert
            return self.controller.relayAnsweredForCircuitWatchdog(
                relayAnsweredThisSession: self.relayAnsweredThisSession
            )
        }
    }

    private func installNewCircuitHook() {
        TorManager.shared.onNewCircuitAccepted = { [weak self] in
            self?.controller.noteNewCircuitRequested()
        }
    }

    // MARK: - Network-restore kick (2026-10-25)
    //
    // Android sibling: RunViewModel registerNetworkRestoreHook /
    // performNetworkRestoreKick. The decision — baseline, 2 s debounce, 15 s rate
    // limit — is the shared `NetworkRestoreKick`; here only the NWPathMonitor, the
    // one timer and the action:
    //   1. TorManager.kickForNetworkRestore (DisableNetwork 1 -> 0; it aborts the
    //      in-flight probe/peek through onNewCircuitAccepted when connected),
    //   2. the stall watch re-armed (the miss-streak run starts over from now),
    //   3. the opt-out ladder's backoff woken (networkRestoreEpoch).
    // Nothing on a loss. The interface key is an equality key only — never logged.

    private var pathMonitor: NWPathMonitor?
    private let networkRestoreKick = NetworkRestoreKick(
        debounceMs: NetworkRestoreKick.companion.DEBOUNCE_MS,
        minIntervalMs: NetworkRestoreKick.companion.MIN_INTERVAL_MS
    )
    private var networkRestoreCheckItem: DispatchWorkItem?
    /// Rate-limit deferral already logged for the pending restore.
    private var networkRestoreDeferralLogged = false
    /// Bumped after every network-restore kick attempt; read by the opt-out
    /// ladder's backoff (awaitDeregBackoffOrRestore). Main actor only.
    private var networkRestoreEpoch = 0

    /// Process-lifetime (AppState and TorManager.shared both are), so it is never
    /// cancelled; Android's sibling unregisters in onCleared because its owner dies.
    private func startNetworkRestoreMonitor() {
        guard pathMonitor == nil else { return }
        let monitor = NWPathMonitor()
        // Delivered on main; the FIRST update is the current path = the baseline.
        monitor.pathUpdateHandler = { [weak self] path in
            MainActor.assumeIsolated { self?.onNetworkPath(path) }
        }
        pathMonitor = monitor
        monitor.start(queue: .main)
    }

    private func onNetworkPath(_ path: NWPath) {
        // Opaque equality key: the preferred interface's type + BSD name. A switch
        // Wi-Fi -> cellular changes it; never logged.
        let key: String? = path.status == .satisfied
            ? (path.availableInterfaces.first.map { "\($0.type)/\($0.name)" } ?? "satisfied")
            : nil
        let wasUp = networkRestoreKick.isNetworkUp()
        let wait = networkRestoreKick.observe(networkKey: key)
        if key == nil {
            if wasUp {
                networkRestoreCheckItem?.cancel()
                networkRestoreCheckItem = nil
                NetworkRestoreKick.companion.logLost()
            }
            return
        }
        scheduleNetworkRestoreCheck(afterMs: wait)
    }

    /// One timer, replaced on every restore event (that IS the debounce).
    private func scheduleNetworkRestoreCheck(afterMs ms: Int64) {
        guard ms >= 0 else { return }
        networkRestoreCheckItem?.cancel()
        let item = DispatchWorkItem { [weak self] in
            MainActor.assumeIsolated {
                guard let self else { return }
                self.networkRestoreCheckItem = nil
                let d = self.networkRestoreKick.due()
                if d.fire {
                    self.networkRestoreDeferralLogged = false
                    self.performNetworkRestoreKick()
                    return
                }
                guard d.waitMs >= 0 else { return }
                if d.rateLimited && !self.networkRestoreDeferralLogged {
                    self.networkRestoreDeferralLogged = true
                    NetworkRestoreKick.companion.logDeferred(waitMs: d.waitMs)
                }
                self.scheduleNetworkRestoreCheck(afterMs: d.waitMs)
            }
        }
        networkRestoreCheckItem = item
        DispatchQueue.main.asyncAfter(deadline: .now() + Double(ms) / 1000.0, execute: item)
    }

    /// The action. Embedded Tor only: an external proxy or the debug direct path
    /// has no Tor of ours to tell. The ladder wake and the stall-watch re-arm run
    /// whether or not the toggle reached Tor (the ladder waits for its transport).
    private func performNetworkRestoreKick() {
        if ExternalProxyMode.shared.isExternalThisProcess || ExternalProxyMode.shared.endpoint != nil
            || extProxyStatus.isExternal || !RelayConfig.shared.isTorRequired {
            NetworkRestoreKick.companion.logSkip(reason: .notEmbeddedTor)
            return
        }
        if let skip = TorManager.shared.kickForNetworkRestore() {
            NetworkRestoreKick.companion.logSkip(reason: skip)
        }
        // Only for an open session: pre-unlock there is no watch and no ladder.
        if isUnlocked && !isMoveFrozen {
            rearmRelayStallWatchForNetworkRestore()
        }
        networkRestoreEpoch += 1
    }

    /// iOS's stall watch is the miss-streak state in checkRelayReachability: the
    /// unreachable run, its sustained-NEWNYM rung and the stalled escalation all
    /// start over from the restore (Android: startRelayStallWatch with a full
    /// first window). `isRelayReachable` itself is untouched — only an answer
    /// flips it. `.relaunchRequired` is never downgraded.
    private func rearmRelayStallWatchForNetworkRestore() {
        relayUnreachableStreak = 0
        lastStreakBumpAtMs = 0
        unreachableRunStartedAtMs = 0
        lastSustainedNewnymAtMs = 0
        sustainedNewnymsFired = 0
        if relayConnectPhase == .stalled { relayConnectPhase = .connecting }
        LogBuffer.shared.append(level: "D", tag: "NetRestore", message: "network restore: stall watch re-armed")
    }

    /// Opts TorManager into the bootstrap-stall rung before every start()
    /// (idempotent). A switch rather than a gate: below 100 % this Tor process
    /// cannot have produced a relay answer, so the session has nothing to veto
    /// with — every rule lives in the shared `TorBootstrapStall`. For iOS this is
    /// the ONLY rescue for a bootstrap stuck mid-ladder (no in-process restart).
    /// Android sibling: `bootstrapStallKick = true` on every TorManager
    /// RunViewModel builds.
    private func installBootstrapStallKick() {
        TorManager.shared.bootstrapStallKickEnabled = true
    }

    /// The warm-up rotation: ONE `SIGNAL NEWNYM` on a warm-up (started pre-unlock) that
    /// burned its budget, then the single permitted second warm-up attempt. Since
    /// 2026-10-06 it may also fire AFTER unlock, as long as the session has had no
    /// relay round trip yet (`MessageManager.shouldFireWarmupNewnym`, shared with
    /// Android).
    ///
    /// The budget it spends is the controller's `EarlyNewnymLedger` — the SAME per-session budget
    /// the post-unlock cold rung (`maybeFireEarlyNewnym`) spends, capped by
    /// `controller.earlyNewnymMaxFires()` — so the two rungs together can never
    /// exceed the cap whichever fires first. It needs no vault: Tor's control
    /// channel has been up since launch and NEWNYM carries nothing.
    ///
    /// It cannot use `controller.earlyNewnymDue`, whose evidence is full-budget
    /// PROBE_TIMEOUTs on a transport that does not exist yet; the equivalent
    /// evidence here is the warm-up's own burnt budget, already classified by
    /// the shared predicate before this is called. `noteEarlyNewnymFired()` is
    /// still called so a transport that DOES exist never counts pre-unlock
    /// evidence toward its next rung. Android sibling:
    /// `RunViewModel.fireWarmupNewnym`.
    private func rotateAndRetryWarmup(socksPort: UInt16) {
        // An in-session wipe retires the warm-up outright.
        guard !wipedThisSession else { return }
        // Same guard as the cold rung: a dead tor_main cannot rotate anything.
        guard !TorManager.shared.relaunchRequired else { return }
        // THE shared gate (commonMain, identical on Android): no relay round trip
        // yet this session — LOCKED OR NOT — and the per-session NEWNYM budget
        // shared with `maybeFireEarlyNewnym` not spent. Unlocking during those
        // 25 s no longer cancels the rotation (2026-10-06): iPhone users unlock at
        // ~t5, and the session's first probe is stuck on the SAME wedged HS
        // circuits, so refusing here only deferred the rescue to the cold rung at
        // ~t45–50. A session that has ALREADY reached the relay is what refuses.
        // Descriptor-stage early recovery (DescriptorHedge, 2026-10-13): when the
        // 10 s descriptor-stage NEWNYM already fired for this stall it REPLACES
        // this one — retry the warm-up on its fresh circuits, no second NEWNYM.
        // Android sibling: armPreUnlockRelayWarmup, same check.
        if controller.descriptorHedge.stageNewnymFiredThisSession {
            controller.warmRelayRendezvous(socksPort: Int32(socksPort), retriesUsed: 1, onRotateDue: nil)
            return
        }
        guard controller.warmupNewnymAllowed(
            relayAnsweredThisSession: relayAnsweredThisSession,
            newnymsFiredThisSession: controller.earlyNewnymFiredThisSession()
        ) else { return }
        guard TorManager.shared.requestNewCircuit() else {
            // Deliberately does NOT retire the session budget the way the
            // post-unlock sibling does: this runs seconds after Tor first
            // reported connected, when the control channel can still be coming
            // up, and spending the whole ladder on that timing would be wrong.
            // The post-unlock rung retries and retires it if it is really gone.
            LogBuffer.shared.append(level: "W", tag: "Relay",
                message: "NEWNYM unavailable (control channel down) — warm-up circuit rotation skipped")
            return
        }
        // The panel line is the EXISTING cold-rung phrase with the same shared
        // counter, because this IS that rung fired on pre-unlock evidence — the
        // WARMUP_FAILED line immediately above it in the panel says which evidence.
        bookEarlyNewnym(cold: false,
                        logMessage: "rendezvous warm-up burned its budget — requested fresh Tor circuits")
        // retriesUsed: 1 == RelayWarmup.MAX_RETRIES, so this attempt can never
        // ask for another rotation — the shared predicate refuses it.
        controller.warmRelayRendezvous(socksPort: Int32(socksPort), retriesUsed: 1, onRotateDue: nil)
    }

    /// DESCRIPTOR-STAGE EARLY RECOVERY (2026-10-13; Android sibling
    /// `RunViewModel.fireDescriptorStageNewnym`). TorManager calls it on main when
    /// the shared `DescriptorHedge` decided the descriptor episode is still open
    /// 10 s after its first request with the hedge budget spent or ≥ 2 requests
    /// outcome-less. ONE NEWNYM through the SAME shared gate and budget as the
    /// warm-up rotation (`controller.warmupNewnymAllowed`: no relay answer yet,
    /// the `EarlyNewnymLedger` count under the shared cap), so it is never a third NEWNYM;
    /// the warm-up rotation then retries without its own.
    private func fireDescriptorStageNewnym() {
        guard !wipedThisSession else { return }
        guard !TorManager.shared.relaunchRequired else { return }
        guard controller.warmupNewnymAllowed(
            relayAnsweredThisSession: relayAnsweredThisSession,
            newnymsFiredThisSession: controller.earlyNewnymFiredThisSession()
        ) else {
            LogBuffer.shared.append(level: "D", tag: "Relay",
                message: "descriptor stage stalled — NEWNYM refused by the session gate")
            return
        }
        DescriptorHedge.companion.logStageStalled()
        guard TorManager.shared.requestNewCircuit() else {
            LogBuffer.shared.append(level: "W", tag: "Relay",
                message: "NEWNYM unavailable (control channel down) — descriptor-stage rotation skipped")
            return
        }
        controller.descriptorHedge.noteStageNewnymFired()
        bookEarlyNewnym(cold: false,
                        logMessage: "descriptor stage stalled — requested fresh Tor circuits")
    }

    /// Books ONE early NEWNYM that has just been requested (the warm-up rotation,
    /// the descriptor-stage rung, the cold-start rung): bumps the shared session
    /// budget in the Kotlin `EarlyNewnymLedger` (`controller.noteEarlyNewnymSpent`,
    /// + the cold-rung count when [cold]), resets the evidence
    /// (`controller.noteEarlyNewnymFired`), and writes the log line and the EXISTING
    /// coded NEWNYM panel line — verbatim, numbers only; Android emits the
    /// identical string so the panel reads the same on both platforms.
    private func bookEarlyNewnym(cold: Bool, logMessage: String) {
        _ = controller.noteEarlyNewnymSpent(cold: cold)
        controller.noteEarlyNewnymFired()
        let phrase = controller.earlyNewnymPhrase()
        LogBuffer.shared.append(level: "W", tag: "Relay",
            message: "\(logMessage) (\(phrase))")
        ConnectionLog.shared.append(
            kind: ConnectionLog.Kind.stall,
            text: "relay unreachable - requesting fresh circuits (\(phrase))",
            code: ConnectionLog.Code.newnym
        )
    }

    // Device integrity — true if jailbreak detected.
    @Published var isDeviceCompromised = false

    // Observed state that drives navigation.
    @Published var isUnlocked = false
    @Published var isConfigured = false

    // Debug mode (settings row, ContactListView `settings_debug_mode`) —
    // DebugMode.kt in commonMain, Keychain-backed via IosAppController's own
    // KeyValueStore instance (see [setDebugMode]). Read from the store at
    // init below so a toggle made in a previous session (this app, or a
    // previous RELEASE install — see RunApp.init's DebugMode.applyAtStartup)
    // is reflected immediately, before the settings sheet is ever opened.
    @Published var debugMode = false

    // First-open push-notification prompt: set by [unlock] / [recoverWithCode]
    // from the shared, one-shot `consumePushPromptOnce()` vault-meta latch
    // (PushPromptOnboarding.kt in commonMain) — true only on the very first
    // unlock this vault has ever seen. Rendered by ContactListView (it owns
    // showPushSettings, the carousel this prompt's "Yes" opens), gated on
    // parity with Android's RunViewModel.showPushPrompt.
    @Published var showPushPrompt = false

    // In-app update nudge: holds the relay-advertised version string once the
    // health loop (checkRelayReachability) has evaluated it true for this
    // session (see UpdateNudge.kt in commonMain for the once-per-day-per-version
    // throttle). nil = no nudge to show. Rendered by ContactListView, gated on
    // `!showPushPrompt` (lowest priority — no priority queue, so only one dialog
    // binding may read true at a time) —
    // parity with Android's RunViewModel.showUpdateNudge.
    @Published var showUpdateNudge: String? = nil

    // Introducer-side "your intro got relayed" info modal: fed by
    // ReferralManager.onIntroRelayed (commonMain), fired whenever an
    // introducee's accept lands on this device (the introducer) and gets
    // passed on to the other party — a FIFO because both introducees can
    // accept in quick succession and each is its own info dialog, never
    // coalesced. RAM-only (unlike the offer/consent queues above, this is
    // pure notification — nothing to persist across a relaunch). Rendered by
    // ContactListView; dismissReferralRelayEvent() pops the head. Android
    // sibling: RunViewModel's equivalent queue over the same hook.
    @Published var referralRelayEvents: [ReferralRelayEvent] = []

    // Group invites the user closed with "Later" this session (group ids only,
    // RAM only, NOT @Published: ContactListView re-derives its rows itself).
    // The consent surface does not auto-present them again; they show as rows in
    // the groups area. Cleared in clearInMemoryIdentifierMaps() (lock / wipe).
    // Lives here, not in the view, so it survives the list's view lifecycle.
    // Android sibling: RunViewModel.deferredGroupInviteIds.
    var deferredGroupInviteIds: Set<String> = []

    // Referral offers (introIds, base64url) closed with "Later" this session: the
    // same non-blocking rule and lifetime as deferredGroupInviteIds (RAM only, not
    // @Published, cleared with it). Approve un-defers first so a failed accept
    // re-presents as Retry. Android sibling: RunViewModel.deferredReferralOfferIds.
    var deferredReferralOfferIds: Set<String> = []

    // In-app store-review nudge (ReviewPromptPolicy.kt in commonMain — the
    // pure decision function; everything here is orchestration). A one-shot
    // per-session SIGNAL, not a dialog: ContactListView's
    // `@Environment(\.requestReview)` action needs a SwiftUI View context
    // AppState itself doesn't have, so this just flips true once
    // checkRelayReachability decides to ask, and ContactListView calls
    // `consumeRequestReviewFlow()` right after it fires the OS review sheet
    // request. Parity with Android's RunViewModel.requestReviewFlow.
    @Published var requestReviewFlow = false

    /// ContactListView calls this immediately after it has (attempted to)
    /// invoke `requestReview()` for a fired [requestReviewFlow].
    func consumeRequestReviewFlow() {
        requestReviewFlow = false
    }

    // Set by an IN-SESSION emergencyWipe() (e.g. 5 wrong PINs)
    // and never cleared until the process is relaunched. ContentView shows a
    // persistent black screen while this is set, so a coercer who forces a wipe
    // sees a screen indistinguishable from powered-off — NOT a fresh setup
    // screen (which would reveal a wipe just occurred). A genuine relaunch
    // (fresh process) resets this to false and shows setup, exactly like Android,
    // whose startDestination is computed once per launch. The launch-time
    // orphan / 7-day wipes intentionally do NOT set this (they route to setup on
    // that fresh launch, matching Android).
    @Published var wipedThisSession = false

    // The transport half of the published state (torState, extProxyStatus, the
    // three bootstrap-stall tiers) lives in [transport] (AppState+TransportStatus.swift);
    // views keep reading it through the read-only forwarders there.

    /// Wall-clock (uptime) of the last proxy reachability probe — rate limit for
    /// the re-probe the health loop triggers on a missed relay answer.
    private var extProxyLastProbeUptime: TimeInterval = 0
    private var extProxyProbeInFlight = false
    /// Bounded re-resolution of an UNREADABLE setting at unlock (see
    /// connectViaExternalProxyIfConfigured). Never more than 3 per process.
    private var extProxyUnreadableRetries = 0


    // Relay reachability — true when the relay server responds to HTTP.
    @Published var isRelayReachable: Bool = false
    /// THE contact-list reveal gate (user requirement 2026-09-14): the relay has
    /// answered AND the connect-time unread prime has settled, so every
    /// "message waiting" dot is already in `unreadCounts` in the frame the
    /// runestone lights and the contacts appear. `isRelayReachable` stays the
    /// raw outage signal (relay-trouble banner, row dimming, send enablement);
    /// only ContactListView's connect transition keys on this. Android sibling:
    /// `RunViewModel.contactsReady`.
    @Published var contactsReady: Bool = false
    /// The prime's FIRST per-contact result landed (C4b), or the pass ended
    /// without emitting anything (no contacts, every peek failed, cancelled), or
    /// it was skipped, or the `unreadPrimeRevealCapSec` backstop counted from the
    /// first relay answer ran out. Reset with `isRelayReachable` (per transport,
    /// in stopRelayCheck). Every write goes through `settleUnreadPrime`, which
    /// owns the shared rules in `ConnectReveal`.
    private var unreadPrimeSettled = false
    private var unreadPrimeCapTask: Task<Void, Never>? = nil
    /// Backstop for `contactsReady`: 3 s since C4b — the gate now releases on the
    /// prime's FIRST per-contact result, so this only ever covers a genuinely
    /// wedged peek. THE number is `ConnectReveal.UNREAD_PRIME_REVEAL_CAP_MS` in
    /// commonMain, which Android's `RunViewModel.UNREAD_PRIME_REVEAL_CAP_MS`
    /// reads too, because it is printed into a panel line both platforms must
    /// emit word for word.
    private static let unreadPrimeRevealCapSec: TimeInterval =
        TimeInterval(ConnectReveal.shared.UNREAD_PRIME_REVEAL_CAP_MS) / 1000

    /// Narrated + measured at most once per session — see `markRevealIfNeeded`.
    private var revealMarked = false

    private func recomputeContactsReady() {
        // The predicate itself is shared with Android's
        // `RunViewModel.contactsReady` — see ConnectReveal.kt.
        // "Relay answered" = the probe-driven reachability flag OR this transport's
        // own first completed onion round trip (2026-10-26, connect-time lever):
        // the prime's first /peek 2xx IS a relay answer, and in 19 of 21 measured
        // prod unlocks it landed 130 ms (p50) to 500 ms (max) BEFORE the parallel
        // health probe that used to be the only thing that could flip this gate.
        // The latch is per MessageManager, i.e. per transport, exactly like the
        // two halves of the gate; send enablement and the outage banner stay on
        // isRelayReachable alone. Android: RunViewModel.contactsReady.
        // The round-trip latch is a REVEAL accelerator only. It is monotonic for the
        // transport's lifetime, so on its own it kept the list "ready" — lit
        // runestone, relay-gated rows enabled — through a relay OUTAGE (2026-11-04:
        // the simulator runestone never dimmed after the relay died although the
        // probe had latched `reachable: true → false`). Once the miss hysteresis has
        // latched the relay unreachable the accelerator is spent and the published
        // flag is the only truth. Android sibling: `_relayFirstAnswer` is cleared on
        // the same latch in RunViewModel's health loop.
        let roundTripDone = controller.messageManager?.hasCompletedRelayRoundTrip() ?? false
        let latchedUnreachable = relayUnreachableStreak >= AppState.relayUnreachableStreakLimit
        let ready = ConnectReveal.shared.contactsReady(
            relayAnswered: isRelayReachable || (roundTripDone && !latchedUnreachable),
            primeSettled: unreadPrimeSettled
        )
        if ready != contactsReady { contactsReady = ready }
        if ready { markRevealIfNeeded() }
    }

    /// THE END OF THE USER'S WAIT: one panel line and one measurement at the instant `contactsReady`
    /// first turns true — the frame the contact list actually appears in.
    ///
    /// Why it is not `isRelayReachable`: since the reveal gate landed the list
    /// also waits for the connect-time unread prime to settle (bounded by
    /// `unreadPrimeRevealCapSec`), and in 44 of 45 measured iOS timelines that
    /// prime had NOT finished when the relay answered — so `secs` stopped
    /// several seconds before the user saw anything and nothing measured the
    /// difference.
    ///
    /// `ConnectTelemetry.markRevealed` is set-once per SESSION (a process latch,
    /// re-armed by `beginWarmTorSession` through `startNewRevealSession` when the
    /// bounded Tor keep-alive lets a second session live in this process) and is
    /// read by the report after its jitter delay, so a reveal landing while the
    /// report sleeps still counts; one that outlives it omits the field rather
    /// than delaying the report. `revealMarked` is reset with the rest of the
    /// session (stopRelayCheck), so an in-process re-auth unlock narrates its own
    /// reveal while the telemetry latch underneath keeps describing the FIRST
    /// connect of the session.
    /// Android sibling: `RunViewModel.armRevealMark`.
    private func markRevealIfNeeded() {
        guard !revealMarked else { return }
        revealMarked = true
        if let connectStartedAt = connectStartUptime {
            let elapsedMs = min(max(0, ProcessInfo.processInfo.systemUptime - connectStartedAt), 86_400) * 1000
            ConnectTelemetry.shared.markRevealed(msSinceConnectAnchor: Int64(elapsedMs))
        }
        // Fixed phrase, no number and no identifier — the panel's own timestamp
        // is the number. Android emits this string verbatim.
        ConnectionLog.shared.append(
            kind: ConnectionLog.Kind.relay,
            text: "contact list revealed",
            code: ConnectionLog.Code.reveal
        )
    }

    /// Settles the unread-prime half of `contactsReady` — the ONLY place that
    /// flips it true — and re-evaluates the reveal gate.
    ///
    /// The decision (is this the first event? does it narrate PRIME_CAP?) lives
    /// in `ConnectReveal.primeSettle` in commonMain, so Android's
    /// `RunViewModel.settleUnreadPrime` reveals on exactly the same evidence and
    /// emits the same panel line. Everything here is @MainActor, so the flip
    /// needs no lock (Android's callers are on two different threads and pair the
    /// predicate with a compare-and-set).
    private func settleUnreadPrime(_ event: ConnectReveal.PrimeEvent) {
        let outcome = ConnectReveal.shared.primeSettle(alreadySettled: unreadPrimeSettled, event: event)
        guard outcome.settles else { return }
        unreadPrimeSettled = true
        unreadPrimeCapTask?.cancel(); unreadPrimeCapTask = nil
        if outcome.logCapLine {
            LogBuffer.shared.append(level: "W", tag: "AppState", message: "unread prime reveal cap hit — revealing contacts without it")
            // PRIME_CAP (C4a): the reveal was held by a wedged peek, not by the
            // network — without a code this line was invisible to the connect
            // timeline. Android emits the identical phrase.
            ConnectionLog.shared.append(
                kind: ConnectionLog.Kind.relay,
                text: "unread prime cap \(Int(AppState.unreadPrimeRevealCapSec)) s — revealing contacts",
                code: ConnectionLog.Code.primeCap
            )
        } else {
            let why = event.name.lowercased().replacingOccurrences(of: "_", with: " ")
            LogBuffer.shared.append(level: "D", tag: "AppState", message: "unread prime settled (\(why)) — contacts may reveal")
        }
        recomputeContactsReady()
    }

    // "We have actually talked to the relay on this Tor session" — latched on the
    // first COMPLETED `.onion` round-trip (MessageManager.hasCompletedRelayRoundTrip),
    // NOT on Tor's `Bootstrapped 100%`. Bootstrap only proves Tor reached the directory
    // system and built *a* circuit; the hidden-service descriptor fetch + rendezvous with
    // the relay's onion happens afterwards and routinely takes several more seconds. This
    // is the HONEST "connected" evidence.
    //
    // Android parity: RunViewModel._relayHandshakeComplete (StateFlow), mirrored the SAME
    // way — read off MessageManager.hasCompletedRelayRoundTrip() in the reachability loop,
    // never a new source of truth. Unlike [isRelayReachable] the shared latch is monotonic
    // for the lifetime of a transport, so this does not flap on a transient miss; it drops
    // to false only when the transport itself is torn down (lock / wipe / relay-loss),
    // reset in stopRelayCheck() alongside isRelayReachable — the same pairing Android resets
    // together (RunViewModel restartTor() / session teardown).
    //
    // Added for cross-platform parity/observability. NO VIEW OBSERVES IT: it is read only
    // inside AppState (publishRelayHandshake). It stays @Published for now because
    // its writes also fire objectWillChange, which computed view inputs reading
    // non-published state may rely on; demoting it is a separate, reviewed decision.
    // Follow-up if the "reaching the relay…" copy should prefer it the way Android's
    // ContactListScreen does (litVisible ← isRelayReachable is close, but this is the
    // strictly-honest signal).
    @Published var relayHandshakeComplete: Bool = false

    // Relay-connect stall UX (QA report #1). iOS already self-heals a wedged circuit
    // (NEWNYM in checkRelayReachability); once that's had several tries and the relay is
    // STILL unreachable, flip to .stalled so the contact list can offer a manual Reconnect
    // (another NEWNYM kick) + a relaunch hint — iOS can't restart Tor in-process, so a
    // truly dead Tor thread needs an app relaunch. Resets to .connecting on the next hit.
    // `.relaunchRequired`: TorManager latched this process as unable to ever
    // produce a working Tor again (dead thread / terminal bootstrap failure /
    // post-wipe stop). Distinct from `.stalled` — Reconnect (NEWNYM) is useless
    // here; the UI shows a close-and-reopen hint instead, and ContentView
    // recycles the process on the next `.background`. Never downgraded.
    enum RelayConnectPhase { case connecting, stalled, relaunchRequired }
    @Published var relayConnectPhase: RelayConnectPhase = .connecting

    // contactId → count of text blobs waiting on the relay — the contact-list
    // unread badge count. Driven by a non-destructive /peek sweep on the
    // control-poll loop; cleared optimistically when a conversation opens
    // (markContactRead).
    @Published var unreadCounts: [String: Int] = [:]

    // groupId → count of unread group messages — the GROUP row's unread dot.
    // Driven by KIND_ACTIVITY control notices (group texts share members' 1:1
    // inboxes, so the /peek sweep can't attribute them); cleared when the group
    // conversation opens (markGroupRead).
    @Published var groupUnreadCounts: [String: Int] = [:]

    // contactId → true once IosAppController.forwardSecrecyStalled
    // reports the per-contact legacy-fallback counter (dr-legacyfb) has crossed the
    // stall threshold — the responder's ratchet still has no sending chain, so this
    // device's outbound direction keeps falling through to the no-forward-secrecy
    // static envelope. A SIGNAL for the 1:1 conversation notice row, never a send
    // gate. Refreshed on conversation open and after every completed send — see
    // [refreshForwardSecrecyStalled] and ConversationView's sendMessage; no polling
    // loop. Android sibling: RunViewModel.forwardSecrecyStalled.
    @Published var forwardSecrecyStalled: [String: Bool] = [:]

    /// Re-evaluates [forwardSecrecyStalled] for one contact. Cheap — a single `_meta`
    /// read — so it's fine to call inline like [refreshMoveFrozen]; best-effort like
    /// every other bridge read off this counter: no transport yet or a transient
    /// vault-read hiccup both read as "not stalled" (never a false positive).
    func refreshForwardSecrecyStalled(contactId: String) {
        forwardSecrecyStalled[contactId] = controller.forwardSecrecyStalled(contactId: contactId)
    }

    // contactId → true once IosAppController.ratchetRefused reports the
    // secure channel with this contact has provably failed to establish and sends
    // are being refused (the role-binding latch). Backs the
    // `ratchet_refused_notice` conversation row, which takes precedence over
    // [forwardSecrecyStalled]'s row when both would show. Refreshed on conversation
    // open, after every completed send, and on every poll tick — the last one
    // because, unlike [forwardSecrecyStalled], this signal is cleared by an INBOUND
    // ratchet blob, not only by our own send landing. Android sibling:
    // RunViewModel.ratchetRefused.
    @Published var ratchetRefused: [String: Bool] = [:]

    /// Re-evaluates [ratchetRefused] for one contact. Cheap — a single `_meta` read
    /// — best-effort like [refreshForwardSecrecyStalled]: no transport yet or a
    /// transient vault-read hiccup both read as "not refused" (never a false
    /// positive that would tell a user to re-pair a healthy contact).
    func refreshRatchetRefused(contactId: String) {
        ratchetRefused[contactId] = controller.ratchetRefused(contactId: contactId)
    }

    // "Move to new device" (docs/device-move.md). Both are RAM-only by design.
    //
    // [isMoveFrozen] mirrors the vault's `mig_frozen` row and is recomputed on
    // every vault open (unlock / recoverWithCode) — while it is true ContentView
    // routes to the frozen screen INSTEAD of the contact list, on every unlock,
    // until the user wipes or a cancel proves the bundle undrained.
    //
    // [pendingMoveHandle] is the NEW phone's scanned/pasted handle: it carries the
    // one-time code and MUST NEVER be persisted (docs/device-move.md, Protocol B2 —
    // "parse into RAM only. No persistence: process death means rescan"). Set by
    // MoveFromDeviceView before onboarding, consumed by the post-unlock import.
    @Published var isMoveFrozen = false
    @Published var pendingMoveHandle: MoveHandle? = nil

    /// Re-reads `mig_frozen` from the (now open) vault. Cheap — one `_meta` read.
    func refreshMoveFrozen() {
        controller.moveRefreshFrozenState()
        isMoveFrozen = controller.moveIsFrozen()
        if isMoveFrozen {
            LogBuffer.shared.append(level: "W", tag: "Move", message: "vault is frozen for a move — routing to the frozen screen")
        }
    }

    /// Fresh-credential gate in front of "Move to new device".
    /// Mirrors `verifyCurrentPin`: the guess counts against the daily change-PIN
    /// budget (recorded first), the cap runs the emergency wipe, and on a Lever B
    /// vault the Secure-Enclave biometric is demanded too. `ok` grants the
    /// single-use token `moveBeginExport` consumes (Kotlin refuses without it).
    /// Heavy + may prompt — off the main thread; `completion` lands on main with
    /// "ok" / "wrong" / "wipe" / "deferred".
    func verifyMoveExportAuth(_ credential: String, completion: @escaping (String) -> Void) {
        DispatchQueue.global(qos: .userInitiated).async { [self] in
            let outcome = controller.moveVerifyExportAuth(credential: credential)
            hopToMain {
                if outcome == "wipe" { self.emergencyWipe() }
                completion(outcome)
            }
        }
    }

    // Contacts the relay has persistently 404'd (inbox lost server-side) → the
    // list flags them for re-pair (same UX as a stale contact). Refreshed by the
    // control poll; a change posts .contactsChanged so loadContacts re-computes.
    @Published var relayLostContacts: Set<String> = []

    /// Tor bootstrap progress normalized to 0.0–1.0.
    var torProgress: Double {
        switch torState {
        case .disconnected: return 0.0
        case .bootstrapping(let p): return Double(p) / 100.0
        case .connected: return 1.0
        }
    }

    var isTorConnected: Bool {
        if !RelayConfig.shared.isTorRequired { return true }
        return torState == .connected
    }

    // -----------------------------------------------------------------------
    // Two-phase pre-connect status line — Android sibling: androidApp's
    // RelayConnectHints.connectStatusLine (both platforms source the SAME
    // connect_* L10n keys from strings_contact_list.xml, so the wording can't
    // drift). A single "…100%" caption used to be misleading because it mapped
    // Tor-Connected straight to 100% while the relay handshake was still in
    // flight, so the line has TWO phases: Tor bootstrap, then the relay
    // handshake. This function picks the WORDING only.
    //
    // The bootstrap percent is deliberately NOT part of this text: a frozen
    // percent reads as a hang, so the render sites show an animated dots
    // cadence instead (ContactListView's `RelayConnectingCaption`). The percent
    // still exists internally: BootstrapProgressPacer paces it, it drives the
    // ring-pulse opacity, and it appears in the ConnectionLog panel / telemetry. A static (not an instance method) so both ContactListView and
    // AddContactView can call it without an AppState instance detour.
    // -----------------------------------------------------------------------

    /// The single pre-connect status line — pure phase wording, no percent.
    /// [externalProxy]: external SOCKS proxy mode — the embedded Tor never starts,
    /// so the Tor phase wording would be false; the pre-proxy phase says the
    /// user's proxy is being reached instead.
    static func connectStatusLine(torConnected: Bool, externalProxy: Bool = false) -> String {
        if torConnected { return L10n.connectRelayPhase }
        return externalProxy ? ExtProxyText.connectingPhase : L10n.connectTorPhase
    }

    var vault: VaultDatabase? { controller.vault }

    // -----------------------------------------------------------------------
    // Unlock
    // -----------------------------------------------------------------------

    // CR-1: controller.unlock() does PBKDF2 + AEAD + SQLCipher open — run
    // it off the main thread so the PIN UI stays responsive. Result and
    // all @Published state changes are delivered on the main queue.
    func unlock(pin: String, completion: @escaping @MainActor (UnlockOutcome) -> Void) {
        LogBuffer.shared.append(level: "D", tag: "AppState", message: "unlock attempt")
        DispatchQueue.global(qos: .userInitiated).async { [self] in
            // Tri-state from IosAppController.unlock (Kotlin Int → Swift Int32):
            // .opened / .denied (wrong PIN — counts) / .error (transient — retry).
            let outcome = UnlockOutcome(rawValue: Int(controller.unlock(credential: pin))) ?? .error
            hopToMain {
                if outcome == .opened {
                    self.didOpenVault()
                } else {
                    LogBuffer.shared.append(level: "W", tag: "AppState", message: "unlock not opened: \(outcome)")
                }
                completion(outcome)
            }
        }
    }

    /// The `.opened` branch of unlock(), on the main actor right after the vault opened.
    private func didOpenVault() {
        self.isUnlocked = true
        // A successful unlock is a stronger proof the vault exists than
        // anything `isConfigured` was previously derived from, and it is
        // the ONE flip `setRealCredentialWithLevel`'s completion
        // deliberately skips (see its own comment: flipping there would
        // route ContentView to PinEntryView mid-onboarding, before the
        // PRIVATE-tier recovery-code step has even shown). Left
        // perpetually false for the rest of the process, a fresh
        // onboarding session that later re-locks IN-PROCESS with no
        // intervening relaunch — the periodic MAXIMUM re-auth timer, or
        // release-build Lever C idle auto-lock — flipped `isUnlocked`
        // back to false with `isConfigured` still false, and ContentView
        // fell all the way through PinEntryView to first-run
        // PinSetupView's "choose protection level" chooser instead of the
        // re-auth/lock passphrase prompt (reauth.spec.ts, 2026-09-28).
        // Setting it HERE, once, on the very first unlock a fresh vault
        // ever sees, closes that window for every later in-process lock
        // this process lives through; a genuine relaunch already
        // recomputes it independently via runLaunchSecurityChecks. A
        // no-op for the far more common returning-user unlock, where
        // this is already true.
        self.isConfigured = true
        // DEBUG-ONLY test seam: the vault is now open, so seed any
        // --test-seed-contacts=<N> fake contacts before the contact
        // list first reads them. No-op unless the arg is present;
        // compiled out of Release. See seedTestContactsIfRequested.
        #if DEBUG
        self.seedTestContactsIfRequested()
        #endif
        // Assigned PROMPTLY, right after the vault opens (see the helper).
        self.installReferralSessionHooks()
        // Re-arm the per-session push-prompt offer on every unlock.
        // The prompt itself is raised on the FIRST relay answer of
        // the session — see maybeOfferPushPromptOnRelayContact
        // and the gate in PushPromptOnboarding.kt.
        self.pushPromptOfferedThisSession = false
        // "Move to new device": is this vault the OLD phone of a
        // move? Read on EVERY open (the flag is a vault row, so it
        // survives relaunches) — ContentView shows the frozen screen
        // instead of the contact list while it is true.
        self.refreshMoveFrozen()
        // In-app store-review nudge (ReviewPromptPolicy.kt,
        // commonMain): record this unlock in the vault's
        // `_meta` singleton on EVERY unlock, unconditionally
        // — the actual ask-or-not decision is made once per
        // session in checkRelayReachability, alongside the
        // update nudge. It is
        // vault-backed now, not plaintext UserDefaults — see
        // ReviewPromptStore's class doc.
        if let openVault = self.controller.vault {
            ReviewPromptStore.recordUnlock(vault: openVault)
        }
        let wasWiped = self.inactivityCrypto.isWiped()
        LogBuffer.shared.append(level: "D", tag: "AppState", message: "vault unlocked, inactivityCrypto.wiped=\(wasWiped)")
        if wasWiped {
            // @Throws — a transient Keychain failure here used to
            // abort the process. Leaving the key wiped is safe: the
            // next crypto use reloads it lazily (requireKeyLocked).
            do {
                try self.inactivityCrypto.reloadKey()
                LogBuffer.shared.append(level: "D", tag: "AppState", message: "inactivityCrypto key reloaded")
            } catch {
                LogBuffer.shared.append(level: "W", tag: "AppState", message: "inactivityCrypto reload deferred — key unavailable")
            }
        }
        InactivityWipe.touch(crypto: self.inactivityCrypto)
        self.startTorOrDirect()
        // Re-request an APNs token on every
        // successful unlock, not just at launch — a vault
        // re-lock (background, foreground auto-lock) is where
        // this process most often sits between one unlocked
        // stretch and the next, and this is what
        // [refreshPushRegistrationIfNeeded] depends on ever
        // having a non-nil [lastPushDeviceToken] to resync
        // from. No-op unless the AUTHENTICATED consent says
        // vendor push (see its own guard).
        //
        // This is now the FIRST APNs request of the session (the
        // pre-unlock one in RunApp is gone), and it is correctly
        // placed: the vault is open here, which the consent
        // proof's in-vault freshness epoch requires.
        self.registerApnsIfPushConsentProven()
        // After unlock the in-app unread dots are the source
        // of truth again — the relay's aps.badge:1 already
        // did its terminated-app job; clear it here so it
        // doesn't sit stale until the next lock() recomputes
        // it from the (now-populated) unread maps.
        self.setAppIconBadge(false)
        // An Argon2 unlock that FINISHES after the user left must
        // not leave an unlocked vault in a background process —
        // which, since the bounded Tor keep-alive, can survive the
        // background. ContentView's `.onChange(isUnlocked)` +
        // `.background` re-lock is the other guard, but SwiftUI may
        // deliver it late; this one is synchronous, on the same
        // main-actor turn that set isUnlocked = true.
        self.relockIfUnlockedInBackground(site: "unlock")
    }

    #if DEBUG
    // -----------------------------------------------------------------------
    // DEBUG-ONLY throwaway test seam — seed N fake contacts on launch.
    //
    // Mirrors the --test-wipe-on-launch= / --test-reauth-interval-ms= launch-arg
    // handling in RunApp.init(), but runs HERE (post-unlock) because the insert
    // needs an OPEN vault, which RunApp.init cannot provide. When the process was
    // launched with --test-seed-contacts=<N>, inserts N fake contacts into the
    // now-open vault so a full contact list renders on-device for a UI bug repro.
    //
    // STRICTLY gated: the whole thing is #if DEBUG (never in a Release binary),
    // AND it is a hard no-op unless the launch arg is present. The fake records
    // carry only the minimum ContactRecord fields a list row needs (a unique
    // contactId, a "Seed NN" alias, a random shared secret, defaults for the
    // rest); they have NO inbox/capability rows, so a seeded contact renders as
    // "Repair required" and a tap may fail to open a conversation — acceptable
    // for this test (the goal is a full, scrollable, tappable list of rows).
    // -----------------------------------------------------------------------
    private func seedTestContactsIfRequested() {
        guard !didSeedTestContacts else { return }
        guard let arg = ProcessInfo.processInfo.arguments
                .first(where: { $0.hasPrefix("--test-seed-contacts=") }),
              let n = Int(arg.split(separator: "=", maxSplits: 1)[1]), n > 0 else { return }
        guard let vault = controller.vault else { return }
        didSeedTestContacts = true
        let nowMs = Int64(Date().timeIntervalSince1970 * 1000)
        for i in 1...n {
            // Deterministic, test-namespaced id so a cold relaunch that re-runs
            // this (INSERT OR REPLACE keys on contact_id) replaces rather than
            // duplicates. Zero-padded alias so the LAST row is identifiable.
            let cid = String(format: "seedtestcontact%02d", i)
            // 32 random bytes — a syntactically-valid shared secret. Never talks
            // to a relay in this test; UInt8.random avoids a Security import.
            let secret = Data((0..<32).map { _ in UInt8.random(in: UInt8.min...UInt8.max) })
            let record = ContactRecord(
                contactId: cid,
                sharedSecret: kotlinByteArray(from: secret),
                trustLevel: 0,
                alias: String(format: "Seed %02d", i),
                aliasLastRotated: nowMs,
                mnemonic: "",
                outboundCounter: 0,
                inboundCounter: 0,
                inboundEpoch: "",
                outboundCtlCounter: 0,
                inboundCtlCounter: 0,
                // v10 group-channel counters — Kotlin default arguments do not
                // cross the ObjC bridge, so every field is positional here.
                outboundGrpCounter: 0,
                inboundGrpCounter: 0,
                vouchedByContactId: nil,
                vouchedAt: 0
            )
            _ = try? vault.insertContact(contact: record)
        }
        LogBuffer.shared.append(level: "W", tag: "DiagSwift",
                                message: "test-seed-contacts: inserted \(n) fake contacts")
        // If the contact list already rendered (its onAppear ran before this),
        // its .contactsChanged subscription re-reads the vault and shows them.
        NotificationCenter.default.post(name: .contactsChanged, object: nil)
    }

    #endif

    /// Set only for the duration of [lockInForegroundScene]'s call into lock(): the
    /// scene is still on screen (`.active`, or `.inactive` behind the privacy cover —
    /// Control Center, app switcher), so the lock leaves Tor running and does not
    /// block on the Debug-mode flush, exactly like an `.active` lock.
    private var lockStaysInForegroundScene = false

    /// An IN-SCENE lock — ContentView's periodic re-auth and Lever-C idle locks,
    /// including an overdue re-auth fired while `.inactive`. The vault side of
    /// lock() is unchanged; only its Tor-teardown gate reads this reason instead of
    /// `applicationState`, so a re-auth that fires while `.inactive` keeps the
    /// daemon and the re-unlock from the PIN screen re-wires to it (no relaunch).
    /// Any tier, MAXIMUM included: an `.active` re-auth lock has always kept Tor,
    /// and MAXIMUM's no-keep-alive rule applies on the `.background` that follows
    /// (handleSceneEnteredBackground: armTorKeepAliveOnBackground refuses → stop()
    /// + recycle). Never used on a `.background` path.
    func lockInForegroundScene() {
        lockStaysInForegroundScene = true
        defer { lockStaysInForegroundScene = false }
        lock()
    }

    /// Locks the vault without wiping data; forces credential re-entry. Swift half:
    /// stops pollers, flushes the Debug-mode batch, stops Tor and clears the RAM logs.
    /// Kotlin half (`controller.lock()` = IosAppController.lock): cancels the session
    /// and move scopes, drops the move code, closes the ack fence, closes the vault,
    /// scrubs manager RAM (ends the parked-send session) and wipes the device key.
    func lock() {
        LogBuffer.shared.append(level: "D", tag: "AppState", message: "lock() — clearing session state")
        // Bounded Tor keep-alive, ABSOLUTE residue cap: the moment an UNLOCKED
        // session ended is what the cap measures from (a double lock() or a lock
        // with nothing open must not move it). See torKeepAliveResidueLeftSec.
        if isUnlocked { lastUnlockedSessionLockUptime = ProcessInfo.processInfo.systemUptime }
        isUnlocked = false
        sessionGeneration &+= 1
        // Captured BEFORE stopRelayCheck() clears it — the Debug-mode "lock"
        // flush further down is skipped entirely on a session whose relay was
        // not answering (see there).
        let relayWasUp = isRelayReachable
        stopRelayCheck()
        // Debug mode's "lock" upload (DebugLogUploader.kt) — the TRANSPORT is
        // snapshotted HERE, before `controller.lock()` below drops
        // `messageManager` (the vault closes there — see
        // IosAppController.lock()); a nil snapshot means "the vault is
        // already closed" (a double lock(), or a lock() with nothing ever
        // unlocked), so the flush below has nothing to do. The ACTUAL upload
        // attempt is deliberately deferred past the crypto-erase-first block
        // (controller.lock() + inactivityCrypto.wipeKey() + the RAM-residue
        // clears just below it) — never let a slow/dead relay delay the
        // erase — mirroring Android's RunViewModel.onCleared kdoc ("placed
        // AFTER the crypto-erase-first block ... so it can only delay this
        // trailing, non-security-critical cleanup — never the erase"). It
        // still lands before LogBuffer/ConnectionLog are cleared and before
        // TorManager.shared.stop(), which is what actually matters for this
        // upload to have anything left to describe.
        //
        // Gated on `relayWasUp` — the reachability verdict captured at the TOP
        // of this function, before stopRelayCheck() cleared it. A session whose
        // last health probe did not succeed has a dead or half-open circuit, on
        // which this flush can only burn its whole budget while blocking the
        // main actor, so it is not attempted AT ALL (2026-09-14) rather
        // than merely bounded. Android sibling: the `debugLogRelayWasUp`
        // snapshot in RunViewModel.lockSession.
        let debugLogTransport = (debugMode && relayWasUp)
            ? controller.messageManager?.relayTransport()
            : nil
        // "Move to new device": drop the RAM-only one-time code before the rest of
        // the teardown (controller.lock() does the same on its side — this call is
        // the explicit, self-documenting one, and it is idempotent). This is the
        // `.background` path ContentView drives, so the QR and its code leave view
        // state exactly when the vault key material does. NOT driven from the
        // transient `.inactive` — see the scenePhase handler in ContentView.
        controller.moveScrubExportCode()
        // The NEW phone's half of the same secret. The
        // scanned handle carries the inbox READ capability AND the one-time code,
        // which together decrypt the whole exported vault — and its key is
        // HKDF-derived independently of this vault, so closing the vault below
        // does not reach it. It was the one move secret lock() left resident in a
        // process iOS keeps alive indefinitely after a background lock. Dropping
        // it lands the user in exactly the state "Continue without it" produces: a
        // provisioned, working vault, with the old phone still frozen and able to
        // re-issue — never a brick. Android has always done this
        // (RunViewModel.lockSession); emergencyWipe() already did it on this side.
        pendingMoveHandle = nil
        controller.lock()
        inactivityCrypto.wipeKey()
        // Scrub the social-graph id maps from RAM on lock too, not
        // only on the panic wipe. iOS backgrounds rather than kills, so
        // AppState stays alive; these @Published dictionaries keyed by full
        // contact/group ids would otherwise remain recoverable from a seized
        // locked-but-powered device (RAM acquisition), enumerating the user's
        // contact/group graph. Re-unlock repopulates them from the control poll
        // within one cycle, so clearing on lock is safe. Parity with the
        // LogBuffer.clear() / key-zeroing this method already does.
        //
        // App-icon badge (shared design decision, 2026-08-20): computed
        // BEFORE the unread maps below are cleared. The relay's aps.badge:1
        // is applied by iOS even while the app is foregrounded, so a message
        // that arrived AND was read during this session would otherwise
        // leave a stale "1" behind at lock; one that arrived and was NOT
        // read should keep showing it. Boolean presence only — never
        // `unreadCounts.values.reduce` — this is a badge, not a count.
        // pushEnabled-gated: an opted-out user never gets a badge, even with
        // unread messages sitting locally.
        let hasUnread = !unreadCounts.isEmpty || !groupUnreadCounts.isEmpty
        setAppIconBadge(pushEnabled && hasUnread)
        clearInMemoryIdentifierMaps()
        // lastPushDeviceToken is left alone here (emergencyWipe() drops it):
        // clearing it would silently defeat the coverage-gap fix on every
        // lock/unlock cycle (CR-1 makes that the common case), and the token
        // itself names no contact/message (Apple and the relay already hold it
        // once registered). The inbox-id set cleared below is cheap to
        // repopulate: the periodic re-sync re-covers it within one control-poll
        // cycle post-unlock (an idempotent re-PUT, not a functional loss).
        clearPushSessionBookkeeping()
        // Debug mode's "lock" flush, continued from the snapshot taken at the
        // top of this function (see [debugLogTransport] there) — fired now,
        // AFTER the crypto-erase-first block above, but still BEFORE
        // LogBuffer/ConnectionLog are cleared and before TorManager.shared.stop()
        // just below, which is what this flush actually needs intact (it ships
        // whatever LogBuffer/ConnectionLog lines are still new since the last
        // successful tick — see DebugLogUploader.flush, cursor-based; a kept-alive
        // Tor is not stopped at all, see the keep-alive note there). Bounded
        // to [debugLogLockFlushTimeoutSec] via a DispatchSemaphore signalled by
        // the detached flush Task — NOT async/await, because `lock()` is
        // synchronous and every scenePhase/settings call site expects it to
        // return immediately — the same synchronous-bounded-wait idiom
        // TorManager.stop() below already uses for its own HALT
        // acknowledgement. The `.background` transition budget is ~5 s and
        // stop() may itself wait up to TorManager.haltAckTimeoutSec, so this is
        // a ceiling, not a target: teardown continues below regardless of
        // whether the flush finished, timed out, or was never attempted.
        // `debugLogTransport == nil` (debug mode off, the relay was not
        // answering, or the vault was already closed) skips with no attempt.
        // Wait ONLY when the app is leaving the foreground (Tor is stopped a few
        // lines down and the process may be suspended). An in-process re-auth
        // lock runs on the main actor from ContentView's watchdog timer while
        // the user may be mid-tap, and Tor + the captured transport stay alive
        // there, so the detached task finishes on its own — blocking the UI for
        // up to the timeout bought nothing (2026-09-14; Android's
        // lockSession makes the same split). In that detached case the SAME
        // task clears LogBuffer once the batch is out, so the clear below cannot
        // race the collect into an empty lock batch.
        //
        // `leavingForeground` is the ONE foreground test both this wait and the Tor
        // stop below use: false for an in-scene lock (lockInForegroundScene — the
        // re-auth/idle locks, `.inactive` included), else "not `.active`".
        let leavingForeground = !lockStaysInForegroundScene && UIApplication.shared.applicationState != .active
        let waitForLockFlush = leavingForeground
        var logBufferClearDeferred = false
        if let debugLogTransport {
            logBufferClearDeferred = flushDebugLogOnLock(debugLogTransport, waitForLockFlush: waitForLockFlush)
        }
        // Tear Tor DOWN when the app is genuinely LEAVING the
        // foreground. The working DIR is deliberately KEPT (2026-08-01 — see
        // TorManager.preservesStateAcrossLaunches): only the control cookie and
        // control socket are dropped, while the cached consensus/descriptors and
        // entry-guard state are what the next launch reuses. `stop()` here, never
        // `stop(discardingState: true)` — that variant is for wipes and terminal
        // Tor failures. Gate on
        // not-`.active` so a FOREGROUND idle auto-lock (Lever C) — which keeps the
        // app visible with Tor legitimately running and would just re-wire to the
        // same daemon on re-unlock — does NOT stop it (that would needlessly force
        // a relaunch and race a live daemon). The same holds for an overdue re-auth
        // ContentView fires while the scene is `.inactive` (Control Center, app
        // switcher — still on screen): it locks through lockInForegroundScene, so
        // `leavingForeground` is false and Tor is kept for the PIN-screen
        // re-unlock (2026-11-06; before, `.inactive` read as not-`.active`, Tor was
        // stopped and the user needed a relaunch). stop() latches relaunchRequired, so
        // ContentView's on-`.background` self-recycle brings Tor back on the next
        // launch (iOS cannot re-init tor_main in-process anyway) — WARM now, off
        // the preserved guards + consensus.
        //
        // BOUNDED KEEP-ALIVE (2026-10-23): when ContentView's `.background` branch
        // decided — BEFORE calling this — to keep Tor for the background-task
        // budget (`armTorKeepAliveOnBackground`), the daemon is NOT stopped here;
        // the keep-alive's deadline stops it (and recycles the process) unless the
        // user returns first. Everything else in this function — the vault close,
        // the key wipe, every RAM scrub — runs unchanged either way.
        if leavingForeground && !torKeepAlive.isKeeping {
            TorManager.shared.stop()
        }
        // Final, unconditional ledger fence: bump the TransportFailedSends epoch
        // (and clear) AFTER the transport is torn down, so a send loop that is
        // still mid-backoff — ConversationView / sendPrivateReply survive a lock on
        // purpose — can neither re-park its plaintext + contactId nor start
        // another attempt (they check isSendSessionCurrent). IosAppController.lock()
        // already ends the session on the Kotlin side; this second bump covers a
        // record that raced in between (idempotent apart from the bump).
        TransportFailedSends.companion.shared.endSession()
        // Drop buffered session metadata from RAM on lock so a seized
        // locked-but-powered device yields nothing from it (the buffer is
        // DEBUG-only, but clear it regardless). Deferred to the
        // lock-flush task above when one is in flight in the foreground (bounded
        // by that flush's own HTTP timeout), immediate otherwise.
        if !logBufferClearDeferred { LogBuffer.shared.clear() }
        // Connection-log panel (ConnectionLog.kt): same RAM-residue rule, but it
        // is live in RELEASE builds too, so the clear is unconditional. CLEAR
        // FIRST, then leave one fixed-phrase marker so the panel explains why it
        // went empty; the marker names nothing. Android sibling:
        // RunViewModel.lockSession().
        ConnectionLog.shared.clear()
        ConnectionLog.shared.append(
            kind: ConnectionLog.Kind.system,
            text: "session locked",
            code: ConnectionLog.Code.sessionLocked
        )
        // Trade-off: sweep
        // DELIVERED notification-center records on every lock, not only a
        // panic wipe — see clearDeliveredNotifications(). Cost: a user with
        // several unread "Notification" banners who reads one conversation
        // and backgrounds the app loses delivery awareness for the rest —
        // those records are gone from Notification Center on next unlock.
        // Accepted because a seized LOCKED phone exposing a message-arrival
        // timeline is exactly the exposure this sweep exists to close, and the
        // notification body is contentless ("Notification") — what's lost
        // is awareness, not content. To reverse this tradeoff, delete the
        // `clearDeliveredNotifications` call below (clearWipeResidue()'s
        // call, further down, is the wipe-path equivalent and must stay
        // unconditional regardless of this decision).
        // includePending: false — do NOT cancel SCHEDULED/not-yet-delivered
        // local requests here. Those aren't a delivered-content forensic
        // artifact (nothing has reached Notification Center), so canceling
        // them on every ordinary backgrounding is over-scoped; only
        // clearWipeResidue() (every wipe path) cancels pending requests too.
        clearDeliveredNotifications(includePending: false)
    }

    /// lock()'s Debug-mode "lock" flush — the one INTENTIONAL main-thread wait in
    /// lock() (see the long comment at its call site for why it is a bounded
    /// DispatchSemaphore wait and not async/await). Fires the detached flush over
    /// [debugLogTransport] snapshotted before `controller.lock()`; waits up to
    /// [debugLogLockFlushTimeoutSec] only when [waitForLockFlush] (the app is
    /// leaving the foreground). Returns true when LogBuffer's clear is deferred to
    /// the detached task (foreground lock: the task clears it once the batch is
    /// out), false when lock() must clear it itself.
    private func flushDebugLogOnLock(_ debugLogTransport: RelayHttp, waitForLockFlush: Bool) -> Bool {
        let sem = DispatchSemaphore(value: 0)
        let app = debugLogAppVersion
        Task.detached(priority: .utility) {
            _ = try? await DebugLogUploader.shared.flush(
                transport: debugLogTransport, platform: "ios", app: app, reason: "lock"
            )
            if !waitForLockFlush { LogBuffer.shared.clear() }
            sem.signal()
        }
        if waitForLockFlush {
            if sem.wait(timeout: .now() + Self.debugLogLockFlushTimeoutSec) == .timedOut {
                // The flush is still mid-POST and the process is about to be
                // suspended; the detached task may never run again while
                // this process lives. Release the uploader's in-flight latch
                // NOW, or every flush of the next unlock (connect, periodic,
                // the next lock) would see "already flushing" and upload
                // nothing — the 2026-09-21 prod bug: Settings row ON, flag
                // persisted, connect telemetry received, zero batches after
                // the first background/return. The latch is also time-based
                // on the Kotlin side (DebugLogUploader.STALE_FLUSH_MS) as a
                // second guard; this is the prompt release.
                DebugLogUploader.shared.abandonFlush()
                LogBuffer.shared.append(level: "W", tag: "AppState", message: "lock flush did not finish in time — latch released")
            }
        }
        return !waitForLockFlush
    }

    /// RAM-residue scrub shared by lock() and emergencyWipe() — one list, so the two
    /// teardown paths cannot drift again (they did once: the two ratchet-health maps
    /// were missing from one of them). iOS backgrounds rather than kills, and the
    /// deniable wipe keeps the process alive on purpose, so these @Published
    /// dictionaries keyed by full contact/group ids would otherwise stay recoverable
    /// from live process RAM on a seized, powered device, naming the user's contacts.
    /// Everything here is re-derived after the next unlock (control poll, vault
    /// refreshers), so clearing is always the safe direction.
    /// Android sibling: RunViewModel.clearInMemoryIdentifierMaps().
    private func clearInMemoryIdentifierMaps() {
        unreadCounts = [:]
        groupUnreadCounts = [:]
        relayLostContacts = []
        // An undismissed referral relay-info event carries a CONTACT ALIAS (the
        // introducer/introducee the modal names). It is re-derivable from the
        // relay on the next unlock.
        referralRelayEvents = []
        // The shown version string is relay-chosen state (UpdateNudge.kt in
        // commonMain). The vault's own copy is erased/re-arms with the vault; this
        // is only the in-RAM mirror.
        showUpdateNudge = nil
        // "Later" group-invite ids: a new session presents each pending invite once again.
        deferredGroupInviteIds = []
        deferredReferralOfferIds = []
        // contactId-keyed ratchet-health SIGNALS, re-derived from the vault by
        // refreshForwardSecrecyStalled / refreshRatchetRefused on the next
        // conversation open, send and poll tick, so clearing them can neither
        // suppress a notice nor lose state.
        forwardSecrecyStalled = [:]
        ratchetRefused = [:]
        pushPromptOfferedThisSession = true
        reviewSheetRequestedThisSession = false
    }

    /// Push-registration bookkeeping shared by lock() and emergencyWipe(): raw inbox
    /// ids, same RAM-residue class as clearInMemoryIdentifierMaps(). The cached
    /// device token is NOT touched here; each caller decides (lock keeps it, the
    /// wipe drops it).
    /// Android sibling: RunViewModel.clearPushSessionBookkeeping().
    private func clearPushSessionBookkeeping() {
        // Bump BEFORE the clear, not after — see [pushTeardownEpoch]. A
        // refreshPushRegistrationIfNeeded() pass mid-flight when the teardown runs
        // must observe the new epoch when it lands, so its formUnion is discarded
        // instead of re-planting inbox ids into this torn-down session's RAM.
        pushTeardownEpoch += 1
        pushRefreshInFlightEpoch = nil
        pushRegisteredInboxIds = []
    }

    // -----------------------------------------------------------------------
    // First-run setup
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Threat-level slider + Lever B recovery code
    // -----------------------------------------------------------------------

    var hasRecoveryCode: Bool { controller.hasRecoveryCode() }
    /// Heavy controller work (Argon2id / SQLCipher re-key / Secure-Enclave prompt)
    /// off the main thread, its result delivered on the main actor. Callers capture
    /// `let controller = self.controller` so the work closure never touches the
    /// main-actor `self` (the sendBugReport idiom).
    private func offMain<T>(_ work: @escaping @Sendable () -> T, then done: @escaping @MainActor (T) -> Void) {
        DispatchQueue.global(qos: .userInitiated).async {
            let result = work()
            hopToMain { done(result) }
        }
    }

    var currentProtectionLevel: String { controller.currentProtectionLevel() }
    /// Maximum shield (MaximumShield.kt): contacts that reported Maximum while THIS device is
    /// at MAXIMUM — empty otherwise. Blocking vault read. Android sibling: `RunViewModel.maximumShield`.
    func maximumShieldContactIds() -> Set<String> { controller.maximumShieldContactIds() }
    func isMaximumShieldClaimed(contactId: String) -> Bool { controller.isMaximumShieldClaimed(contactId: contactId) }
    // Returns false on a transient device-key outage (nothing written; Kotlin logs
    // and defers instead of throwing across the bridge). Callers must ABORT their
    // apply flow on false: proceeding would rotate the credential
    // / toggle Lever B to match the NEW tier while the persisted level and every
    // enforcement timer stayed at the OLD one, silently.
    func setProtectionLevel(_ level: String) -> Bool { controller.setProtectionLevel(level: level) }

    /// Level-aware provision (slider). Sets credential mode + level in one write;
    /// heavy — off-main; completion on main. `false` when nothing was provisioned:
    /// a passphrase level below the entropy floor (the UI gates it, this is the
    /// boundary backstop), a transient device-key outage, or the existing-vault guard
    /// refusing (see provisionFailedDueToDeviceKey / routeToUnlockIfVaultPresent).
    func setRealCredentialWithLevel(_ credential: String, passphraseMode: Bool, level: String,
                                    completion: @escaping @MainActor (Bool) -> Void) {
        let controller = self.controller
        // Intentionally does NOT flip isConfigured on completion: the onboarding flow
        // may still show the recovery code before the first unlock, and flipping
        // isConfigured would route ContentView to PinEntryView mid-flow. isUnlocked
        // (set by the closing unlock) drives the transition into the app; a relaunch
        // recomputes isConfigured anyway.
        offMain({
            controller.setRealCredentialWithLevel(credential: credential, passphraseMode: passphraseMode, level: level)
        }, then: completion)
    }

    /// True when the JUST-COMPLETED `setRealCredentialWithLevel` returned `false`
    /// because the device key (Keychain) was transiently unavailable — mirrors
    /// Android `VaultSelector.lastProvisionWasDeviceKeyUnavailable`, see
    /// `IosAppController.lastProvisionWasDeviceKeyUnavailable` for the two
    /// upstream sources this covers on iOS's ordering. Call from the `completion`
    /// closure above, on the same main-queue hop, right after a `false` result —
    /// a later provision attempt overwrites the underlying flag.
    func provisionFailedDueToDeviceKey() -> Bool { controller.lastProvisionWasDeviceKeyUnavailable() }

    /// Enable Lever B + mint a recovery code. `completion` gets the code on success,
    /// or nil (unsupported / wrong credential / failed). Heavy + prompts — off-main.
    func enableLeverBWithRecovery(_ credential: String, completion: @escaping @MainActor (String?) -> Void) {
        let controller = self.controller
        offMain({ () -> String? in
            let r = controller.enableLeverBWithRecovery(credential: credential)
            return r.hasPrefix("code:") ? String(r.dropFirst(5)) : nil
        }, then: completion)
    }

    /// Finalize Lever B (two-phase): commit the PREPARED auth-bound key and
    /// promote to `level` atomically, after the user acknowledges the recovery code.
    /// `completion` gets false if nothing was pending or the commit failed — the vault
    /// then stays a working base PIN vault (never over-claims, never bricks). Off-main.
    func finalizeLeverB(_ level: String, completion: @escaping @MainActor (Bool) -> Void) {
        let controller = self.controller
        offMain({ controller.finalizeLeverB(level: level) }, then: completion)
    }

    /// The two ReferralManager hooks every session-opening path installs
    /// (didOpenVault() and recoverWithCode()) — a fresh ReferralManager per unlock
    /// needs its own hooks. Assigned PROMPTLY, right after the vault opens: the
    /// onIntroFinalized setter flushes a latched rehydrate-time finalize (a peer's
    /// accept that landed while we were dead). Both hooks fire OUTSIDE
    /// ReferralManager's lock, OFF the main thread (see the shared contract's
    /// kdoc), so each hops to main before posting / touching the @Published queue.
    /// onIntroRelayed feeds the introducer-side info modal through the bounded,
    /// deduping appendReferralRelayEvent.
    private func installReferralSessionHooks() {
        controller.referralManager?.onIntroFinalized = {
            DispatchQueue.main.async {
                NotificationCenter.default.post(name: .contactsChanged, object: nil)
            }
        }
        controller.referralManager?.onIntroRelayed = { [weak self] event in
            hopToMain {
                self?.appendReferralRelayEvent(event)
            }
        }
    }

    /// Recover a Lever-B-bricked vault (recovery code + credential), then open it —
    /// mirrors unlock's success wiring. Heavy — off-main; outcome on main.
    func recoverWithCode(_ code: String, credential: String,
                         completion: @escaping @MainActor (UnlockOutcome) -> Void) {
        DispatchQueue.global(qos: .userInitiated).async { [self] in
            let outcome = UnlockOutcome(rawValue: Int(controller.recoverWithCode(recoveryCode: code, credential: credential))) ?? .error
            hopToMain {
                if outcome == .opened {
                    self.isUnlocked = true
                    // Parity with didOpenVault() — assigned PROMPTLY.
                    self.installReferralSessionHooks()
                    // First-open push-notification prompt — parity with didOpenVault().
                    // (armed here, raised on the first relay answer — see didOpenVault()).
                    self.pushPromptOfferedThisSession = false
                    // "Move to new device" frozen probe — parity with didOpenVault().
                    self.refreshMoveFrozen()
                    // In-app store-review nudge — parity with didOpenVault().
                    if let openVault = self.controller.vault {
                        ReviewPromptStore.recordUnlock(vault: openVault)
                    }
                    // See didOpenVault() — a reload failure defers, never aborts.
                    if self.inactivityCrypto.isWiped() { try? self.inactivityCrypto.reloadKey() }
                    InactivityWipe.touch(crypto: self.inactivityCrypto)
                    self.startTorOrDirect()
                    // Parity with didOpenVault(): recovery is
                    // another session-opening path, and without this call a
                    // session entered via the recovery code never obtains a
                    // device token — [refreshPushRegistrationIfNeeded] then
                    // no-ops on its `lastPushDeviceToken == nil` guard for the
                    // entire session. No-op unless the AUTHENTICATED consent
                    // says vendor push (its own guard); the vault is
                    // open here, which that proof's epoch check requires.
                    self.registerApnsIfPushConsentProven()
                    // Parity with didOpenVault(): recovery is another
                    // session-opening path, so the badge clears here too
                    // — the in-app unread dots are the source of truth
                    // again once the vault is open.
                    self.setAppIconBadge(false)
                    // Same background re-lock as didOpenVault() — see there.
                    self.relockIfUnlockedInBackground(site: "recovery")
                }
                completion(outcome)
            }
        }
    }

    // -----------------------------------------------------------------------
    // Change PIN
    // -----------------------------------------------------------------------

    /// Verifies `pin` against the vault. NOT side-effect-free: every
    /// change-PIN flow routes through here, so it RECORDS a change-PIN abuse attempt
    /// and triggers an emergency wipe at the daily cap — never call it in a probing
    /// loop. The Argon2id (v3) KDF is heavy, so it runs off the main thread; the
    /// result lands on main.
    func verifyCurrentPin(_ pin: String, completion: @escaping (Bool) -> Void) {
        DispatchQueue.global(qos: .userInitiated).async { [self] in
            // Daily change-PIN abuse cap: every change-PIN flow passes through
            // this current-PIN check, so recording here bounds BOTH probe
            // channels. The MAX-th attempt in a 24h window triggers an
            // emergency wipe. Recorded before the check so a wrong guess counts.
            let limitReached: Bool
            do {
                limitReached = try controller.changePinAttempts.recordAttemptAndCheckLimit()
            } catch {
                // Device key transiently unreadable (locked keybag / transient
                // Keychain error) — the abuse counter can't be read/written. DEFER:
                // never wipe on a transient; fail the current-PIN check so the user
                // simply retries once the key is readable again.
                hopToMain { completion(false) }
                return
            }
            if limitReached {
                hopToMain { self.emergencyWipe(); completion(false) }
                return
            }
            let ok = controller.verifyCredential(credential: pin)
            hopToMain { completion(ok) }
        }
    }

    /// Rotate the current vault's PIN (preserving its data). Heavy (PBKDF2 +
    /// re-wrap), so it runs off the main thread; the outcome lands on main.
    func changePin(current: String, new: String, completion: @escaping @MainActor (ChangePinOutcome) -> Void) {
        let controller = self.controller
        offMain({ () -> ChangePinOutcome in
            let code = controller.changeCredential(currentCredential: current, newCredential: new)
            return code == "success" ? .success : .wrongCurrent
        }, then: completion)
    }

    /// [changePin] that also switches PIN ↔ passphrase mode atomically
    /// (high-risk mode enable/disable — hardening plan Lever A). Heavy — off
    /// the main thread; outcome lands on main.
    func changeCredentialAndMode(current: String, new: String, passphraseMode: Bool,
                                 completion: @escaping @MainActor (ChangePinOutcome) -> Void) {
        let controller = self.controller
        offMain({ () -> ChangePinOutcome in
            let code = controller.changeCredentialAndMode(
                currentCredential: current, newCredential: new, passphraseMode: passphraseMode
            )
            return code == "success" ? .success : .wrongCurrent
        }, then: completion)
    }

    // -----------------------------------------------------------------------
    // Lever B — Secure-Enclave auth-bound DB-key unwrap (opt-in)
    // -----------------------------------------------------------------------

    var biometricUnlockAvailable: Bool { controller.supportsDbKeyAuthBinding() }
    var biometricUnlockEnabled: Bool { controller.isDbKeyAuthBound() }
    /// True when the vault is PRIVATE on a LEGACY weak (device-passcode-openable)
    /// auth-bound key the unlock-time reconcile couldn't upgrade — a UI signal to
    /// prompt re-harden or step-down. Never throws.
    var needsLeverBReharden: Bool { controller.needsLeverBReharden() }

    /// Enable/disable the SE auth-bound DB-key layer. The disable path prompts
    /// once (Secure-Enclave biometry/passcode) to unwrap the current auth-bound
    /// blob; enable does not prompt. Heavy + may prompt — off the main thread.
    func setBiometricUnlock(_ enabled: Bool, completion: @escaping @MainActor (Bool) -> Void) {
        let controller = self.controller
        offMain({ controller.setDbKeyAuthBinding(enabled: enabled) }, then: completion)
    }

    /// RUN-01, Secure → Maximum: re-key the vault AFTER the Lever B drop, with the
    /// credential the settings chain just set (VaultSelector.rotateDbKeyAfterTierUpgrade).
    /// Heavy (KDF + re-key) — off the main thread; the Bool is informational.
    func rotateDbKeyAfterTierUpgrade(_ credential: String, completion: @escaping @MainActor (Bool) -> Void) {
        let controller = self.controller
        offMain({ controller.rotateDbKeyAfterTierUpgrade(credential: credential) }, then: completion)
    }

    // -----------------------------------------------------------------------
    // Messaging — the send / delete / reset-relay-access API lives in
    // AppState+Conversations.swift; only this stored set stays here (extensions
    // cannot add stored properties).
    // -----------------------------------------------------------------------

    /// Bubble ids whose PARKED send a transport-back re-drive just landed
    /// (TransportFailedSends.onRedriven, hopped to main here). The conversation
    /// views consume the ids they own and flip the bubble ✗ → ✓ (and a send loop
    /// still mid-backoff reads it as delivered instead of re-sending a duplicate).
    /// Ids of a view that is already gone stay behind harmlessly: UUIDs, RAM-only,
    /// dies with the session like the ledger itself.
    @Published var redrivenMessageIds: Set<String> = []

    // -----------------------------------------------------------------------
    // Opt-in push (docs/RELAY_SPEC.md) — CONTENTLESS.
    //
    // Tier 0 (default, false): unchanged behavior — Rún only checks the relay
    // while it's open / in a live background session.
    // Tier 2 (opt-in): a contentless APNs push wakes the app to poll; the
    // relay never sends message content to Apple, only a wake signal, and
    // only for inboxes THIS device explicitly registered (its own read cap
    // authenticates the registration — docs/RELAY_SPEC.md (push)).
    //
    // The registration round-trip (PUT/DELETE /inbox/{id}/push) is best-
    // effort: a failed register/unregister never blocks the UI toggle, which
    // must reflect the user's CHOICE immediately, independent of whether the
    // relay round-trip succeeds this instant (it can also lag behind Tor
    // coming up). All orchestration (looping inboxes, building the request)
    // lives in commonMain (PushRegistration.kt / IosAppController) so it's
    // unit-tested there; this layer only supplies WHEN to call it.
    // -----------------------------------------------------------------------

    /// Tier-2 opt-in preference. Computed over the shared `NotificationLevel`
    /// model — `true` iff the persisted level is `.vendorPush` (read through
    /// Kotlin's fold, written via plain UserDefaults — see `NotifLevelPreference`
    /// above). Not vault key material, so it is
    /// NOT gated behind unlock and (unlike vault content) is fine to read
    /// before PIN entry. Defaults to false (Tier 0) — docs/RELAY_SPEC.md (push) "off
    /// by default". Not `@Published` (can't wrap a computed property); the
    /// setter below calls `objectWillChange.send()` itself so SwiftUI
    /// observers (e.g. the ContactListView toggle) still react.
    var pushEnabled: Bool {
        get {
            // `notif_level == vendor_push`, after the forward-fold migration from
            // the legacy `push_tier2_enabled` bool (seeding `notif_level` when the
            // legacy bool is what said so). ONE copy of that fold, in Kotlin
            // (IosAppController.foldLegacyPushPreference), shared with the
            // consent latch's plaintext read so the two can never disagree.
            controller.foldLegacyPushPreference()
        }
        set {
            objectWillChange.send()
            persistNotifLevel(newValue)
        }
    }

    /// Small helper so the `pushEnabled` setter body stays a one-liner; kept
    /// private and free of any other side effects (no auth/registration
    /// logic here — that all still lives in `setPushEnabled` below,
    /// unchanged).
    private func persistNotifLevel(_ enabled: Bool) {
        UserDefaults.standard.set(
            enabled ? NotifLevelPreference.vendorPush : NotifLevelPreference.off,
            forKey: NotifLevelPreference.storageKey
        )
        // The line above is the LOCAL wake/badge gate
        // and nothing more — a plaintext UserDefaults value anyone able to write
        // the container can choose. The device-key-authenticated CONSENT PROOF is
        // what `IosAppController.registerRefs` requires before it hands the relay
        // a wake address, so it is written here, at the one Swift choke point for
        // a genuine user choice. Deliberately SECOND: plaintext-without-proof
        // self-heals on the next `provenNotificationLevel()` (it is that read's
        // one-time migration source), while proof-without-plaintext would
        // register a device whose banners are all dropped.
        _ = controller.setPushConsent(on: enabled)
    }

    /// Session-scoped cache of the APNs device token + APNs env ("sandbox"/
    /// "production") most recently delivered to [registerPushToken]. Two
    /// jobs: (1) lets [refreshPushRegistrationIfNeeded] — the periodic
    /// control-poll re-sync — register a newly paired/referred contact's
    /// inbox without asking iOS for a fresh token every cycle, and (2) is the
    /// PAIR a new callback is diffed against to detect a
    /// sandbox↔production environment flip (a dev/TestFlight install
    /// upgraded in place to App Store) or an APNs-reissued token, either of
    /// which must invalidate [pushRegisteredInboxIds] so every inbox
    /// re-registers under the new identity. [registerApnsIfPushConsentProven]
    /// asks iOS for a token at every UNLOCK, not only from the Settings toggle
    /// (the pre-unlock launch-time request was dropped —
    /// the consent proof's epoch lives in the vault), so this can refresh more
    /// than once per session. In-memory only; never persisted
    /// (docs/vault-relay-internals.md).
    private var lastPushDeviceToken: (hex: String, env: String)?

    /// Session-scoped "already told the relay about this inbox" set — the
    /// coverage-gap fix's "seen" cache. Starts empty each unlocked session
    /// (cleared in `lock()`/`emergencyWipe()`, same RAM-residue posture as
    /// `relayLostContacts`/`unreadCounts` there); the periodic re-sync fills
    /// it in as it registers newly-discovered inbound-TEXT inboxes, so
    /// re-diffing every control-poll cycle costs nothing once caught up.
    private var pushRegisteredInboxIds: Set<String> = []

    /// Bumped by every push-identity teardown — [lock] and [emergencyWipe] —
    /// BEFORE either empties [pushRegisteredInboxIds]/[lastPushDeviceToken],
    /// so a [refreshPushRegistrationIfNeeded] pass that STRADDLES one can
    /// notice and throw its own result away instead of re-planting raw relay
    /// inbox ids into the RAM of a session that has since locked, or of the
    /// deliberately-alive post-wipe process whose whole point is that this
    /// set stays empty. Mirrors Android's `pushTeardownEpoch`
    /// (RunViewModel.kt) — bump-then-clear is the ordering that matters: a
    /// clear-then-bump would leave a window where the pass reads the epoch,
    /// the teardown empties the fields, the pass re-populates them, and the
    /// pass's own post-hoc check still sees the pre-bump value, i.e. the
    /// teardown must always win. AppState is `@MainActor`-isolated (unlike
    /// RunViewModel's non-suspend wipe path off the mutex-holding thread), so
    /// a plain `Int` bumped/read/compared on the main actor is enough — no
    /// atomic needed. In-memory only (docs/vault-relay-internals.md) —
    /// never persisted, same as the fields it guards.
    private var pushTeardownEpoch = 0

    /// Single-flight owner of [refreshPushRegistrationIfNeeded]: the
    /// [pushTeardownEpoch] of the pass in progress, nil when none. MainActor-only.
    private var pushRefreshInFlightEpoch: Int?

    /// "A pending-dereg sweep is already in flight" — the anti-hammer guard on
    /// [sweepPendingPushDeregistrationIfNeeded] (2026-08-11): each sweep's
    /// DELETEs run over fresh Tor streams and can outlast a control-poll
    /// cycle, so without this latch back-to-back cycles would stack identical
    /// DELETE passes against the relay. Set on the main actor before the
    /// detached pass starts, cleared (also on the main actor) when it
    /// finishes; a fully successful sweep additionally disarms the persisted
    /// [PushDeregPending] flag, so a sweep never re-runs after success —
    /// nothing re-arms the flag but a new Settings opt-out. In-memory only,
    /// same posture as the session fields above. Android's equivalent
    /// single-flight guard is `withPushRefreshTurn`'s try-lock.
    private var pushDeregSweepInFlight = false

    /// Bumped every time a Settings opt-out ARMS the persisted
    /// [PushDeregPending] flag (`unregisterCurrentInboxesBestEffort(
    /// retryingForOptOut: true)`); captured by each retry ladder and each
    /// sweep pass at start and re-checked before the ONE mutation that
    /// matters — DISARMING the flag. Two opt-out ladders CAN overlap: opt-out
    /// (ladder A starts, arms) → re-enable → opt-out again (ladder B,
    /// re-arms), all inside A's ~65 s backoff window — nothing cancels A (no
    /// Task is held). A fully-successful pass by A over its OWN older,
    /// narrower ref snapshot would then clear the flag B armed, orphaning
    /// B's wider set — which can include an inbox minted during the brief
    /// re-enable — with the sweep permanently disarmed: a push row left on
    /// the relay for an opted-out device, the exact leak the flag exists to
    /// catch.
    ///
    /// The guard sits on the DISARM, deliberately NOT on the DELETEs: a
    /// stale ladder's DELETEs are harmless and idempotent (rows a newer
    /// opt-out wants gone anyway), so cancelling them buys nothing — only
    /// clearing a flag a newer opt-out armed is dangerous, so only the
    /// disarm is gated; a stale ladder just stops.
    ///
    /// Same stale-async-completion pattern — and the same actor-isolation
    /// discipline — as [pushTeardownEpoch]: a plain `Int` bumped/read/
    /// compared on the main actor (the detached ladders hop back via
    /// `MainActor.run` before their disarm), no atomic needed. In-memory
    /// ONLY, never persisted — the bare boolean stays the entire persisted
    /// surface; a process restart resetting this to zero is safe, the
    /// armed flag survives and the sweep simply re-runs. Mirrors Android
    /// `pushDeregGeneration` (RunViewModel.kt).
    private var pushDeregGeneration = 0

    /// Opt-out ladders in flight (2026-10-25). The sweep stands down while any
    /// is — both used to send the same DELETEs over the same dead circuits at
    /// once. Main actor only. Android sibling: `pushDeregLaddersActive`.
    private var pushDeregLaddersActive = 0

    /// Launch/unlock-time counterpart to the Settings-toggle
    /// entry point below. Before this, the ONLY call site for
    /// `registerForRemoteNotifications()` in the whole iOS tree was inside
    /// [setPushEnabled]'s toggle-ON branch, so [lastPushDeviceToken] stayed
    /// nil for the rest of any session that hadn't JUST flipped the toggle —
    /// a contact paired in a LATER session never got push (nothing ever
    /// re-drove [refreshPushRegistrationIfNeeded] past its own
    /// `lastPushDeviceToken == nil` guard), and an APNs-reissued token
    /// (device restore, reinstall) was never noticed either. Apple's own
    /// contract is to re-register at every launch. `pushEnabled` is
    /// UserDefaults-backed, not vault key material (see its own doc above),
    /// so this is safe to call before unlock. Idempotent per Apple's docs —
    /// calling it again at launch and at every later unlock in the same
    /// process costs nothing beyond the callbacks it produces.
    ///
    /// Deliberately NOT gated on notification authorization status: silent
    /// (content-available) push needs a device token but not alert/sound/badge
    /// permission, and a proven VENDOR_PUSH consent already implies the user
    /// granted that permission once, in [setPushEnabled]'s toggle-ON branch.
    ///
    /// Two changes, both essential:
    ///  - it is gated on the DEVICE-KEY-AUTHENTICATED consent
    ///    (`controller.pushConsentProven()`), not the plaintext `pushEnabled`
    ///    NSUserDefaults value a planted file could set; and
    ///  - it is no longer called from `RunApp`'s `.onAppear` (before unlock).
    ///    The proof's freshness epoch lives in the vault, so it can only be
    ///    evaluated with the vault OPEN — which is also the only state in which
    ///    a token could have been used, since registering an inbox needs the
    ///    vault to enumerate refs. An opted-OUT user still triggers nothing at
    ///    all, and a session that never unlocks (Lever C, a launch the user
    ///    abandons) simply does not register — acceptable, because
    ///    `registerRefs` could not have run in that session either.
    func registerApnsIfPushConsentProven() {
        guard controller.pushConsentProven() else { return }
        LogBuffer.shared.append(level: "D", tag: "Push", message: "registerApnsIfPushConsentProven: requesting device token")
        UIApplication.shared.registerForRemoteNotifications()
    }

    /// Settings-toggle entry point.
    ///
    /// Enable: request notification authorization, then ask iOS for a device
    /// token — delivered asynchronously to AppDelegate, which calls
    /// [registerPushToken] below once it arrives.
    ///
    /// Disable: DELETE for every inbound inbox this device knows about right
    /// now, fired off without blocking the toggle — since 2026-08-11 with
    /// in-session retry/backoff and a persisted pending flag a later
    /// session's sweep finishes (see
    /// [unregisterCurrentInboxesBestEffort]'s retryingForOptOut leg).
    func setPushEnabled(_ enabled: Bool) {
        pushEnabled = enabled
        UserDefaults.standard.set(enabled, forKey: PushPreference.storageKey)
        LogBuffer.shared.append(level: "I", tag: "Push", message: "push tier2 set to \(enabled)")
        if enabled {
            UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge]) { granted, error in
                if let error {
                    LogBuffer.shared.append(level: "W", tag: "Push", message: "authorization error: \(String(describing: type(of: error)))")
                }
                // DIAG (2026-07-24): pin the exact stall point of the on-device
                // registration failure — did the grant callback fire, and with what.
                LogBuffer.shared.append(level: "I", tag: "Push", message: "authorization callback granted=\(granted)")
                guard granted else {
                    LogBuffer.shared.append(level: "W", tag: "Push", message: "notification authorization denied")
                    return
                }
                hopToMain {
                    LogBuffer.shared.append(level: "I", tag: "Push", message: "calling registerForRemoteNotifications")
                    UIApplication.shared.registerForRemoteNotifications()
                }
            }
        } else {
            unregisterCurrentInboxesBestEffort(retryingForOptOut: true)
            UIApplication.shared.unregisterForRemoteNotifications()
            // An opted-out device must show nothing — the relay side of the
            // DELETE above (best-effort) is what stops future badges from
            // ever arriving, but this clears whatever's showing right now.
            setAppIconBadge(false)
            // Opting out means nothing is registered anymore (the DELETE
            // above just told the relay so) — forget the "seen" cache and
            // cached token too, so a later re-opt-in starts clean rather
            // than skipping inboxes the diff thinks it already covered.
            lastPushDeviceToken = nil
            pushRegisteredInboxIds = []
        }
    }

    /// AppDelegate → here: APNs handed us a device token
    /// (`didRegisterForRemoteNotificationsWithDeviceToken`). Registers it for
    /// every inbound inbox over the app's Tor HTTP path. No-ops if the user
    /// opted back out in the (brief, async) window between the authorization
    /// prompt and the token arriving. If Tor isn't up yet the (token, env)
    /// pair is still CACHED below rather than dropped —
    /// [refreshPushRegistrationIfNeeded]'s periodic control-poll resync picks
    /// it up once Tor connects, and every launch/unlock now re-requests
    /// a token anyway, so a cold-start toggle no longer loses coverage for
    /// the rest of the session.
    func registerPushToken(_ tokenHex: String) {
        guard pushEnabled else {
            LogBuffer.shared.append(level: "D", tag: "Push", message: "device token arrived after opt-out — ignoring")
            return
        }
        #if DEBUG
        let env = "sandbox"
        #else
        let env = "production"
        #endif
        // Cache the (token, env) pair BEFORE the Tor-
        // readiness guard below, not after. It used to sit after that guard,
        // so flipping the toggle during a cold start (Tor still
        // bootstrapping) threw the token away for the rest of the session —
        // [refreshPushRegistrationIfNeeded] reads [lastPushDeviceToken] and
        // silently no-ops forever when it's nil, and nothing else ever
        // re-requested one. Caching here first lets that periodic resync
        // recover once Tor comes up.
        //
        // This is a DELIBERATE divergence from Android's adopt-only-after-
        // transport rule (RunViewModel.kt refreshVendorPushRegistrationLocked:
        // `vendorPushToken = token` only after a live transport exists).
        // Android can re-fetch its FCM token at will on the next pass, so
        // adopting late just costs one cycle; iOS gets exactly ONE token
        // delivery per `registerForRemoteNotifications()` call and has no way
        // to ask again on demand, so dropping it here would mean losing it
        // for the whole session. Do not "harmonise" these two — they diverge
        // on purpose.
        //
        // Compare the PAIR (hex, env), not just the hex.
        // `env` is baked from `#if DEBUG` above, so a dev/TestFlight install
        // upgraded in place to an App Store build silently flips
        // sandbox→production while reusing the same device-token bytes. Left
        // undetected, the relay keeps routing to the stale sandbox
        // registration forever — APNs answers that with 400 BadDeviceToken,
        // which the relay deliberately does not act on (docs/RELAY_SPEC.md (push)).
        // Clearing [pushRegisteredInboxIds] forces every inbox to
        // re-register under the new (token, env) identity on the next
        // resync. Mirrors RunViewModel.kt's
        // `if (token != vendorPushToken) vendorPushRegisteredIds.clear()`.
        if lastPushDeviceToken?.hex != tokenHex || lastPushDeviceToken?.env != env {
            pushRegisteredInboxIds = []
        }
        lastPushDeviceToken = (tokenHex, env)
        let port = relayTransportSocksPort
        guard port > 0 else {
            LogBuffer.shared.append(level: "W", tag: "Push", message: "device token arrived before Tor is up — cached for control-poll resync")
            return
        }
        let controller = self.controller
        // Fold every id this eager pass registers into the session's "seen" set
        // (2026-10-26): it never did, so the resync fired at the first relay
        // answer ~1 s later re-PUT the very same inboxes on every unlock ("3/3
        // registered" then "resync: 3 new") — three wasted onion round trips per
        // unlock, on the relay and on the rendezvous circuit the user is waiting
        // on. Same epoch guard as refreshPushRegistrationIfNeeded: a lock()/wipe
        // teardown racing this pass discards its bookkeeping.
        let epochAtEntry = pushTeardownEpoch
        Task.detached(priority: .utility) { [weak self] in
            let ok = controller.registerPushToken(
                deviceTokenHex: tokenHex, env: env, socksPort: Int32(port),
                onRegistered: { id in
                    let inboxId = String(describing: id)
                    Task { @MainActor in
                        guard let self, self.pushTeardownEpoch == epochAtEntry else { return }
                        self.pushRegisteredInboxIds.insert(inboxId)
                    }
                }
            )
            LogBuffer.shared.append(level: "I", tag: "Push", message: "registered \(ok) inbox(es) for push")
        }
    }

    /// Periodic re-sync counterpart to [registerPushToken] — closes the
    /// coverage gap where a contact paired/referred/re-paired AFTER the most
    /// recent device-token callback never got its inbox registered
    /// (on-device evidence 2026-07-27: a live text inbox, minted after the
    /// initial registration, never received push). Before the launch/unlock request existed
    /// iOS asked for a fresh device token ONLY when the Settings toggle was
    /// flipped ON — never on an ordinary relaunch or mid-session — so this
    /// was the ONLY path that ever revisited registration.
    /// [registerApnsIfPushConsentProven] now re-asks at every unlock,
    /// but that still doesn't cover a contact paired mid-session, between one
    /// launch/unlock and the next — this still runs on the SAME cadence as
    /// the background control-poll loop (see startControlPoll), which already sits downstream of every
    /// inbox-minting call site (pairing, referral accept, re-pair), mirroring
    /// Android's RunViewModel.refreshVendorPushRegistration, which runs the
    /// identical diff on the identical cadence. Diffs against the session-scoped
    /// `pushRegisteredInboxIds` so a steady-state session (no new contacts)
    /// costs zero relay round-trips once caught up.
    private func refreshPushRegistrationIfNeeded() {
        guard pushEnabled, let token = lastPushDeviceToken else {
            // The INVERSE branch, same cadence (2026-08-11): with push OFF, a
            // Settings opt-out whose relay DELETE never landed leaves its
            // persisted flag armed — finish the job here. (Also reached when
            // pushEnabled is true but no token is cached yet; the sweep's own
            // !pushEnabled guard makes that a no-op.)
            sweepPendingPushDeregistrationIfNeeded()
            return
        }
        let port = relayTransportSocksPort
        guard port > 0 else { return }
        let controller = self.controller
        // A COMMITTED read-cap rotation evicts the relay's push registration
        // for that inbox (any token — ours, or one an attacker registered while
        // they held the device). Drop those ids from the session set so the diff
        // below re-registers OUR token under the new cap; no new registration call
        // site. Mirrors Android's refreshVendorPushRegistration.
        let evicted = Set(controller.drainRotatedPushInboxIds().map { String(describing: $0) })
        if !evicted.isEmpty { pushRegisteredInboxIds.subtract(evicted) }
        let seen = Array(pushRegisteredInboxIds)
        // Snapshot BEFORE the detached Task starts, and compare again on the
        // way back in — see [pushTeardownEpoch]. Each PUT below runs over a
        // fresh Tor stream and can take seconds; a lock() or emergencyWipe()
        // teardown racing in the meantime must always win, so this pass's
        // result is discarded (never applied) if the epoch moved.
        let epochAtEntry = pushTeardownEpoch
        // Single-flight (2026-10-24): this now also fires on the first relay answer,
        // so it can overlap the control-poll call, and a 32-inbox pass outlasts a
        // poll cycle. A second pass would snapshot the same unmerged `seen` and
        // re-PUT every inbox. The flag holds the epoch of the pass that owns it, so
        // a pass that straddles a lock()/wipe (epoch bumped, flag nil'd there) can
        // never clear — or be mistaken for — its successor's flag.
        guard pushRefreshInFlightEpoch == nil else {
            LogBuffer.shared.append(level: "D", tag: "Push", message: "push resync already in flight — skipped")
            return
        }
        pushRefreshInFlightEpoch = epochAtEntry
        Task.detached(priority: .utility) { [weak self] in
            // Each id is merged the moment its PUT lands (Kotlin calls this from a
            // worker thread), so a pass cut short by Tor churn or backgrounding
            // keeps what it registered. The epoch check discards it after a teardown.
            let newlyRegistered = controller.registerNewPushInboxes(
                deviceTokenHex: token.hex, env: token.env, socksPort: Int32(port), alreadyRegisteredIds: seen,
                onRegistered: { id in
                    let inboxId = String(describing: id)
                    Task { @MainActor in
                        guard let self, self.pushTeardownEpoch == epochAtEntry else { return }
                        self.pushRegisteredInboxIds.insert(inboxId)
                    }
                }
            )
            if !newlyRegistered.isEmpty {
                LogBuffer.shared.append(level: "I", tag: "Push", message: "push resync: \(newlyRegistered.count) new inbox(es) registered")
            }
            await MainActor.run {
                guard let self else { return }
                // Cleared on EVERY exit, but only if still ours (see the flag's note).
                if self.pushRefreshInFlightEpoch == epochAtEntry { self.pushRefreshInFlightEpoch = nil }
                if !newlyRegistered.isEmpty, self.pushTeardownEpoch != epochAtEntry {
                    LogBuffer.shared.append(level: "D", tag: "Push", message: "push identity torn down mid-refresh — discarded \(newlyRegistered.count) result(s)")
                }
            }
        }
    }

    /// The INVERSE branch of the periodic push re-sync (2026-08-11): finishes
    /// a Settings opt-out whose relay-side `DELETE /inbox/{id}/push` never
    /// landed (Tor down, all in-session retries dead, or the app terminated
    /// mid-backoff). Without this there was NO reconciliation pass anywhere:
    /// the local wake gate read OFF while the relay kept the APNs
    /// registration — and kept dispatching contentless wakes through Apple —
    /// forever.
    ///
    /// Runs on the EXISTING control-poll cadence via
    /// [refreshPushRegistrationIfNeeded]'s guard-else (the scheduler is
    /// startControlPoll's loop — deliberately no new timer), and only while
    /// (a) the vault is open, (b) push is OFF, and (c) the persisted
    /// [PushDeregPending] flag is armed. Re-enumerates the OPEN vault's
    /// inbound-text inboxes (the flag is a bare boolean; read caps come
    /// exclusively from the vault at sweep time).
    ///
    /// Anti-hammer: [pushDeregSweepInFlight] keeps at most one sweep in
    /// flight, and a fully successful sweep disarms the flag — generation-
    /// gated ([pushDeregGeneration]), so a pass a newer opt-out superseded
    /// mid-flight leaves it armed — and once disarmed it cannot re-run —
    /// nothing re-arms it but a new opt-out. A partial failure keeps
    /// the flag and retries on a later cycle; single pass per cycle, the
    /// jittered 25–45 s cadence IS the backoff here. Mirrors Android
    /// `RunViewModel.sweepPendingPushDeregistration`.
    private func sweepPendingPushDeregistrationIfNeeded() {
        guard !pushEnabled,
              UserDefaults.standard.bool(forKey: PushDeregPending.storageKey),
              isUnlocked,
              !pushDeregSweepInFlight else { return }
        // An opt-out ladder is retrying these DELETEs right now: no overlap
        // (2026-10-25, Android parity). The flag stays armed; a cycle after the
        // ladder ends sweeps whatever it left.
        guard pushDeregLaddersActive == 0 else {
            LogBuffer.shared.append(level: "D", tag: "Push", message: "push dereg sweep: skipped (opt-out ladder active)")
            return
        }
        let refs = controller.currentInboundInboxRefs()
        guard !refs.isEmpty else {
            // Open vault, nothing left that could hold a push row. No
            // generation guard on this disarm: main-actor-synchronous with
            // the entry checks (no await since), so it is provably never
            // stale — Android's sibling sits past suspend points and does
            // carry the guard.
            UserDefaults.standard.removeObject(forKey: PushDeregPending.storageKey)
            LogBuffer.shared.append(level: "D", tag: "Push", message: "push dereg: 0/0 inboxes cleared")
            return
        }
        let port = relayTransportSocksPort
        guard port > 0 else { return }   // no transport this cycle — next one retries
        let controller = self.controller
        pushDeregSweepInFlight = true
        // Snapshot BEFORE the detached Task starts, and compare again on the
        // way back in — a newer opt-out arming mid-sweep must leave the flag
        // armed ([pushDeregGeneration]; the guard is on the disarm, never
        // the DELETEs).
        let generationAtEntry = pushDeregGeneration
        LogBuffer.shared.append(level: "D", tag: "Push", message: "push dereg sweep: pass started (\(refs.count) inboxes)")
        Task.detached(priority: .utility) { [weak self] in
            let failures = controller.unregisterPushInboxesReturningFailures(refs: refs, socksPort: Int32(port))
            LogBuffer.shared.append(level: "D", tag: "Push", message: "push dereg: \(refs.count - failures.count)/\(refs.count) inboxes cleared")
            await MainActor.run {
                guard let self else { return }
                self.pushDeregSweepInFlight = false
                guard failures.isEmpty else { return }
                guard self.pushDeregGeneration == generationAtEntry else {
                    LogBuffer.shared.append(level: "D", tag: "Push", message: "push dereg: superseded by a newer opt-out — flag left armed")
                    return
                }
                UserDefaults.standard.removeObject(forKey: PushDeregPending.storageKey)
            }
        }
    }

    /// Best-effort DELETE for every inbound inbox currently known, fired off
    /// WITHOUT blocking the caller — used by both the Settings opt-out toggle
    /// and (see emergencyWipe) the panic-wipe path, which must never wait on
    /// network I/O (crypto-erase-first).
    ///
    /// [retryingForOptOut] splits the two callers (2026-08-11, the
    /// opt-out-DELETE-never-landed defect — hardware evidence: one DELETE per
    /// inbox on a slow Tor circuit, result swallowed, relay kept dispatching
    /// contentless wakes for the opted-out device forever):
    ///  - `false` (the wipe, the default): the historical ONE-SHOT pass,
    ///    unchanged. A wipe destroys the vault, so a persisted "dereg still
    ///    owed" flag armed here could never be cleared afterwards (no vault →
    ///    no caps → the sweep can never run) — the wipe path must neither arm
    ///    it nor retry; a miss stops mattering once the inbox itself expires
    ///    (docs/RELAY_SPEC.md (push)).
    ///  - `true` (the Settings opt-out): arms the persisted [PushDeregPending]
    ///    flag BEFORE the first DELETE attempt (before the enumeration, even,
    ///    so a process death anywhere past that line leaves the sweep armed),
    ///    retries each still-failing inbox with backoff
    ///    (pushDeregMaxAttempts/pushDeregBackoffSeconds — identical schedule
    ///    to Android `RunViewModel.unregisterPushInBackground`), and clears
    ///    the flag only when EVERY ref's DELETE succeeded AND the pass is
    ///    still the newest opt-out ([pushDeregGeneration]). Whatever still
    ///    fails is finished by [sweepPendingPushDeregistrationIfNeeded] on a
    ///    later session's control-poll cadence.
    private func unregisterCurrentInboxesBestEffort(retryingForOptOut: Bool = false) {
        if retryingForOptOut {
            // Bump, then arm ([pushDeregGeneration]'s ordering — the newer
            // opt-out must always win; the ladder captures the value below,
            // still on the main actor).
            pushDeregGeneration += 1
            // BARE BOOLEAN: never inbox ids or read caps — the sweep
            // re-enumerates the open vault instead.
            UserDefaults.standard.set(true, forKey: PushDeregPending.storageKey)
        }
        let refs = controller.currentInboundInboxRefs()
        let port = relayTransportSocksPort
        if retryingForOptOut, refs.isEmpty, isUnlocked {
            // Enumerated an OPEN vault and found nothing to unregister — the
            // opt-out is trivially complete; disarm the flag armed above. No
            // generation guard here, unlike every other disarm: this line is
            // main-actor-synchronous with the bump above (no await between
            // them), so it is provably never stale — Android's sibling has no
            // actor and does carry the guard.
            UserDefaults.standard.removeObject(forKey: PushDeregPending.storageKey)
            LogBuffer.shared.append(level: "D", tag: "Push", message: "push dereg: 0/0 inboxes cleared")
            return
        }
        guard port > 0, !refs.isEmpty else {
            if retryingForOptOut {
                // No transport (or no open vault to read refs from): nothing
                // can be sent now. The armed flag hands the job to the sweep.
                LogBuffer.shared.append(level: "D", tag: "Push", message: "push dereg: no transport — deferred to sweep")
            }
            return
        }
        let controller = self.controller
        guard retryingForOptOut else {
            // Wipe path: one-shot, result deliberately unobserved.
            Task.detached(priority: .utility) {
                _ = controller.unregisterPushTokenForInboxes(refs: refs, socksPort: Int32(port))
            }
            return
        }
        // Snapshot BEFORE the detached Task starts, and compare again on the
        // way back in — see [pushDeregGeneration] (same shape as
        // [pushTeardownEpoch] in refreshPushRegistrationIfNeeded).
        let generationAtArm = pushDeregGeneration
        // Counted BEFORE the Task so a sweep evaluating now already sees the
        // ladder; released on the main actor when it ends (below).
        pushDeregLaddersActive += 1
        Task.detached(priority: .utility) { [weak self] in
            // Read on the main actor each time (AppState is @MainActor).
            let currentEpoch: () async -> Int = { await MainActor.run { self?.networkRestoreEpoch ?? 0 } }
            let currentPort: () async -> UInt16 = { await MainActor.run { self?.relayTransportSocksPort ?? 0 } }
            let reEnabled: () -> Bool = {
                // Raw UserDefaults read (thread-safe) instead of the
                // MainActor-isolated `pushEnabled` — no actor hop needed, and a
                // re-enable always writes vendor_push into notif_level at toggle
                // time (persistNotifLevel).
                UserDefaults.standard.string(forKey: NotifLevelPreference.storageKey) == NotifLevelPreference.vendorPush
            }
            // FAIL-FAST passes (2026-10-25): every DELETE on its own 25 s budget, in
            // parallel (IosAppController.unregisterPushInboxesReturningFailures).
            var restoreEpoch = await currentEpoch()
            // After-restore extension: the monotonic time the ladder last saw the
            // restore epoch move (PushRegistration.continueDeregLadder, shared).
            var seenEpoch = restoreEpoch
            var restoreSeenAtMs: KotlinLong? = nil
            let nowMs: () -> Int64 = { Int64(ProcessInfo.processInfo.systemUptime * 1000) }
            var failures = controller.unregisterPushInboxesReturningFailures(refs: refs, socksPort: Int32(port))
            var attempt = 1
            // Ladder-only phrases, word for word with Android's.
            LogBuffer.shared.append(level: "D", tag: "Push", message: "push dereg ladder: pass \(attempt) done, \(failures.count) of \(refs.count) failed")
            while !failures.isEmpty {
                let epochNow = await currentEpoch()
                if epochNow != seenEpoch {
                    seenEpoch = epochNow
                    restoreSeenAtMs = KotlinLong(value: nowMs())
                }
                if !PushRegistration.shared.continueDeregLadder(passesDone: Int32(attempt), normalPasses: Int32(pushDeregMaxAttempts), nowMs: nowMs(), restoreSeenAtMs: restoreSeenAtMs) {
                    break
                }
                // Past the normal passes = the after-restore extension (Android parity).
                let afterRestore = attempt >= pushDeregMaxAttempts
                let backoffSeconds = afterRestore ? UInt64(PushRegistration.shared.DEREG_RESTORE_BACKOFF_MS / 1000) : pushDeregBackoffSeconds[attempt - 1]
                // The backoff ends early on a network-restore kick (epoch captured
                // before the pass that just failed, so a restore during it counts).
                if await awaitDeregBackoffOrRestore(seconds: backoffSeconds, sinceEpoch: restoreEpoch, epoch: currentEpoch) {
                    LogBuffer.shared.append(level: "D", tag: "Push", message: "push dereg ladder: backoff ended early (network restored)")
                }
                // Toggled straight back ON during the backoff — stop deleting
                // rows a fresh enable is (re)registering. The flag stays
                // armed; that is inert while notifications are ON (the sweep
                // is gated on OFF) and the next opt-out re-arms it anyway.
                if reEnabled() {
                    LogBuffer.shared.append(level: "D", tag: "Push", message: "push dereg ladder: re-enabled during backoff - stopped")
                    break
                }
                // Re-acquire the transport EACH retry (Android parity, 16c01dcd): the
                // SOCKS port can be absent right after a network restore, and the
                // embedded Tor is recovering, not gone. Bounded wait, then the sweep.
                let waitStart = ProcessInfo.processInfo.systemUptime
                var freshPort = await currentPort()
                let transportAbsent = freshPort == 0
                if transportAbsent {
                    LogBuffer.shared.append(level: "D", tag: "Push", message: "push dereg ladder: no transport - waiting up to \(pushDeregTransportWaitSeconds) s")
                }
                while freshPort == 0 && ProcessInfo.processInfo.systemUptime - waitStart < Double(pushDeregTransportWaitSeconds) {
                    try? await Task.sleep(nanoseconds: 1_000_000_000)
                    freshPort = await currentPort()
                }
                let waitedS = Int(ProcessInfo.processInfo.systemUptime - waitStart)
                if freshPort == 0 {
                    LogBuffer.shared.append(level: "D", tag: "Push", message: "push dereg ladder: still no transport after \(waitedS) s - stopped")
                    break
                }
                if transportAbsent {
                    LogBuffer.shared.append(level: "D", tag: "Push", message: "push dereg ladder: transport back after \(waitedS) s")
                }
                if reEnabled() {
                    LogBuffer.shared.append(level: "D", tag: "Push", message: "push dereg ladder: re-enabled during backoff - stopped")
                    break
                }
                attempt += 1
                LogBuffer.shared.append(level: "D", tag: "Push", message: afterRestore ? "push dereg retry \(attempt) (after network restore)" : "push dereg retry \(attempt)/\(pushDeregMaxAttempts)")
                restoreEpoch = await currentEpoch()
                failures = controller.unregisterPushInboxesReturningFailures(refs: failures, socksPort: Int32(freshPort))
                LogBuffer.shared.append(level: "D", tag: "Push", message: "push dereg ladder: pass \(attempt) done, \(failures.count) of \(refs.count) failed")
            }
            await MainActor.run { self?.pushDeregLaddersActive -= 1 }
            // Counts only — never a capability, never a raw inbox id. The e2e
            // suite asserts on this exact line (identical wording on Android).
            LogBuffer.shared.append(level: "D", tag: "Push", message: "push dereg: \(refs.count - failures.count)/\(refs.count) inboxes cleared")
            // The guard is on the DISARM, not the DELETEs ([pushDeregGeneration]):
            // this pass's DELETEs were harmless and idempotent even if a newer
            // opt-out overlapped, but clearing a flag that newer opt-out armed
            // — over a wider inbox set this pass never enumerated — would
            // retire the sweep with a relay push row still standing.
            if failures.isEmpty {
                await MainActor.run {
                    guard let self else { return }
                    guard self.pushDeregGeneration == generationAtArm else {
                        LogBuffer.shared.append(level: "D", tag: "Push", message: "push dereg: superseded by a newer opt-out — flag left armed")
                        return
                    }
                    UserDefaults.standard.removeObject(forKey: PushDeregPending.storageKey)
                }
            }
        }
    }

    /// AppDelegate → here: a contentless background push woke the app
    /// (`didReceiveRemoteNotification`, background/content-available). The
    /// remote payload carries NOTHING (docs/RELAY_SPEC.md (push)) — it is only ever a
    /// signal to check.
    ///
    /// If the vault is not ALREADY unlocked in this live process, there is
    /// nothing safe to poll: CR-1 requires the PIN, and this callback has no
    /// way to prompt for one. In that case we still surface a generic local
    /// notification (never a preview of content) so the user knows to open
    /// Rún, and report `.noData` (we performed no fetch). If the vault IS
    /// unlocked and Tor is already connected — a live, recently-backgrounded
    /// session — poll every contact for real and only notify if something
    /// actually arrived.
    func handleRemotePushWake(completionHandler: @escaping (UIBackgroundFetchResult) -> Void) {
        LogBuffer.shared.append(level: "D", tag: "Push", message: "remote push wake received")
        // A deniably-wiped install
        // (wipedThisSession — the black wiped_cover screen that's supposed to
        // be indistinguishable from powered-off) or a device the user opted
        // OUT of push must NEVER surface a banner here, regardless of how the
        // wake reached the process (APNs registration can outlive both states
        // — see clearWipeResidue()'s unregisterForRemoteNotifications() call
        // (now run by EVERY wipe path, including the three
        // launch-time ones in runLaunchSecurityChecks — not only this
        // in-session panic path) and the UserDefaults residue fixes,
        // none of which is guaranteed to have already propagated to Apple's
        // servers). Note this guard alone can't help a TERMINATED process at
        // all — a contentless ALERT push is rendered by SpringBoard without
        // ever invoking this method — which is exactly why the unregister
        // call matters more than this guard does. Silently report .noData
        // with no local notification of any kind — do NOT fall through to
        // the generic "open Rún to view it" banner below.
        guard pushEnabled, !wipedThisSession else {
            LogBuffer.shared.append(level: "D", tag: "Push", message: "push wake suppressed (pushEnabled=\(pushEnabled), wipedThisSession=\(wipedThisSession))")
            // Consistent with "surface nothing" above, not a contradiction of
            // it: SpringBoard may already have auto-applied the relay's
            // aps.badge:1 from this very push before this callback ran (that
            // part is outside app control, same as the banner render this
            // comment already calls out) — but clearing it back to zero here
            // is itself surfacing nothing, so an opted-out or just-wiped-
            // this-session install doesn't keep sitting behind a lit badge.
            setAppIconBadge(false)
            completionHandler(.noData)
            return
        }
        guard isUnlocked, controller.messageManager != nil, let vault else {
            Self.postLocalNotification(body: L10n.apnsNotificationBody)
            completionHandler(.noData)
            return
        }
        // getAllContacts() mints N live sharedSecret
        // pre-images; only contactId is read here, so wipe the rest before the
        // array is dropped.
        let allContactRecords = vault.getAllContacts()
        let contactIds = allContactRecords.map { $0.contactId }
        for record in allContactRecords { record.sharedSecret.secureWipe() }
        let blocked = BlockStore.blocked()
        let msgManager = controller.messageManager
        let ctrl = controller
        Task { @MainActor [weak self] in
            guard let self else { completionHandler(.noData); return }
            var gotAny = false
            // Bounded: a background wake gets a short OS execution budget: don't
            // let one stalled Tor circuit block every remaining contact.
            let deadline = Date().addingTimeInterval(20)
            for id in contactIds {
                if Date() >= deadline { break }
                if blocked.contains(id) { continue }   // Never touch a blocked inbox
                // NON-DESTRUCTIVE peek — MUST NOT drain. This wake only needs to
                // know IF something is waiting (the notification is contentless), so
                // it peeks instead of draining. peekInbox's own contract: "unread
                // texts deliberately survive on the relay until their conversation is
                // opened (an app exit must not destroy them)". The old code drained
                // here via pollMessages just to test !isEmpty, then discarded the
                // messages (they are in-memory only) — so any message that arrived
                // while its conversation was closed (the normal push case) was burned
                // off the relay and lost before it could ever be displayed. Peek leaves
                // it for the ConversationView poll to drain + show. (Android's
                // NotificationPollWorker already peeks for exactly this reason.)
                //
                // ALL THREE inboxes are peeked (extended by the group-inbox
                // pair): the relay wake is contentless and names no inbox, and
                // since inbound CONTROL inboxes joined the push-registration
                // surface (allPushableInboxes) a referral offer/accept or a group
                // invite can be the ONLY thing that woke this device. Peeking text
                // alone would silently drop the banner for a control-only wake —
                // this must produce the exact same generic banner as a message
                // wake, never a distinct copy (no lock-screen leak of "this is an
                // introduction"). Group texts now land on their OWN inbox
                // (DIR_INBOUND_GRP), so a group-only wake (text and control both
                // empty) would otherwise produce NO banner at all — peeking it
                // here closes that. peekControlPending/peekGroupInboxPending are
                // both peek-only, never a drain (cc121f8) — see
                // IosAppController.peekControlPending /
                // IosAppController.peekGroupInboxPending. peekGroupInboxPending
                // returns nil instantly (no network call) for a contact with no
                // group inbox yet, so this costs nothing extra for the majority.
                let (textPending, ctlPending, grpPending) = await Task.detached(priority: .background) {
                    (msgManager?.peekInbox(contactId: id)?.intValue,
                     ctrl.peekControlPending(contactId: id)?.intValue,
                     ctrl.peekGroupInboxPending(contactId: id)?.intValue)
                }.value
                if let textPending, textPending > 0 { gotAny = true; break }
                if let ctlPending, ctlPending > 0 { gotAny = true; break }
                if let grpPending, grpPending > 0 { gotAny = true; break }
            }
            if gotAny {
                Self.postLocalNotification(body: L10n.apnsNotificationBody)
            }
            completionHandler(gotAny ? .newData : .noData)
        }
    }

    /// The ONE identifier every local
    /// notification this app posts is filed under. See [postLocalNotification].
    private static let localNotificationId = "run.local.newmessage"

    /// Generic, content-free local notification — never a preview of message
    /// text, sender, or count (docs/RELAY_SPEC.md (push): contentless end-to-end).
    ///
    /// A FIXED identifier, not a fresh `UUID()` per post. iOS persists every
    /// DELIVERED notification in `/private/var/mobile/Library/UserNotifications/
    /// <bundle-id>/` — outside the sandbox, so `NSFileProtectionComplete` does not
    /// cover it, AFU-readable, and a first-class UFED/GrayKey/AXIOM parser target.
    /// With a per-post UUID those records ACCUMULATED, one per push wake, building a
    /// message-arrival timeline on a device whose vault cannot even be opened — the
    /// wake that creates them happens while LOCKED, and the only non-wipe sweep
    /// (`lock()`) is on a path that by definition requires a prior unlock. (The
    /// documented 64-notification cap does not bound this: it applies to PENDING
    /// requests, and these are delivered immediately.)
    ///
    /// iOS does NOT auto-collapse DELIVERED records by identifier — `add()` with a
    /// repeated id replaces a pending request but leaves the already-delivered one
    /// in place — so removing the previous delivered record explicitly is what makes
    /// repeated wakes REPLACE rather than stack, and gives the same single-banner
    /// behaviour Android already has. Worst case the timeline is one record deep,
    /// and ContentView's `.background` sweep takes even that.
    private static func postLocalNotification(body: String) {
        let center = UNUserNotificationCenter.current()
        center.removeDeliveredNotifications(withIdentifiers: [localNotificationId])
        let content = UNMutableNotificationContent()
        content.title = "Rún"
        content.body = body
        // ALERTS (product decision 2026-08-05) — the sibling of Android's
        // IMPORTANCE_HIGH channel (NotificationHelper.ensureChannel); the two
        // platforms must feel the same. This reverses an earlier
        // silencing, and the cost it carries is real and accepted: the body stays
        // contentless, but a chime hands anyone holding a LOCKED, seized phone a
        // precise arrival timestamp per message, which correlates one-to-one
        // against relay-side observation. Timing only — never content, sender or
        // count — and the user can silence it per-app in iOS Settings, which is
        // the mitigation we now point at (PushSettingsView's "Sound & alerts").
        //
        // `.default` is the system notification sound, NOT a custom one: a
        // recognisable app-specific chime would attribute the arrival to Rún
        // for any bystander in earshot, which is strictly worse than the
        // generic tone every other app shares.
        //
        // interruptionLevel is left at `.active` (the default): banner + sound
        // while unlocked, and no `.timeSensitive` — that pierces Focus modes
        // and would take the choice away from the user again.
        //
        // LOCK SCREEN: nothing is suppressed here either, so iOS applies the
        // user's own "Show Previews" setting (Settings › Notifications › Rún) —
        // the platform default already behaves like Messages. The body is the
        // fixed generic string, so a preview shows "Notification", never a
        // sender or content; a user who wants even that hidden sets Previews to
        // Never, which is exactly the control the "Sound & alerts" row opens.
        content.sound = .default
        // Match the relay's constant `"badge":1` (shared design decision,
        // 2026-08-20) so the in-process background-wake path — this one —
        // leaves the app icon in the same state a terminated-app push would
        // via SpringBoard. Boolean presence only, never a count; `1` is an
        // Int literal, auto-bridged to the NSNumber? this property expects.
        content.badge = 1
        let request = UNNotificationRequest(identifier: localNotificationId, content: content, trigger: nil)
        center.add(request)
    }

    /// Sweep DELIVERED notification records when the app backgrounds while the
    /// vault is LOCKED — the one path that both CREATES these records (a push wake
    /// with no vault to poll posts a banner) and never reaches [lock]'s sweep, since
    /// every `lock()` call site is gated on having been unlocked.
    ///
    /// Same policy and same accepted cost as the notification sweep inside [lock]: the user
    /// loses awareness of banners they have not read yet when they leave the app,
    /// never content (the body is contentless "Notification"). `includePending:
    /// false` for the same reason [lock] uses it — a not-yet-delivered request is
    /// not a delivered-content artifact. Local-only, no network I/O.
    func sweepDeliveredNotificationsWhileLocked() {
        clearDeliveredNotifications(includePending: false)
    }

    /// iOS persists delivered notifications
    /// in `/private/var/mobile/Library/UserNotifications/<bundle-id>/` —
    /// OUTSIDE the app sandbox (so `NSFileProtectionComplete` in
    /// iosApp.entitlements doesn't cover it), AFU-readable, and a first-class
    /// UFED/GrayKey/AXIOM parser target: one record per push wake with title,
    /// body and timestamp, i.e. a message-arrival timeline surviving an app
    /// whose whole promise is that seizure yields nothing. Called from both
    /// [lock] (every backgrounding leaves nothing behind, not just a panic
    /// wipe) and [clearWipeResidue] (every wipe path). `includePending`
    /// additionally cancels SCHEDULED (not-yet-delivered) local requests —
    /// corrected 2026-07-30: those are not a delivered-content forensic
    /// artifact (nothing has reached Notification Center yet), so [lock]
    /// passes `false` and only [clearWipeResidue] passes `true`. Local-only,
    /// no network I/O — safe to call unconditionally and cheaply on every lock.
    private func clearDeliveredNotifications(includePending: Bool = true) {
        let center = UNUserNotificationCenter.current()
        center.removeAllDeliveredNotifications()
        if includePending {
            center.removeAllPendingNotificationRequests()
        }
    }

    /// App-icon badge — boolean presence only, NEVER a count (shared design
    /// decision, 2026-08-20). The relay always sends a constant `"badge":1`
    /// in its APNs alert payload; SpringBoard applies that with no app code
    /// running, which is the only way to badge a TERMINATED app. This helper
    /// is the client's side of "badge iff something is waiting since the
    /// last unlock" for every in-process path (unlock, recovery, opt-out,
    /// wipe, lock, push-wake bail). iOS 16+ `setBadgeCount` — NOT the
    /// deprecated `UIApplication.applicationIconBadgeNumber` (deployment
    /// target is 16.0). AppState is `@MainActor`-isolated (class annotation
    /// above), so every call site is already on the main actor; no manual
    /// dispatch needed. The completion is best-effort and intentionally
    /// ignored on success — a stale badge is a cosmetic miss, not a security
    /// issue — but a failure is still worth a log line for diagnosability.
    private func setAppIconBadge(_ waiting: Bool) {
        UNUserNotificationCenter.current().setBadgeCount(waiting ? 1 : 0) { error in
            if let error {
                LogBuffer.shared.append(level: "W", tag: "Push", message: "setBadgeCount failed: \(String(describing: type(of: error)))")
            }
        }
    }

    // --- Referral / vouching (referral.md) ---

    /// Introduce two existing contacts to each other over the relay.
    /// `startReferral` does blocking Tor sends — fan them out on a
    /// DETACHED task so the Introduce button never runs N blocking round-trips on the
    /// main actor (a UI hang on a slow circuit). Parity with Android's
    /// startReferralsInBackground; survives the Introduce sheet being dismissed.
    ///
    /// `onDone` reports whether EVERY recipient's `startReferral` returned
    /// non-nil. A nil result means no transport or an invalid pairing — never a
    /// delivery failure, which is a durable, redriven obligation core-side (see
    /// ReferralManager's offer-redrive kdoc) — so only "nothing was even
    /// attempted" is worth surfacing. Fires on the main actor; defaults to a
    /// no-op so this stays source-compatible with any other caller.
    func startReferrals(fromContactId: String, toContactIds: [String], onDone: @escaping @MainActor (Bool) -> Void = { _ in }) {
        let controller = self.controller
        Task.detached(priority: .userInitiated) {
            var allStarted = true
            for id in toContactIds {
                let introId = controller.referralManager?.startReferral(contactAId: fromContactId, contactBId: id)
                if introId == nil { allStarted = false }
            }
            await MainActor.run { onDone(allStarted) }
        }
    }

    /// Referral offers awaiting consent (polled by the contact list).
    func pendingReferralOffers() -> [ReferralOffer] {
        controller.referralManager?.pendingOffers() ?? []
    }

    /// Approve a referral: mints an inbox pair over the relay (off the main
    /// thread), generates the ephemeral key, and sends our accept.
    func acceptReferral(introId: String) async -> Bool {
        guard let rm = controller.referralManager else { return false }
        // acceptOffer mints over the relay; the Kotlin side runs the PoW on
        // Dispatchers.Default, so awaiting here doesn't block the main actor.
        let ok = ((try? await rm.acceptOffer(introId: introId))?.boolValue) ?? false
        NotificationCenter.default.post(name: .contactsChanged, object: nil)
        return ok
    }

    func declineReferral(introId: String) {
        controller.referralManager?.declineOffer(introId: introId)
    }

    /// Pop the head of [referralRelayEvents] once its info dialog has been
    /// acknowledged. Guarded against an already-empty queue so a stray double
    /// dismiss (e.g. a rapid second tap) can't crash on removeFirst().
    func dismissReferralRelayEvent() {
        guard !referralRelayEvents.isEmpty else { return }
        referralRelayEvents.removeFirst()
    }

    /// Mirrors `ReferralManager.MAX_PENDING_RELAY_EVENTS`
    /// (a `private const val` in commonMain's ReferralManager companion — not visible
    /// from this platform layer, hence the duplicated literal rather than an import).
    private static let maxPendingReferralRelayEvents = 8

    /// Appends `event` to [referralRelayEvents], deduping on `introId` (a
    /// re-delivered accept for an intro already queued replaces the stale entry
    /// in place instead of adding a second one) and bounding the list to
    /// [maxPendingReferralRelayEvents] by dropping the OLDEST entry on overflow.
    ///
    /// Was a bare `.append(event)` at both call sites, which defeated
    /// commonMain's own MAX_PENDING_RELAY_EVENTS=8 pre-hook cap: when an
    /// introduction's second leg is unreachable the success-only dedupe in
    /// ReferralManager never arms, so every re-delivered accept appended
    /// another entry (two aliases pinned in RAM) and queued another modal.
    /// Android sibling: RunViewModel.appendReferralRelayEvent.
    private func appendReferralRelayEvent(_ event: ReferralRelayEvent) {
        // An in-flight control drain can deliver a relay event after lock() /
        // emergencyWipe() cleared the list: it carries contact aliases + ids, so
        // it must not land in a locked session's RAM.
        guard isUnlocked else { return }
        referralRelayEvents.removeAll { $0.introId == event.introId }
        referralRelayEvents.append(event)
        if referralRelayEvents.count > Self.maxPendingReferralRelayEvents {
            referralRelayEvents.removeFirst(referralRelayEvents.count - Self.maxPendingReferralRelayEvents)
        }
    }

    /// Delivers our own (inboxId, writeCap) to a freshly paired contact whose
    /// full QR we scanned while they only saw our secret-only code (instant-QR
    /// pairing). Detached with jittered retries so it survives the AddContact
    /// sheet being dismissed. Receiver-side application is idempotent.
    func announceInbox(contactId: String, myInboxId: String, peerWriteCap: String,
                       myCtlInboxId: String? = nil, peerCtlWriteCap: String? = nil,
                       myGrpInboxId: String? = nil, peerGrpWriteCap: String? = nil) {
        let controller = self.controller
        Task.detached(priority: .userInitiated) {
            for attempt in 1...3 {
                // gib/gwc appended last — Kotlin default arguments do not cross the
                // ObjC bridge, so every parameter is explicit (§1.3/§1.6).
                let ok = controller.messageManager?.sendInboxAnnounce(
                    contactId: contactId, myInboxId: myInboxId, peerWriteCap: peerWriteCap,
                    myCtlInboxId: myCtlInboxId, peerCtlWriteCap: peerCtlWriteCap,
                    myGrpInboxId: myGrpInboxId, peerGrpWriteCap: peerGrpWriteCap
                ) ?? false
                if ok {
                    LogBuffer.shared.append(level: "D", tag: "AppState", message: "inbox announce delivered")
                    return
                }
                if attempt < 3 {
                    let delaySeconds = 2.0 + Double.random(in: 0...3.0)
                    try? await Task.sleep(nanoseconds: UInt64(delaySeconds * 1_000_000_000))
                }
            }
            // The peer stays in "awaiting inbox" — honest UI state; the user
            // can re-pair if this persists.
            LogBuffer.shared.append(level: "W", tag: "AppState", message: "inbox announce failed after 3 attempts")
        }
    }

    // -----------------------------------------------------------------------
    // Relay reachability
    // -----------------------------------------------------------------------

    // Relay-health thresholds (kept next to the state they gate).
    // 3 consecutive misses (~24-36s at the jittered 8-12s cadence) before declaring
    // the relay unreachable — long enough to ride out concurrent-load stream flaps,
    // short enough that a genuine outage still surfaces promptly.
    private static let relayUnreachableStreakLimit = 3

    // Minimum wall-time between counted misses, AT the bg
    // loop's 8 s floor. Every bg cycle (8–12 s) still counts one miss, but the sub-second
    // 1:1 loop and the 3–8 s group loop can't add extra bumps within the window — so the
    // streak advances at ~8 s per miss no matter how many loops probe (was 7000 → a
    // conversation-open grey-out at ~14 s, undershooting the threshold's intent). With
    // this floor: grey-out at 3 misses ≈ 24 s. (The NEWNYM rungs no longer ride this
    // counter at all — both are wall-clock anchored; see newnymAfterUnreachableMs.)
    private static let minStreakBumpIntervalMs: Double = 8000

    // App-level circuit self-heal cadence: request fresh Tor circuits (NEWNYM) after
    // this much CONTINUOUS unreachability, then again every newnymRepeatMs — a sustained
    // wedge that outlived several flap-recovery windows, NOT transient contention. Kept
    // conservative on purpose (see the call site). See TorManager.requestNewCircuit.
    //
    // WALL-CLOCK since 2026-09-15 (connect-time study §1c). It was `newnymEveryStreak = 8`
    // COUNTED MISSES, which is ~64 s only while misses cost the 8 s floor: a COLD cycle
    // costs 2 × 20 s (MessageManager.HEALTH_HTTP_TIMEOUT_SECONDS), so 8 misses was
    // 160–320 s and the rung provably never ran on the measured 155 s cold connect. 64_000
    // reproduces the warm timing exactly (8 × the 8 s floor) and now means the same thing
    // cold. The cold rung (maybeFireEarlyNewnym, ~35 s / ~80 s) sits AHEAD of this one for
    // sessions that have never had an answer; this one keeps covering a session that had
    // one and then went bad, which the cold rung deliberately does not touch.
    private static let newnymAfterUnreachableMs: Double = 64_000
    private static let newnymRepeatMs: Double = 64_000

    // QA #1: after this many continuous misses (~24 × ~8s ≈ 3 min — several NEWNYM
    // self-heal cycles deep) surface the manual-reconnect UI instead of an endless
    // "Connecting…". Well past newnymAfterUnreachableMs so the auto-heal gets a fair chance first.
    private static let stalledStreakThreshold = 24

    // Consecutive failed health checks. isRelayReachable only drops to false after
    // relayUnreachableStreakLimit of them (recovers to true on the first success), so
    // a single transient onion-stream rendezvous failure — common when several
    // devices hammer fresh Tor streams concurrently — no longer instantly greys out
    // Add-contact / drops the session. Each SwiftTorHttp request opens a fresh
    // stream, so one flaky stream ≠ relay down. Pure UX-gating hysteresis (nothing
    // security-critical reads isRelayReachable); mirrors the runestone's 3s debounce.
    private var relayUnreachableStreak = 0
    // Wall-clock of the last COUNTED miss. THREE loops call
    // checkRelayReachability (bg 8–12 s, 1:1 0.5–1.2 s, group 3–8 s), so counting the
    // streak per-probe let an open conversation cross the limit — and the NEWNYM cadence
    // — in seconds, not the ~24–36 s the threshold intends (premature grey-out + circuit
    // churn). We now count at most one miss per bg-cadence window of real time, so the
    // streak reflects elapsed time regardless of how many loops probe. 0 = fresh outage.
    private var lastStreakBumpAtMs: Double = 0

    /// Transport-back redrive edge (2026-10-16). `true` while the transport is
    /// down from this loop's point of view — no relay answer yet this session, or
    /// ANY missed probe since the last answer (counted or throttled: a miss is a
    /// miss for a send that failed meanwhile, whatever the hysteresis above makes
    /// of it for the UI). Consumed by the first answering probe, which is the one
    /// disconnected→connected TRANSITION (an edge, never the reachable level) on
    /// which `redriveTransportFailures` replays transport-failed sends — once per
    /// outage, then not again until the next miss re-arms it. Starts armed so the
    /// session's FIRST answer re-drives what the previous session left behind.
    /// Android keys the same edge on its manager being re-created after a Tor
    /// restart; iOS cannot restart Tor in-process (`relaunchRequired`), so the
    /// NEWNYM self-heal rungs resolve as this probe edge instead.
    private var transportDownForRedrive = true
    /// One redrive pass at a time. An edge that lands while a pass is still
    /// re-sending is dropped, not queued: that pass walks everything still
    /// failed, and the next outage's miss re-arms the latch anyway.
    private var transportRedriveInFlight = false

    /// Wall-clock (epoch ms) of the FIRST counted miss of the current unreachable
    /// run, 0 while the relay is answering. The sustained NEWNYM rung below is
    /// anchored on THIS, not on a miss count: a cold health cycle costs 2 × 20 s
    /// (MessageManager.HEALTH_HTTP_TIMEOUT_SECONDS), so "8 misses" meant ~64 s on a
    /// warm session but 160–320 s on a cold one — i.e. the rung provably never ran
    /// inside the connect waits it exists for (connect-time study §1c). Android
    /// sibling: RunViewModel.startRelayStallWatch, whose rung is likewise anchored
    /// on wall time (RELAY_SELF_HEAL_RESTART_MS), never on counted misses.
    private var unreachableRunStartedAtMs: Double = 0

    /// Wall-clock (epoch ms) of the last NEWNYM fired by the SUSTAINED rung, so it
    /// repeats on wall time instead of on every Nth miss. 0 = none this run.
    private var lastSustainedNewnymAtMs: Double = 0

    /// How many NEWNYMs the SUSTAINED (stall-watch) rung has fired in the CURRENT
    /// unreachable run — the number its panel line renders, and the only thing
    /// that tells that line apart from the cold rung's `(NEWNYM n/2)`. Reset with
    /// the run itself (and by a manual Reconnect, which re-anchors it), exactly
    /// like `unreachableRunStartedAtMs`. Android sibling: the `newnymTries`
    /// counter local to RunViewModel.startRelayStallWatch's escalation.
    private var sustainedNewnymsFired = 0

    // The early-NEWNYM budget (cap count + the cold rung's own count) lives in the
    // Kotlin `EarlyNewnymLedger` the controller holds (`controller.earlyNewnym*`):
    // session-scoped, never re-armed by a transport re-wire, reset only by
    // beginWarmTorSession. Android sibling: RunViewModel's early-NEWNYM budget.

    /// Set-once SESSION latch: the relay has answered at least once this session
    /// (`isRelayReachable` or `relayHandshakeComplete` ever true). Input to the
    /// shared C5 warm-up rotation gate (`MessageManager.shouldFireWarmupNewnym`
    /// via `controller.warmupNewnymAllowed`), which must refuse once the session
    /// has reached the relay. Kept here, not on the MessageManager, because a
    /// transport re-wire builds a fresh manager whose own round-trip latch starts
    /// false. Same per-session scope as the early-NEWNYM ledger: never reset by a
    /// lock, only by a NEW session in a surviving process (the bounded Tor
    /// keep-alive's warm return, `beginWarmTorSession`). Also the "known wedged"
    /// input of that keep-alive's gate. Android sibling:
    /// RunViewModel.relayAnsweredThisSession.
    private var relayAnsweredThisSession = false

    // In-app update nudge: evaluated AT MOST ONCE per session (a fresh AppState
    // per launch, and re-armed by beginWarmTorSession when the bounded Tor
    // keep-alive lets a second session live in the same process), even
    // though this loop reruns every 8-12 s — MessageManager.newerRelayVersion()
    // is a monotonic per-instance latch, but the vault-throttle read/write in
    // UpdateNudge.kt is unconditionally idempotent-safe to call repeatedly, so
    // this flag exists purely to avoid re-hitting SQLCipher every cycle once a
    // verdict (shown or not-shown-today) has already been reached this session.
    private var updateNudgeEvaluated = false

    // In-app store-review nudge: same "at most once per AppState instance/
    // session" shape as updateNudgeEvaluated above, and evaluated at the SAME
    // tick (right after it) — see the ordering comment at that call site.
    private var reviewPromptEvaluated = false
    /// Set alongside `requestReviewFlow`; the first-open push prompt yields to
    /// the native review sheet for the rest of the session (see the gate in
    /// PushPromptOnboarding.kt). Reset with the session in lock()/wipe.
    private var reviewSheetRequestedThisSession = false
    /// First-open push prompt: "already offered this session" leg of the same
    /// gate — armed (false) by both unlock paths, flipped by the first relay
    /// answer. Android sibling: RunViewModel.pushPromptOfferedThisSession.
    private var pushPromptOfferedThisSession = true

    /// Monotonic anchor for "when this session's relay connect began" —
    /// `ProcessInfo.systemUptime` (boot-relative, immune to wall-clock steps),
    /// the same clock InactivityWipe / InactivityAutoLock use. Set ONCE per
    /// session by `startTorOrDirect()`: a NEWNYM self-heal, a manual Reconnect
    /// or a FOREGROUND re-unlock (Lever C / re-auth) mid-session is still ONE
    /// wait from the user's side and never re-anchors. The only reset is a NEW
    /// session in a surviving process — a warm return inside the bounded Tor
    /// keep-alive window (`beginWarmTorSession`), which is what a fresh process
    /// used to be. Android sibling: RunViewModel.connectStartElapsedMs.
    private var connectStartUptime: TimeInterval?

    /// One anonymous connect-time report per SESSION (ConnectTelemetry.kt) —
    /// sent ONLY while Debug mode consent is on; the latch is set regardless.
    /// Deliberately NOT reset by lock() — a foreground re-unlock must not
    /// produce a second report; re-armed only by `beginWarmTorSession` (the
    /// bounded keep-alive's warm return = a new session). Android sibling:
    /// RunViewModel.connectTelemetrySent.
    private var connectTelemetrySent = false

    /// The SOCKS port relay transports are created with: the user's proxy port in
    /// external proxy mode, else the embedded Tor's published port. In external
    /// mode SwiftTorHttp dials the configured endpoint regardless of this value
    /// (ExternalProxyMode.socksTarget); invalid / unreadable external mode reads 0
    /// (= "no transport"), never the embedded Tor's port.
    private var relayTransportSocksPort: UInt16 {
        if let ep = ExternalProxyMode.shared.endpoint { return ep.port }
        if ExternalProxyMode.shared.isExternalThisProcess || extProxyStatus.isExternal { return 0 }
        return TorManager.shared.socksPort
    }

    /// EXTERNAL SOCKS PROXY MODE — the unlock-time connect when the user routes
    /// relay traffic through their own SOCKS5 proxy. Returns true when this
    /// process is NOT on the embedded-Tor path; the caller then does nothing
    /// further (no Tor start, no hooks, no watchdog). Fail closed throughout: an
    /// invalid setting, a non-onion relay or an unreadable store leaves messaging
    /// unavailable — never the embedded Tor, never direct.
    ///
    /// Never logs the host or port: ConnectionLog phrases carry only the class
    /// word ("loopback"/"lan") and the outcome. NOTE: the phrases are shared
    /// with Android's sibling and must stay word-for-word identical.
    private func connectViaExternalProxyIfConfigured() -> Bool {
        switch ExternalProxyMode.shared.resolve() {
        case .embedded?:
            // A transient "unreadable" from an earlier attempt resolved to
            // embedded: drop the status so the embedded path is unencumbered.
            if extProxyStatus != .off { transport.extProxyStatus = .off }
            return false
        case nil:
            transport.extProxyStatus = .unreadable
            transport.torState = .disconnected
            ConnectionLog.shared.append(
                kind: ConnectionLog.Kind.system,
                text: "ext proxy: setting unreadable - messaging unavailable"
            )
            // Bounded re-resolution (≤ 3 × 2 s): the Keychain was readable a
            // moment ago for the unlock itself, so this is a transient glitch.
            // Re-enters startTorOrDirect, whose anchor is set-once.
            if extProxyUnreadableRetries < 3 {
                extProxyUnreadableRetries += 1
                Task { @MainActor [weak self] in
                    try? await Task.sleep(nanoseconds: 2_000_000_000)
                    guard let self, self.isUnlocked, !self.wipedThisSession,
                          self.extProxyStatus == .unreadable else { return }
                    self.startTorOrDirect()
                }
            }
            return true
        // Both latch the Kotlin-side belt (IosAppController.externalProxyMode, one-way): no telemetry, no direct HTTP, no SOCKS isolation.
        case .invalid?:
            controller.externalProxyMode = true
            transport.extProxyStatus = .invalid
            transport.torState = .disconnected
            ConnectionLog.shared.append(
                kind: ConnectionLog.Kind.system,
                text: "ext proxy: setting invalid - messaging unavailable"
            )
            return true
        case .external(let ep)?:
            controller.externalProxyMode = true
            // The SOCKS path only ever carries a .onion (onionTransportGuard), and
            // direct HTTP is forbidden in this mode — a non-onion relay has no
            // permitted transport at all.
            guard RelayRoutingKt.relayRoutesViaTor() else {
                transport.extProxyStatus = .invalid
                transport.torState = .disconnected
                ConnectionLog.shared.append(
                    kind: ConnectionLog.Kind.system,
                    text: "ext proxy: relay is not an onion - messaging unavailable"
                )
                return true
            }
            if extProxyStatus == .off || extProxyStatus == .unreadable { transport.extProxyStatus = .checking }
            ConnectionLog.shared.append(
                kind: ConnectionLog.Kind.system,
                text: "ext proxy: \(ep.classWord) in use, embedded Tor disabled"
            )
            // A live transport from the start: requests to a dead proxy fail fast
            // (connection refused), and the health loop's misses re-probe the
            // proxy below — no extra timer.
            wireRelayTransport(socksPort: ep.port, reason: "external proxy")
            refreshExternalProxyReachability(force: true)
            return true
        }
    }

    /// SOCKS5-greets the configured proxy (ExternalProxyMode.probe — raw socket,
    /// IP literal) and publishes the verdict. [force] = ignore the 5 s rate
    /// limit (connect / manual Reconnect); otherwise driven only by the health
    /// loop's misses. Narrates TRANSITIONS only.
    private func refreshExternalProxyReachability(force: Bool) {
        guard let ep = ExternalProxyMode.shared.endpoint, !extProxyProbeInFlight else { return }
        let now = ProcessInfo.processInfo.systemUptime
        guard force || now - extProxyLastProbeUptime >= 5 else { return }
        extProxyLastProbeUptime = now
        extProxyProbeInFlight = true
        ExternalProxyMode.probe(ep) { [weak self] ok in
            hopToMain {
                guard let self else { return }
                self.extProxyProbeInFlight = false
                self.applyExternalProxyVerdict(ok, ep: ep)
            }
        }
    }

    private func applyExternalProxyVerdict(_ reachable: Bool, ep: ExternalProxyEndpoint) {
        let next: ExtProxyStatus = reachable ? .reachable : .unreachable
        if extProxyStatus != next {
            transport.extProxyStatus = next
            LogBuffer.shared.append(level: reachable ? "I" : "W", tag: "ExtProxy",
                message: "ext proxy: \(ep.classWord) \(reachable ? "reachable" : "unreachable")")
            ConnectionLog.shared.append(
                kind: ConnectionLog.Kind.relay,
                text: "ext proxy: \(ep.classWord) \(reachable ? "reachable" : "unreachable")"
            )
        }
        // torState doubles as "a SOCKS proxy is up" for the connecting UI and the
        // Add-Contact mint trigger (same as the debug direct branch). The embedded
        // TorManager never publishes in this mode, so nothing overwrites it.
        if isUnlocked { transport.torState = reachable ? .connected : .disconnected }
    }

    /// Creates the Kotlin-side MessageManager over Tor's SOCKS proxy and makes sure
    /// the periodic reachability loop is running. Idempotent: re-entry with a
    /// transport already wired only (re)ensures the loop, so the combine sink,
    /// the resume re-wire and the health loop's own self-heal can all call it.
    ///
    /// [reason] is log-only.
    private func wireRelayTransport(socksPort port: UInt16, reason: String) {
        if controller.messageManager == nil {
            // External proxy mode: the port comes from the user's setting — never logged.
            if ExternalProxyMode.shared.isExternalThisProcess {
                LogBuffer.shared.append(level: "D", tag: "AppState", message: "connecting MessageManager via external SOCKS proxy (\(reason))")
            } else {
                LogBuffer.shared.append(level: "D", tag: "AppState", message: "connecting MessageManager via Tor SOCKS port \(port) (\(reason))")
            }
            controller.connectTor(socksPort: Int32(port))
        }
        startRelayCheck()
    }

    /// [selfHeal] re-wires an absent transport before probing. Only the BACKGROUND
    /// health loop (and the manual Reconnect) may do that: `connectTor` produces no
    /// manager while the Kotlin `vault` is nil, so the condition doesn't clear and
    /// the sub-second conversation loop (0.5–1.2 s) would re-enter it ~1–2×/s on the
    /// MAIN ACTOR — main-thread churn plus a log line per tick, which floods the
    /// 2000-entry LogBuffer and evicts the diagnostics it exists to keep. The bg
    /// loop retries every 8–12 s, so recovery is bounded by one cycle either way.
    func checkRelayReachability(selfHeal: Bool = false) async {
        // Deliberately BEFORE the probe (see selfHealAbsentTransport).
        if selfHeal { selfHealAbsentTransport() }
        let mgr = controller.messageManager
        let hasMgr = mgr != nil
        let probe = await probeRelayDetached(mgr)
        // The probe runs DETACHED, so it ignores the enclosing loop's cancellation
        // and can still be in flight when the session locks — lock() →
        // stopRelayCheck(). Its worst case is RELAY_HEALTH_ATTEMPTS attempts on the
        // probe's OWN budget, never the 60 s message-transport default: 2 × 20 s
        // (HEALTH_HTTP_TIMEOUT_SECONDS) while this transport has yet to complete an
        // onion round-trip — long enough that a cold Tor CAN finish its one-off
        // descriptor fetch + rendezvous inside one attempt, since each attempt opens
        // a fresh stream and carries no progress over — then 2 × 10 s for every
        // cycle after the first success. Both are far from the ~120 s the inherited
        // default cost, which collapsed this loop to one probe pair per ~2 minutes
        // and pinned the UI on "Connecting to the relay…". A second probe can never
        // stack on top of an in-flight one (MessageManager.isRelayReachable
        // serialises them and hands the loser the last completed verdict), so the
        // manual Reconnect below cannot double the transport load either. Without
        // this guard that dead
        // session's result resumes here and writes isRelayReachable + the
        // hysteresis counters into the NEXT session, re-polluting exactly the
        // state stopRelayCheck() clears, and can latch isRelayReachable = true on
        // a LOCKED session (a lit runestone while locked).
        //
        // `isUnlocked` is the load-bearing half: reconnectRelay()'s ad-hoc Task
        // (and the conversation/group view loops) are NOT the cancelled
        // relayCheckTask, so Task.isCancelled alone misses them. Nothing legitimate
        // is suppressed — every caller only runs while unlocked (startRelayCheck is
        // reached from startTorOrDirect, itself only called after isUnlocked = true).
        guard !Task.isCancelled, isUnlocked else { return }

        evaluateUpdateNudgeOnce()
        evaluateReviewPromptOnce()
        noteExternalProxyProbe(answered: probe)
        let effective = probe ? noteRelayAnswered() : noteRelayMiss()
        publishReachability(effective, hasMgr: hasMgr)
        noteTransportForRedrive(probeAnswered: probe)
        armUnreadPrimeRevealCap(relayAnswered: effective)
        recomputeContactsReady()
        sendConnectTelemetryOnce(relayAnswered: effective)
        maybeOfferPushPromptOnRelayContact(relayReachable: effective)
        publishRelayHandshake(mgr)
    }

    /// checkRelayReachability phase (selfHeal only).
    /// CURRENT-VALUE self-heal, read synchronously at check time. The transport
    /// can be absent here even though Tor is up and the vault is unlocked —
    /// `connectTor` silently produces no manager when `vault` is nil (a lock
    /// racing the wiring), and the resume path can complete without ever
    /// reaching a wiring branch. Neither of those raises another CHANGE event,
    /// so an event-driven wiring alone leaves the app permanently silent (the
    /// relay sees literally zero requests). Reading TorManager's current port
    /// here re-establishes it on the very next tick.
    ///
    /// Deliberately BEFORE the probe, so this cycle still probes for real and
    /// cannot bump `relayUnreachableStreak` any more than it would have.
    private func selfHealAbsentTransport() {
        guard controller.messageManager == nil, isUnlocked,
              !TorManager.shared.relaunchRequired, !cachedPortAuthenticationInFlight else { return }
        // External proxy mode: the configured port (0 = no permitted transport).
        let currentPort = relayTransportSocksPort
        if currentPort > 0 {
            wireRelayTransport(socksPort: currentPort, reason: "health-loop self-heal")
        }
    }

    /// checkRelayReachability phase: the one relay-root probe, DETACHED (see the
    /// comment at the call site for why its verdict is re-gated on return).
    private func probeRelayDetached(_ mgr: MessageManager?) async -> Bool {
        await Task.detached(priority: .background) {
            mgr?.isRelayReachable() ?? false
        }.value
    }

    /// checkRelayReachability phase, called once per probe.
    private func noteExternalProxyProbe(answered probe: Bool) {
        // External proxy mode: a relay answer proves the proxy works; a miss
        // re-greets the proxy (rate-limited to one per 5 s inside) so the
        // `ext_proxy_status` line tells "your proxy is down" apart from "the
        // proxy is up but the onion half is slow". Rides this existing loop —
        // no timer of its own.
        if let ep = ExternalProxyMode.shared.endpoint {
            if probe { applyExternalProxyVerdict(true, ep: ep) }
            else { refreshExternalProxyReachability(force: false) }
        }
    }

    /// checkRelayReachability phase, the relay ANSWERED: reset the miss
    /// hysteresis and the NEWNYM rung state. Returns the effective verdict (true).
    private func noteRelayAnswered() -> Bool {
        relayUnreachableStreak = 0
        lastStreakBumpAtMs = 0   // next outage's first miss counts immediately
        unreachableRunStartedAtMs = 0
        lastSustainedNewnymAtMs = 0
        sustainedNewnymsFired = 0
        // Never downgrade .relaunchRequired (a process-lifetime latch).
        if relayConnectPhase != .relaunchRequired { relayConnectPhase = .connecting }
        return true
    }

    /// checkRelayReachability phase, the probe MISSED: the NEWNYM rungs, the
    /// counted-miss hysteresis and the stall latch. Returns the effective verdict:
    /// the last published value until the streak crosses the limit, then false —
    /// it reads `isRelayReachable` BEFORE publishReachability writes it.
    ///
    /// SELF-HEAL LADDER PARITY (cheap → expensive), kept legibly parallel to Android:
    ///   Both, BEFORE Tor is connected: TorManager's bootstrap-stall rung
    ///            (TorBootstrapStall: percent flat 20 s inside the ladder →
    ///            SETCONF DisableNetwork=1 then =0, ≤ 2 per Tor process,
    ///            10 s clear of any NEWNYM; codes TOR_BOOT_KICK / _SKIP).
    ///   iOS:     maybeFireEarlyNewnym (cold transport only, ~35 s / ~80 s from
    ///            the connect anchor, max 2) → maybeFireWarmNewnym (2026-10-07: warm
    ///            transport only, 3 full-budget timeouts / ≥ 28 s dark, then ≥ 40 s;
    ///            ≤ 2 per dark run, ≤ 6 per hour) → newnymAfterUnreachableMs (maybeFireSustainedNewnym,
    ///            line, cheap in-process circuit refresh, any session) → stalledStreakThreshold
    ///            (24 misses ≈ 3 min) → .stalled (manual Reconnect = another NEWNYM)
    ///            → TorManager `relaunchRequired` (process-lifetime latch; iOS CANNOT
    ///            restart Tor in-process, so recovery is exit(0)/relaunch, plus the
    ///            stuck-bootstrap self-heal that latches it).
    ///   Android: RunViewModel.maybeFireEarlyNewnym (the same shared cold-rung predicate) →
    ///            RunViewModel.maybeFireWarmNewnym (the same shared warm predicate) →
    ///            startRelayStallWatch's cheap-NEWNYM rung ahead of its heavier
    ///            restartTor() FULL Tor restart (RELAY_SELF_HEAL_RESTART_MS) →
    ///            RelayConnectPhase.Stalled. Android's heavy rung is an in-process Tor
    ///            restart (it CAN respawn the daemon); iOS's is relaunchRequired because
    ///            it can't. Keep both ladders NEWNYM-first.
    private func noteRelayMiss() -> Bool {
        // COLD-TRANSPORT NEWNYM RUNG — evaluated BEFORE the counted-miss hysteresis below,
        // because it is anchored on wall time from `connectStartUptime`, not on
        // misses. Every gate lives in commonMain (see maybeFireEarlyNewnym), so
        // this and Android's RunViewModel.maybeFireEarlyNewnym fire on the same
        // evidence at the same wall-clock. No-op once the relay has answered.
        maybeFireEarlyNewnym()
        // WARM-TRANSPORT NEWNYM RUNG (2026-10-07): the complement of the line
        // above — only a transport that HAS answered — likewise ahead of the
        // counted-miss hysteresis and the 64 s sustained rung below.
        maybeFireWarmNewnym()
        // iOS-1: only advance the streak once per bg-cadence window of wall-time, so
        // a fast conversation loop can't inflate it (see lastStreakBumpAtMs).
        let nowMs = Date().timeIntervalSince1970 * 1000
        if nowMs - lastStreakBumpAtMs >= AppState.minStreakBumpIntervalMs {
            bumpUnreachableStreak(nowMs: nowMs)
            maybeFireSustainedNewnym(nowMs: nowMs)
            maybeLatchStalled()
        }
        // Hold the last value until the streak crosses the threshold, then latch false.
        return relayUnreachableStreak >= AppState.relayUnreachableStreakLimit ? false : isRelayReachable
    }

    /// noteRelayMiss step: one counted miss (at most once per bg-cadence window).
    private func bumpUnreachableStreak(nowMs: Double) {
        lastStreakBumpAtMs = nowMs
        relayUnreachableStreak += 1
        if unreachableRunStartedAtMs == 0 { unreachableRunStartedAtMs = nowMs }
    }

    /// App-level circuit self-heal (LIGHTER than a full relaunch): only after
    /// a SUSTAINED unreachable run — a genuinely WEDGED circuit, since the relay
    /// itself stays up — ask Tor for fresh circuits (NEWNYM). Deliberately
    /// CONSERVATIVE (first fire after newnymAfterUnreachableMs of CONTINUOUS
    /// unreachability, then every newnymRepeatMs): a transient
    /// multi-device-contention flap recovers on its own inside that window, and
    /// firing NEWNYM into slow-but-working circuits just churns them (the same
    /// lesson as the e2e relaunch trigger, which had to back off 100s→240s). This
    /// targets a truly dead circuit — a real user stuck on "Connecting…" — without
    /// disrupting a handshake that was about to complete. Tor coalesces rapid NEWNYMs.
    ///
    /// WALL-CLOCK, not counted misses (2026-09-15, connect-time study §1c): a miss
    /// costs ~8–12 s warm but 20–40 s cold, so the old `% newnymEveryStreak == 0`
    /// rung fired at ~64 s warm and only at 160–320 s cold — i.e. never inside the
    /// connect waits it exists for. The threshold below is the same wall-clock the
    /// warm case always had (8 misses × the 8 s counted-miss floor), now measured
    /// directly. Android's sibling rung is likewise wall-clock anchored.
    private func maybeFireSustainedNewnym(nowMs: Double) {
        let unreachableForMs = nowMs - unreachableRunStartedAtMs
        let sinceLastNewnymMs = lastSustainedNewnymAtMs == 0
            ? unreachableForMs
            : nowMs - lastSustainedNewnymAtMs
        // Never in external proxy mode: there is no embedded Tor to signal.
        if !ExternalProxyMode.shared.isExternalThisProcess,
           unreachableForMs >= AppState.newnymAfterUnreachableMs,
           sinceLastNewnymMs >= AppState.newnymRepeatMs {
            lastSustainedNewnymAtMs = nowMs
            sustainedNewnymsFired += 1
            // Live connection-log panel (ConnectionLog.kt) — Android sibling:
            // RunViewModel.startRelayStallWatch's NEWNYM rung, which emits this
            // string verbatim. Numbers only.
            //
            // NAMES ITS RUNG (2026-09-15): the cold rung (maybeFireEarlyNewnym)
            // renders `(NEWNYM n/2)` and this one `(NEWNYM n, stall watch)`.
            // Both keep the same ConnectionLog.Code.newnym — the wire vocabulary
            // is unchanged and gains no token — but a reader (panel, debug log,
            // stored timeline read alongside them) could not otherwise tell the
            // cheap connect-time rung from this stall-watch escalation. `n` is
            // this unreachable run's own fire count.
            ConnectionLog.shared.append(
                kind: ConnectionLog.Kind.stall,
                text: "relay unreachable - requesting fresh circuits (NEWNYM \(sustainedNewnymsFired), stall watch)",
                code: ConnectionLog.Code.newnym
            )
            TorManager.shared.requestNewCircuit()
        }
    }

    /// noteRelayMiss step: latch `.stalled` (manual Reconnect) after
    /// stalledStreakThreshold counted misses.
    private func maybeLatchStalled() {
        // `== .connecting` (not `!= .stalled`): .relaunchRequired outranks
        // .stalled and must never be overwritten by the miss counter.
        if relayUnreachableStreak >= AppState.stalledStreakThreshold && relayConnectPhase == .connecting {
            relayConnectPhase = .stalled
            LogBuffer.shared.append(level: "W", tag: "Relay", message: "relay stalled (streak=\(relayUnreachableStreak)) — offering manual reconnect")
            ConnectionLog.shared.append(
                kind: ConnectionLog.Kind.stall,
                text: "relay stalled after \(relayUnreachableStreak) misses - offering manual reconnect",
                code: ConnectionLog.Code.relayStalled
            )
        }
    }

    /// checkRelayReachability phase: publish the effective verdict.
    private func publishReachability(_ effective: Bool, hasMgr: Bool) {
        if effective != isRelayReachable {
            LogBuffer.shared.append(level: "D", tag: "Relay", message: "reachable: \(isRelayReachable) → \(effective) (messageManager=\(hasMgr), missStreak=\(relayUnreachableStreak))")
        }
        isRelayReachable = effective
        if effective { relayAnsweredThisSession = true }
        #if DEBUG
        if effective { noteTorSuspendProbeAnswer() }
        #endif
    }

    /// checkRelayReachability phase: transport-back redrive bookkeeping.
    private func noteTransportForRedrive(probeAnswered probe: Bool) {
        // Transport-back redrive (2026-10-16): keyed on the RAW probe, not on
        // `effective` — the hysteresis latches `isRelayReachable` false only after
        // relayUnreachableStreakLimit counted misses, but a send that failed on
        // a transport-class error during a shorter dark run is just as stuck.
        // Fires exactly once per miss→answer transition (see transportDownForRedrive).
        if probe {
            if transportDownForRedrive {
                transportDownForRedrive = false
                redriveTransportFailuresOnce()
            }
        } else {
            transportDownForRedrive = true
        }
    }

    /// checkRelayReachability phase: the contactsReady reveal backstop.
    private func armUnreadPrimeRevealCap(relayAnswered effective: Bool) {
        // Reveal backstop for contactsReady: the relay has answered but the
        // unread prime has not settled — a wedged peek must not hold the
        // contacts hostage. Counted from the first answer, not from the prime's
        // start (the prime is fired at Tor Connected, often long before).
        if effective, !unreadPrimeSettled, unreadPrimeCapTask == nil {
            unreadPrimeCapTask = Task { @MainActor [weak self] in
                try? await Task.sleep(nanoseconds: UInt64(AppState.unreadPrimeRevealCapSec * 1_000_000_000))
                guard !Task.isCancelled, let self else { return }
                // The PRIME_CAP line and the flip both belong to
                // settleUnreadPrime: it re-reads the flag, so a cap that expires
                // after the prime already settled narrates nothing.
                self.settleUnreadPrime(ConnectReveal.PrimeEvent.cap)
            }
        }
    }

    /// In-app update nudge, at most once per session; called once per probe from checkRelayReachability.
    private func evaluateUpdateNudgeOnce() {
        // In-app update nudge (UpdateNudge.kt / UpdateCheck.kt in commonMain).
        // newerRelayVersionForNudge() is a cheap RAM-latch read, safe to call
        // right here on the main actor. The throttle read (and, on a true
        // verdict, the write) is blocking vault I/O, so it hops off to a
        // detached task exactly like the reachability probe above — same
        // dance as consumePushPromptOnce's DispatchQueue.global hop elsewhere
        // in this file. Evaluated at most once per session (updateNudgeEvaluated).
        // Never logs the version (update nudge).
        if !updateNudgeEvaluated, let nudgeVersion = controller.newerRelayVersionForNudge() {
            updateNudgeEvaluated = true
            // Snapshot BEFORE the detached Task, same idiom as
            // refreshPushRegistrationIfNeeded()/deleteContactPurgingRelay() above
            // — `controller` is a plain Kotlin object reference, not itself
            // main-actor-isolated, so it's safe to call off-actor; only the
            // eventual @Published write needs to hop back via MainActor.run.
            let controller = self.controller
            Task.detached(priority: .background) { [weak self] in
                if controller.shouldShowUpdateNudge(version: nudgeVersion) {
                    // WRITE ON SHOW: before the @Published flip below, not on
                    // dismiss/tap, so a force-quit (or Android's onStop
                    // teardown) between "shown" and "tapped" can't re-nag on
                    // the next foreground.
                    controller.markUpdateNudgeShown(version: nudgeVersion)
                    await MainActor.run {
                        self?.showUpdateNudge = nudgeVersion
                    }
                }
            }
        }
    }

    /// In-app store-review nudge, at most once per session; called once per probe from checkRelayReachability.
    private func evaluateReviewPromptOnce() {
        // In-app store-review nudge (ReviewPromptPolicy.kt, commonMain — the
        // pure decision function; everything here is orchestration). Same
        // "at most once per session" shape as the update nudge above,
        // deliberately NOT nested inside its `if` — a session that never
        // sees an advertised update must still get its one review check.
        // Placed right AFTER it so the ordering check below reads
        // `showUpdateNudge` in a state that has had a real chance to settle
        // for THIS tick (the update-nudge write above is itself a detached
        // Task, so this is a best-effort ordering check, not a guarantee —
        // cosmetic UX polish, not a security control; an occasional overlap
        // is a known limitation, same tolerance this file already grants
        // update-nudge races elsewhere). Fires on the FIRST tick of this loop
        // (~8-12 s post-unlock), not at unlock itself, so the relay-driven,
        // asynchronous update nudge has had a real chance to decide first.
        if !reviewPromptEvaluated {
            reviewPromptEvaluated = true
            // Ordering rule: never in the same session as the push prompt or
            // the update nudge — both are dialogs the native OS review sheet
            // would otherwise stack awkwardly on top of. If either is up
            // right now, this whole session is skipped (the latch above
            // means it is not retried later this session); the next
            // foreground is a fresh AppState (a fresh launch — see the class
            // doc on updateNudgeEvaluated above) and gets a fresh, unbiased
            // check.
            if !showPushPrompt, showUpdateNudge == nil, let openVault = vault {
                let isDebug = BuildFlagsKt.isDebugBuildPublic()
                Task.detached(priority: .background) { [weak self] in
                    // The array itself carries N live,
                    // un-zeroed sharedSecret pre-images even though only `.count`
                    // is ever read from it — the old comment here claimed a wipe
                    // that did not happen. Mirrors RunViewModel.kt's identical
                    // getAllContacts() call for the same review-prompt check.
                    let records = openVault.getAllContacts()
                    let contactCount = Int32(records.count)
                    for record in records { record.sharedSecret.secureWipe() }
                    // The vault's
                    // `_meta` singleton now, not UserDefaults — see
                    // ReviewPromptPolicy.kt's vault-store section.
                    let state = ReviewPromptPolicyKt.readReviewPromptState(vault: openVault)
                    let shouldShow = ReviewPromptPolicy.shared.shouldPrompt(
                        now: Int64(Date().timeIntervalSince1970 * 1000),
                        firstUnlockAt: state.firstUnlockAt,
                        unlockCount: state.unlockCount,
                        contactCount: contactCount,
                        alreadyPrompted: state.alreadyPrompted,
                        isDebugBuild: isDebug
                    )
                    if shouldShow {
                        // WRITE ON ASK, before the flow launches — see
                        // ReviewPromptPolicyKt.markReviewPromptShown's kdoc.
                        ReviewPromptPolicyKt.markReviewPromptShown(vault: openVault)
                        await MainActor.run {
                            self?.requestReviewFlow = true
                            self?.reviewSheetRequestedThisSession = true
                        }
                    }
                }
            }
        }
    }

    /// Connect-time telemetry + Debug-mode "connect" flush, once per session, on the
    /// first relay answer (`effective` = this tick's hysteresis verdict).
    private func sendConnectTelemetryOnce(relayAnswered effective: Bool) {
        // Anonymous connect-time report (ConnectTelemetry.kt, commonMain) —
        // Debug-mode-only (the shared object drops it without consent);
        // fired on the FIRST relay answer of the session, the same instant the
        // push prompt below is gated on. Latched BEFORE handing off, so a
        // reachability flap can never produce a second report. Everything that
        // makes it safe (no capability, no auth, no identifier, 5 s buckets,
        // 2-8 s jitter, one attempt, nothing persisted) lives in the shared
        // object; IosAppController.reportConnectTime only supplies the
        // transport. Android sibling: RunViewModel.armConnectTelemetry.
        guard effective, !connectTelemetrySent, let connectStartedAt = connectStartUptime else { return }
        connectTelemetrySent = true
        // Clamped before the Int64 conversion: Int64(Double) TRAPS on a
        // NaN/out-of-range value, and this is arithmetic on a system clock.
        // The shared object clamps to 3600 s anyway, so 24 h is pure safety.
        let elapsed = min(max(0, ProcessInfo.processInfo.systemUptime - connectStartedAt), 86_400)
        // PHASE SPLIT (lever 5): how much of that wait was Tor's bootstrap.
        // Measured off the SAME anchor, so the relay can derive the
        // rendezvous+relay phase as `secs - tor` without a second clock.
        // Since lever 2, Tor usually reaches .connected BEFORE the anchor, so
        // the max(0, …) makes this 0 — which is the true and interesting
        // answer: the bootstrap cost the user nothing. nil only when Tor never
        // reported connected this session (the debug/simulator direct branch,
        // which never sets torConnectedUptime).
        let torElapsed: KotlinLong? = torConnectedUptime.map {
            KotlinLong(value: Int64(min(max(0, $0 - connectStartedAt), 86_400) * 1000))
        }
        // `boot` (2026-09-11): seconds from this session's Tor PROCESS start
        // — `TorManager.shared.startedAtUptime`, a DIFFERENT anchor than
        // `connectStartedAt` (the speculative start usually runs well before
        // unlock) — to the same first-.connected moment as `torElapsed`.
        // `startedAtUptime` is set at most once per process (tor_main can
        // run only once; see its kdoc), so this never moves across a
        // relaunchRequired teardown — there simply is no next report in
        // this process once that latches. nil when Tor never started this
        // process (`startedAtUptime == 0`, the debug/simulator direct
        // branch) or never connected, AND for a WARM session (bounded
        // keep-alive): it adopted the previous session's Tor and started no
        // Tor process, so `boot` is honestly omitted (Android parity) rather
        // than measured from the first session's start. Unlike
        // `torElapsed`, never capped against `elapsed` — the two share no anchor.
        let bootStartedAt = warmTorSession ? 0 : TorManager.shared.startedAtUptime
        let bootElapsed: KotlinLong? = (bootStartedAt > 0 ? torConnectedUptime : nil).map {
            KotlinLong(value: Int64(min(max(0, $0 - bootStartedAt), 86_400) * 1000))
        }
        // DEBUG MODE ONLY (2026-11-03): the report goes out only while the
        // user's Debug mode consent is on — a default install sends nothing
        // about itself. IosAppController.reportConnectTime re-reads the
        // persisted consent after the jitter as the Kotlin-side belt.
        // External SOCKS proxy mode: NO connect-time report either. The
        // numbers would describe the user's own proxy, not this app's Tor,
        // and the report is skipped rather than mislabelled. (The latch
        // above is still set in both cases, so this stays a once-per-process
        // decision; a consent granted later in the session reports next
        // session. Android sibling: RunViewModel.armConnectTelemetry.)
        if debugMode, !ExternalProxyMode.shared.isExternalThisProcess {
            controller.reportConnectTime(elapsedMs: Int64(elapsed * 1000), torElapsedMs: torElapsed, bootElapsedMs: bootElapsed)
        }
        // Debug mode's "connect" flush — same first-relay-answer,
        // once-per-session occasion as the telemetry report just above
        // (this whole `if` already latches connectTelemetrySent), but
        // gated on the user's own opt-in rather than unconditional. Same
        // 2-8 s jitter so it isn't co-timed with the telemetry POST
        // either. Fire-and-forget; never blocks the main actor.
        // [DebugLogUploader.flush] is cursor-based (DebugMode.kt,
        // commonMain) — this call ships only whatever is new since the
        // last successful flush and is a cheap no-op (no POST at all)
        // when nothing is pending, which is what makes the periodic
        // loop below safe to run at roughly 1 Hz.
        if debugMode {
            let controller = self.controller
            let app = debugLogAppVersion
            // The handle is KEPT ([debugLogConnectTask]) so lock / wipe /
            // a consent toggle-off can cancel it mid-jitter, and `debugMode`
            // is RE-CHECKED after the sleep: up to 8 s pass in here, which
            // is long enough for the user to revoke consent, and an orphan
            // flush would then upload against a revoked flag. Previous
            // session's task is cancelled first — this site latches
            // connectTelemetrySent, so a second one should not exist, but
            // an overwritten handle would leak the old task uncancellable.
            debugLogConnectTask?.cancel()
            debugLogConnectTask = Task.detached(priority: .background) { [weak self] in
                try? await Task.sleep(nanoseconds: UInt64.random(in: 2_000_000_000...8_000_000_000))
                if Task.isCancelled { return }
                guard let self else { return }
                let stillOn = await MainActor.run { self.debugMode && self.isUnlocked }
                guard stillOn else { return }
                let transport = controller.messageManager?.relayTransport()
                _ = try? await DebugLogUploader.shared.flush(
                    transport: transport, platform: "ios", app: app, reason: "connect"
                )
            }
        }
    }

    /// First-open push prompt, raised on the first relay answer of the session.
    private func maybeOfferPushPromptOnRelayContact(relayReachable effective: Bool) {
        // First-open push prompt (PushPromptOnboarding.kt): raised on the FIRST
        // relay answer of the session, never at unlock (2026-09-11, user
        // directive) — the list is revealed at this same instant and the switch
        // the prompt leads to can register now. The vault-meta latch is consumed
        // off the main actor (same hop as the update nudge below); the flag flips
        // first so a reachability flap can never re-ask. Android sibling:
        // RunViewModel.armPushPromptForFirstRelayContact.
        if PushPromptOnboardingKt.pushPromptDueOnRelayContact(
            relayReachable: effective,
            alreadyOfferedThisSession: pushPromptOfferedThisSession,
            reviewSheetRequestedThisSession: reviewSheetRequestedThisSession
        ) {
            pushPromptOfferedThisSession = true
            let controller = self.controller
            Task.detached(priority: .utility) { [weak self] in
                let due = controller.consumePushPromptOnce()
                // Let the list reveal finish before presenting: the same relay
                // answer fades the placeholder into the list (ContactListView
                // litFadeDuration 0.8 s), and a dialog presented mid-transition
                // is hit-tested against a view that is being swapped out — the
                // first tap on it could be swallowed (seen on the simulator).
                if due { try? await Task.sleep(nanoseconds: 1_200_000_000) }
                await MainActor.run {
                    guard let self, self.isUnlocked, due else { return }
                    self.showPushPrompt = true
                }
            }
        }
    }

    /// Honest "connected" signal for the UI (parity with Android
    /// RunViewModel: `_relayHandshakeComplete.value = mgr?.hasCompletedRelayRoundTrip()`).
    /// Read from the SAME captured `mgr` the probe used — not from `probe` — so the
    /// pre-mint warm-circuit gate's successful round-trip also counts, and so this
    /// never flaps on the reachability hysteresis (the shared latch is monotonic per
    /// transport). `mgr == nil` (transport torn down / re-wiring) reads false, which
    /// is the correct reset; stopRelayCheck() also clears it on lock/wipe.
    private func publishRelayHandshake(_ mgr: MessageManager?) {
        let handshook = mgr?.hasCompletedRelayRoundTrip() ?? false
        if handshook && !relayHandshakeComplete {
            LogBuffer.shared.append(level: "I", tag: "Relay", message: "first onion round-trip completed — relay handshake done")
            ConnectionLog.shared.append(
                kind: ConnectionLog.Kind.relay,
                text: "first onion round-trip completed",
                code: ConnectionLog.Code.firstRoundtrip
            )
            // Start the push re-registration pass now rather than at the first
            // control-poll cycle (~30 s later) — the pass is long and short sessions
            // were backgrounded before it ran. Gates mirror the control-poll site:
            // unlocked, not move-frozen (a frozen phone must not re-register rows the
            // export deleted); push/token/port gating lives inside the function, and
            // a concurrent pass is skipped by its single-flight flag.
            if isUnlocked, !isMoveFrozen, !wipedThisSession {
                refreshPushRegistrationIfNeeded()
            }
        }
        relayHandshakeComplete = handshook
        if handshook { relayAnsweredThisSession = true }
    }

    /// COLD-TRANSPORT NEWNYM RUNG
    /// — the CHEAPEST and EARLIEST rung of the self-heal ladder, ahead of the
    /// sustained rung in `checkRelayReachability` and far ahead of `.stalled` /
    /// `relaunchRequired`.
    ///
    /// The phase it targets is INTRODUCTION, not bootstrap: the HS descriptor lands
    /// in ~5 s and an intro/rendezvous circuit is built in 5–15 s, then the
    /// introduction point never completes and the session burns 20 s probes on fresh
    /// STREAMS over the same wedged circuit (rotating a stream rotates neither the
    /// circuit nor the descriptor). `SIGNAL NEWNYM` purges the HS client state and
    /// recovered it in < 5 s where it was observed; it leaves the entry guards alone.
    ///
    /// EVERY gate lives in commonMain — `IosAppController.earlyNewnymDue` →
    /// `MessageManager.shouldFireEarlyNewnym` — so Android's
    /// `RunViewModel.maybeFireEarlyNewnym` fires on exactly the same evidence at
    /// exactly the same wall-clock: cold transport only (never after this session's
    /// first relay answer), ≥ 35 s from `connectStartUptime`, ≥ 2 consecutive
    /// full-budget PROBE_TIMEOUTs, at most `earlyNewnymMaxFires()` per session with
    /// the second not before ~80 s.
    ///
    /// Never touches `connectStartUptime` / `torConnectedUptime`: the connect report
    /// must keep measuring launch → first answer, so a self-heal inside that wait
    /// stays inside the number it improves. No-op on the simulator/direct branch
    /// (no anchor is set there until startTorOrDirect, and Tor's control channel is
    /// absent — `requestNewCircuit()` then reports false and the rung retires).
    private func maybeFireEarlyNewnym() {
        // External proxy mode: no embedded Tor, no NEWNYM, no panel line.
        guard !ExternalProxyMode.shared.isExternalThisProcess else { return }
        guard let connectStartedAt = connectStartUptime else { return }
        guard !TorManager.shared.relaunchRequired else { return }
        let sinceAnchorMs = max(0, ProcessInfo.processInfo.systemUptime - connectStartedAt) * 1000
        guard controller.earlyNewnymHasBudget() else { return }
        guard controller.earlyNewnymDueWithColdFires(
            msSinceConnectAnchor: Int64(min(sinceAnchorMs, 86_400_000)),
            newnymsFiredThisSession: controller.earlyNewnymFiredThisSession(),
            coldRungFiresThisSession: controller.earlyNewnymColdFires()
        ) else { return }
        guard TorManager.shared.requestNewCircuit() else {
            // Control channel down — NEWNYM is unavailable for this process, so
            // stop spending rungs on it (Android does the same).
            LogBuffer.shared.append(level: "W", tag: "Relay",
                message: "NEWNYM unavailable (control channel down) — cold-start circuit rotation skipped")
            controller.exhaustEarlyNewnyms()
            return
        }
        bookEarlyNewnym(cold: true,
                        logMessage: "no relay answer yet after \(Int(sinceAnchorMs / 1000))s — requested fresh Tor circuits")
    }

    /// WARM-TRANSPORT NEWNYM RUNG (2026-10-07) — the cheap rung for a session whose
    /// transport HAS answered and then went dark (onion half wedged mid-session, Tor
    /// still at 100 %). `maybeFireEarlyNewnym` retires at the first answer and the
    /// sustained rung below needs 64 s of counted misses from the first counted miss
    /// (~110 s into a warm outage on the 30 s warm cadence).
    ///
    /// EVERY gate lives in commonMain — `IosAppController.warmNewnymDue` →
    /// `MessageManager.shouldFireWarmNewnym`, budgets in the shared `WarmNewnymLedger`
    /// the controller holds — so Android's `RunViewModel.maybeFireWarmNewnym` fires
    /// on the same evidence: warm transport only, ≥ 3 consecutive full-budget
    /// PROBE_TIMEOUTs spanning ≥ 28 s for the first fire; ≥ 2 fresh ones and ≥ 40 s
    /// after it for the second; ≤ 2 per dark run, ≤ 6 per hour. Called from every
    /// `checkRelayReachability` caller (bg + conversation loops); the shared evidence
    /// run is cleared at each fire, so the extra callers cannot double-fire. The
    /// sustained rung, `.stalled` and `relaunchRequired` are untouched backstops.
    private func maybeFireWarmNewnym() {
        // External proxy mode: no embedded Tor, no NEWNYM, no panel line.
        guard !ExternalProxyMode.shared.isExternalThisProcess else { return }
        guard !TorManager.shared.relaunchRequired else { return }
        guard controller.warmNewnymDue() else { return }
        guard TorManager.shared.requestNewCircuit() else {
            // Control channel down — stop asking for the rest of this dark run
            // (Android does the same; its stall watch then restarts Tor).
            LogBuffer.shared.append(level: "W", tag: "Relay",
                message: "NEWNYM unavailable (control channel down) — warm circuit rotation skipped")
            controller.retireWarmNewnymRun()
            return
        }
        controller.noteWarmNewnymFired()
        let n = Int(controller.warmNewnymFiresThisRun())
        let maxFires = Int(controller.warmNewnymMaxPerRun())
        LogBuffer.shared.append(level: "W", tag: "Relay",
            message: "relay dark for \(controller.warmDarkForSeconds())s after answering — requested fresh Tor circuits (NEWNYM \(n)/\(maxFires), warm)")
        // Panel line: the shared NEWNYM phrase + the fixed word `warm`, numbers
        // only — the Android sibling emits the identical string.
        ConnectionLog.shared.append(
            kind: ConnectionLog.Kind.stall,
            text: "relay unreachable - requesting fresh circuits (NEWNYM \(n)/\(maxFires), warm)",
            code: ConnectionLog.Code.newnym
        )
    }

    /// Replays every outbound message whose last failure was transport-class
    /// (MessageManager.redriveTransportFailures — the manual-Retry path, bounded
    /// to the last 15 min, count-only logging) on the transport-back edge that
    /// checkRelayReachability detects. Runs on the SAME detached background
    /// context the reachability probe and the push-wake peeks use — sends are
    /// blocking onion round-trips — and from this one call site only: never a
    /// view body, so it fires with no conversation open. The Android sibling
    /// (RunViewModel) calls the same shared function on its manager-recreated
    /// edge; this is the whole platform half.
    private func redriveTransportFailuresOnce() {
        guard !transportRedriveInFlight, isUnlocked, let mgr = controller.messageManager else { return }
        transportRedriveInFlight = true
        LogBuffer.shared.append(level: "D", tag: "Relay", message: "transport back — re-driving transport-failed sends")
        Task.detached(priority: .background) { [weak self] in
            // try? flattens the bridged suspend's throws into a count of 0 — a
            // pass that could not run is simply the next edge's problem.
            let count = (try? await mgr.redriveTransportFailures())?.intValue ?? 0
            await MainActor.run {
                self?.transportRedriveInFlight = false
                LogBuffer.shared.append(level: "D", tag: "Relay", message: "transport back — re-driving done (\(count) re-sent)")
            }
        }
    }

    /// Manual "Reconnect" from the relay-stalled contact list (QA #1). iOS can't restart
    /// Tor in-process, so this fires a fresh circuit (NEWNYM) — the same self-heal the
    /// background loop uses — resets the escalation, and re-probes immediately. If Tor's
    /// thread is truly dead, the UI's relaunch hint is the real fix.
    func reconnectRelay() {
        // No Reconnect exists in the .relaunchRequired UI, but never let a stray
        // call downgrade the process-lifetime latch back to "Connecting…".
        guard relayConnectPhase != .relaunchRequired else { return }
        LogBuffer.shared.append(level: "I", tag: "AppState", message: "manual relay reconnect requested (NEWNYM)")
        ConnectionLog.shared.append(
            kind: ConnectionLog.Kind.stall,
            text: "manual reconnect requested",
            code: ConnectionLog.Code.manualReconnect
        )
        relayConnectPhase = .connecting
        relayUnreachableStreak = 0
        lastStreakBumpAtMs = 0
        // The sustained rung's wall-clock window re-arms from NOW (this tap just
        // fired the same NEWNYM it would have). Deliberately NOT the early-NEWNYM ledger:
        // that cap is per SESSION, like the connect anchor it is measured against.
        unreachableRunStartedAtMs = 0
        lastSustainedNewnymAtMs = 0
        sustainedNewnymsFired = 0
        if ExternalProxyMode.shared.isExternalThisProcess {
            // No embedded Tor to rotate: re-greet the user's proxy instead (and
            // re-wire if the transport is absent — the self-heal below).
            refreshExternalProxyReachability(force: true)
        } else {
            TorManager.shared.requestNewCircuit()
        }
        Task { await checkRelayReachability(selfHeal: true) }
    }

    /// Starts periodic relay reachability checks (jittered 8–12 s cadence).
    ///
    /// IDEMPOTENT: a loop that is already running is left alone. The loop reads
    /// `controller.messageManager` fresh every cycle, so it never needs restarting
    /// when the transport is re-wired — and restarting it would fire an extra
    /// immediate probe (plus an extra control-poll warm-up) each time
    /// `wireRelayTransport` is called.
    private func startRelayCheck() {
        if let existing = relayCheckTask, !existing.isCancelled { return }
        relayCheckTask?.cancel()
        relayCheckTask = Task { @MainActor in
            while !Task.isCancelled {
                // The ONLY loop allowed to re-wire an absent transport (see
                // checkRelayReachability's [selfHeal]) — 8–12 s, off the view loops.
                await checkRelayReachability(selfHeal: true)
                // Cadence decided in commonMain (MessageManager.relayHealthDelayMs)
                // so both platforms schedule identically: the jittered 8–12 s
                // heartbeat once this transport has completed an onion round-trip
                // (#13 — a fixed period would be a traffic-analysis beacon for the
                // relay / guard node), and a bounded 1–2 s retry until then, so a
                // cold start spends its first minute rotating onto fresh Tor streams
                // instead of sleeping between them. No transport to probe
                // (messageManager == nil, re-wiring) ⇒ nothing was retried, so it
                // keeps the steady-state heartbeat.
                let delayMs = controller.messageManager?.relayHealthDelayMs()
                    ?? Int64.random(in: 8_000...12_000)
                try? await Task.sleep(nanoseconds: UInt64(max(delayMs, 0)) * 1_000_000)
            }
        }
        startControlPoll()
        // Races the unread dot ahead of startControlPoll's first jittered
        // cycle (3-7s+); merge-only per-contact emission, steady-state loop
        // above is unchanged. It now opens with a control PRE-DRAIN of the
        // group members' control inboxes (see GroupManager.primeUnreadCounts),
        // so a pending GROUP text is attributed to the group instead of the
        // sender's 1:1 row — the two are indistinguishable in a /peek count.
        startUnreadPrime()
        // Debug mode (settings row). RE-READ the persisted consent here, not
        // just the value AppState.init cached: that init ran in RunApp's first
        // initializer, where a cold start (push wake, launch from the lock
        // screen, first instants after unlock) can find the unlocked-only
        // Keychain item unreadable, and DebugMode reads that as OFF. The vault
        // is open by now, so the keybag is unlocked and the read is honest.
        // Only ever flips OFF → ON (a revoked consent is never resurrected —
        // see DebugMode.reapplyPersisted); the connect flush and the periodic
        // loop below both gate on `debugMode`. Prod repro 2026-09-20: flag
        // persisted, two cold relaunches, connect telemetry received, zero
        // /debuglog batches, Settings row showing ON.
        // No `!debugMode` short-circuit: the flag read and the LoggingState
        // switch are TWO reads (RunApp.init vs AppState.init) — a successful
        // flag read says nothing about whether LoggingState got turned on.
        // reapplyDebugModeAfterUnlock is idempotent and only ever flips OFF→ON.
        if controller.reapplyDebugModeAfterUnlock() {
            let wasOff = !debugMode
            debugMode = true
            if wasOff {
                LogBuffer.shared.append(level: "I", tag: "AppState", message: "debug mode re-applied after unlock (startup read had failed)")
            }
        }
        startDebugLogLoop()
    }

    /// One-shot parallel /peek sweep fired the instant the transport is
    /// (re)wired: races the contact-list "message waiting" dot ahead of
    /// [startControlPoll]'s first jittered cycle instead of waiting on the
    /// full sequential sweep. Never throws; calls onComplete on the sweep's
    /// own thread when done (or immediately if the vault is locked/nil) —
    /// nothing here needs to await it.
    ///
    /// It DRAINS the group members' CONTROL inboxes before those peeks (never a
    /// text inbox — those stay peek-only, burn-on-read on the relay), because a
    /// group text rides the sender's 1:1 text inbox and a /peek returns only a
    /// count: without the KIND_ACTIVITY notice that drain delivers, a group
    /// message lights the SENDER's contact row. So this and startControlPoll can
    /// overlap; GroupManager serialises them (the second one skips) and a batch
    /// the prime took is still reported to the poll loop's next cycle, so the
    /// "an applied invite surfaces a group row" nudge is never lost. The blocked
    /// set passed here gates the pre-drain too.
    private func startUnreadPrime() {
        guard isUnlocked, vault != nil else {
            // No sweep is coming — never hold the reveal on it.
            settleUnreadPrime(ConnectReveal.PrimeEvent.skipped)
            return
        }
        let blocked = Array(BlockStore.blocked())
        // Captured on Main, used off-main in onComplete below (the control loop
        // calls groupUnreadCounts() off-main the same way).
        let gm = controller.groupManager
        controller.primeUnreadCounts(blockedContactIds: blocked, onContactUnread: { id, n in
            // Callback arrives on a BACKGROUND thread (Kotlin coroutine) —
            // hop to Main before touching @Published state, same idiom as
            // unlock()'s DispatchQueue.global → DispatchQueue.main hop above.
            hopToMain {
                guard self.isUnlocked else { return }
                // Function-type args box their Ints in the ObjC export, so n
                // arrives as KotlinInt (NSNumber) — unbox, don't Int(n).
                let count = Int(truncating: n)
                if count > 0 {
                    self.unreadCounts[id] = count
                } else {
                    self.unreadCounts.removeValue(forKey: id)
                }
                // C4b: the FIRST per-contact result releases the reveal — the
                // visible list is already correct, and the peeks still in
                // flight update their own rows in place (merge-only), exactly
                // as the steady-state sweep does seconds later. Measured: in
                // 44 of 45 iOS timelines the whole pass had NOT finished when
                // the relay answered, so waiting for it cost up to the full
                // cap on top of the network wait.
                self.settleUnreadPrime(ConnectReveal.PrimeEvent.firstDot)
            }
        }, onComplete: { [weak self] in
            // Settled on EVERY exit (done, failed, skipped) — the contact-list
            // reveal (contactsReady) must never wait on a dead sweep. Since C4b
            // this is normally already settled by the first dot above; it still
            // carries the passes that emit NOTHING: a vault with no contacts, a
            // pass where every peek failed, a cancelled one.
            hopToMain { self?.settleUnreadPrime(ConnectReveal.PrimeEvent.passEnded) }
            // The prime pre-drains group members' CONTROL inboxes (activity
            // notices) before it peeks, so the per-group counts are already
            // current — publish them now rather than on the control loop's
            // first cycle (3–7 s), so the GROUP dot lights in the same beat the
            // contact dot is (correctly) withheld. Same boxed-Int unwrap as the
            // control loop's intMap; hop to Main before touching @Published.
            guard let gm else { return }
            var groupUnread: [String: Int] = [:]
            for (k, v) in gm.groupUnreadCounts() {
                groupUnread[k] = (v as? Int) ?? ((v as? NSNumber)?.intValue ?? 0)
            }
            hopToMain {
                guard let self, self.isUnlocked else { return }
                if self.groupUnreadCounts != groupUnread { self.groupUnreadCounts = groupUnread }
            }
        })
    }

    /// Background CONTROL-channel poll: drains every contact's control inbox
    /// (group invites/rosters/joins/leaves + inbox announces) on a jittered
    /// loop while the vault is unlocked — what makes a group appear on EVERY
    /// member's device without a conversation being open. Texts live on
    /// separate inboxes and are untouched (relay-retention of unread).
    private func startControlPoll() {
        controlPollTask?.cancel()
        let controller = self.controller
        // Session token: a sweep already inside a blocking /peek when lock() /
        // emergencyWipe() runs is NOT stopped by the cancel (the call is
        // synchronous), so every main-actor write below re-checks this token —
        // a late sweep must not re-plant contact ids into the maps the lock just
        // cleared (Android sibling: RunViewModel's pollEpoch).
        let pollSession = sessionGeneration
        controlPollTask = Task.detached(priority: .background) {
            // Establish the Block set on the SHARED
            // groupManager instance UP FRONT — before the 3–7 s warm-up sleep — so both
            // this loop AND the on-demand pollGroup/pollDirect paths (which reuse the
            // same instance) honor Block from the very first poll, not only after the
            // loop's first tick. The set lives Swift-side (BlockStore/Keychain);
            // GroupManager (Kotlin) reads this provider to skip a blocked contact's
            // inbox and drop any invite/referral-offer/inbox-announce from a blocked
            // sender. pollGroup/pollMessages ALSO set it defensively (belt-and-braces
            // against a re-created groupManager). Re-set each cycle too.
            controller.groupManager?.blockedContacts = { BlockStore.blocked() }
            try? await Task.sleep(nanoseconds: UInt64.random(in: 3_000_000_000...7_000_000_000))
            while !Task.isCancelled {
                // pollAllControls returns true when a control batch was
                // drained — an applied invite/roster/announce may have
                // changed vault contents with no navigation. Nudge the
                // contact list to re-query (same fix as Android's
                // vaultEvents; caught by the 3-emulator group e2e suite).
                controller.groupManager?.blockedContacts = { BlockStore.blocked() }
                let received = controller.groupManager?.pollAllControls() == true
                if received {
                    await MainActor.run {
                        NotificationCenter.default.post(name: .contactsChanged, object: nil)
                    }
                }
                // Surface contacts the relay has persistently 404'd (inbox lost) so
                // the list flags them for re-pair. The set is accumulated inside
                // pollControlMessages above; publish it and, on a change, nudge the
                // list to re-query (loadContacts re-reads it into each row's `stale`).
                if let lost = controller.messageManager?.relayLostContacts() {
                    let finalSet = Set(lost.map { String(describing: $0) })
                    await MainActor.run {
                        guard self.isPollSessionCurrent(pollSession) else { return }
                        if self.relayLostContacts != finalSet {
                            self.relayLostContacts = finalSet
                            NotificationCenter.default.post(name: .contactsChanged, object: nil)
                        }
                    }
                }
                // Same cadence: keep push registration in sync with newly minted
                // inbound-text inboxes (coverage-gap fix — see
                // refreshPushRegistrationIfNeeded's kdoc). No-op unless push is
                // opted in and a token is cached; cheap in-memory diff otherwise.
                await MainActor.run {
                    self.refreshPushRegistrationIfNeeded()
                }
                // Same cadence/scope: a non-destructive /peek sweep driving the
                // per-contact unread badge — group-adjusted (group texts riding a
                // contact's inbox are subtracted off and attributed to the group
                // dot instead) — plus the per-group unread counts.
                if let gm = controller.groupManager {
                    // Kotlin Map<String,Int> bridges with boxed (NSNumber) values
                    // — same unwrap the old peekUnreadCounts sweep used.
                    func intMap<V>(_ counts: [String: V]) -> [String: Int] {
                        var map: [String: Int] = [:]
                        for (k, v) in counts {
                            map[k] = (v as? Int) ?? ((v as? NSNumber)?.intValue ?? 0)
                        }
                        return map
                    }
                    // Pass the blocked-contact set so the background sweep
                    // does not poll blocked inboxes (block now stops the network
                    // fetch, not just the row display).
                    let contactUnread = intMap(gm.contactUnreadCounts(blockedContactIds: BlockStore.blocked()))
                    let groupUnread = intMap(gm.groupUnreadCounts())
                    await MainActor.run {
                        // Publish only on CHANGE. An unconditional
                        // assign fires @Published every poll cycle even when unchanged,
                        // recreating ContentView and churning its timer/renders for nothing.
                        guard self.isPollSessionCurrent(pollSession) else { return }
                        if self.unreadCounts != contactUnread { self.unreadCounts = contactUnread }
                        if self.groupUnreadCounts != groupUnread { self.groupUnreadCounts = groupUnread }
                    }
                }
                // Event-driven cadence (MessageManager.controlPollDelayMs): a fast
                // jittered follow-up while a group-membership convergence round-trip
                // is in flight (recent control send/receive), else the jittered
                // 60–90 s idle (fix 3b, 2026-09-16 — was 25–45 s; a sweep on a
                // 16-contact phone costs 14–16 s, and the control channel's
                // payloads are durable on the relay and redriven on this sweep).
                // Prompt enough for invites to feel live, no fixed beacon for a
                // traffic observer.
                // Converging = received control traffic OR resolution still
                // pending (unresolved group members) — poll FAST until the roster
                // lands, not just after our own sends.
                // …OR a group conversation is on screen (the fourth arming condition,
                // 2026-10-01 — GroupManager.setGroupConversationForeground): THIS cycle
                // only, never the persistent window, so the peek-before-drain stays on.
                let converging = received || (controller.groupManager?.hasUnresolvedMembers() == true) ||
                    (controller.groupManager?.isGroupConversationForeground() == true)
                // No-transport fallback: the same 60–90 s idle window
                // controlPollDelayMs would return, kept in lockstep with
                // MessageManager.CONTROL_POLL_IDLE_* and with Android's sibling.
                let delayMs: Int64 = controller.messageManager?.controlPollDelayMs(convergingNow: converging)
                    ?? Int64.random(in: 60_000...90_000)
                // Sleep in 1 s slices and let MessageManager.controlPollIdleWaitShouldEnd
                // cut an IDLE wait short the moment the convergence window opens
                // (the Add-contact scan-back screen arming it, or our own control
                // send from the UI). A FAST wait is never cut, and a quiet idle
                // wait runs its full jittered course. Without this a loop already
                // asleep would ignore the arm for up to 90 s (the two-scan pairing
                // "Almost there" wait, 2026-09-27). Android sibling: startControlPoll
                // in RunViewModel.kt.
                var remaining = delayMs
                while remaining > 0 && !Task.isCancelled {
                    let slice = min(Int64(1_000), remaining)
                    try? await Task.sleep(nanoseconds: UInt64(slice) * 1_000_000)
                    remaining -= slice
                    // fastWantedNow: opening a group conversation mid-sleep ends an
                    // IDLE wait within one slice (same mechanism as the scan-back arm).
                    let fastWanted = controller.groupManager?.isGroupConversationForeground() == true
                    if controller.messageManager?.controlPollIdleWaitShouldEnd(
                        chosenDelayMs: delayMs, fastWantedNow: fastWanted
                    ) == true { break }
                }
            }
        }
    }

    /// True while a control-poll sweep started under [token] may still write
    /// session state: its task is not cancelled, the vault is unlocked and no
    /// lock / wipe has bumped [sessionGeneration] since. Main actor only.
    private func isPollSessionCurrent(_ token: UInt64) -> Bool {
        !Task.isCancelled && isUnlocked && token == sessionGeneration
    }

    private func stopRelayCheck() {
        relayCheckTask?.cancel()
        relayCheckTask = nil
        controlPollTask?.cancel()
        controlPollTask = nil
        stopDebugLogLoop()
        isRelayReachable = false
        // Per-transport, exactly like the handshake latch below: the next
        // transport's prime has not run yet, so the reveal gate closes with it.
        unreadPrimeSettled = false
        unreadPrimeCapTask?.cancel(); unreadPrimeCapTask = nil
        // Same scope as the gate itself (C4a): the next transport's reveal is a
        // new one to narrate. The telemetry latch behind it is per PROCESS and
        // deliberately unaffected — see markRevealIfNeeded.
        revealMarked = false
        recomputeContactsReady()
        // Per-transport honest-handshake latch: the next session's transport has
        // proven nothing yet. Reset alongside isRelayReachable, exactly as Android
        // resets _relayHandshakeComplete with _isRelayReachable (restartTor / teardown).
        relayHandshakeComplete = false
        // The hysteresis counters describe THIS session's transport. Carrying them
        // across a lock made the next session start up to `relayUnreachableStreakLimit`
        // misses deep, so its very first miss latched unreachable instantly. Clearing
        // here can only ever LOWER the streak — it never bumps it, and the limit,
        // the counted-miss interval and the NEWNYM/stalled escalations are untouched.
        relayUnreachableStreak = 0
        lastStreakBumpAtMs = 0
        // The next session's first relay answer is a transport-back edge again
        // (its transport has proven nothing yet) — same reset as relayHandshakeComplete.
        transportDownForRedrive = true
        // The ledger itself is scrubbed by controller.lock() (scrubInMemory); the
        // bubble ids it would have flipped belong to views that are gone too.
        redrivenMessageIds.removeAll()
        // The sustained-outage run is per transport too: left in
        // place across a Lever-C lock (process alive, Tor alive), the next
        // session's FIRST miss saw an outage "older" than newnymAfterUnreachableMs
        // and fired NEWNYM at once. Android keeps this state coroutine-local per
        // outage, so it cannot leak; mirror that by clearing it here — the same
        // three fields reconnectRelay() and a successful probe already reset.
        unreachableRunStartedAtMs = 0
        lastSustainedNewnymAtMs = 0
        sustainedNewnymsFired = 0
    }

    // -----------------------------------------------------------------------
    // Emergency wipe
    // -----------------------------------------------------------------------

    /// [deniable] latches the black-screen hold that makes a panic wipe leave no
    /// sign the app was ever configured. Only the deliberate "erase and start
    /// over" path passes false — it needs to land on setup.
    func emergencyWipe(deniable: Bool = true) {
        wipeDiag("AppState.emergencyWipe() invoked")
        LogBuffer.shared.append(level: "W", tag: "AppState", message: "EMERGENCY WIPE triggered")

        // CRYPTO-ERASE FIRST. Destroy the persisted key
        // material as the VERY FIRST act — before Tor teardown and every other
        // I/O step — because it is instantaneous and irreversible: a process death
        // mid-wipe (a crash in Tor's ObjC teardown, the main-thread watchdog
        // 0x8badf00d while this @MainActor method does synchronous recursive
        // deletes, jetsam, forced power-loss) then still leaves every
        // CryptoProvider-encrypted blob (verifier, PIN-wrapped SQLCipher key,
        // Lever-B recovery blob, counters) undecryptable. Previously TorManager
        // teardown + four I/O steps ran on the main actor BEFORE the key was
        // destroyed, so any of those crashes aborted the "irreversible" wipe with
        // all key material intact while the user believed it had happened. Both
        // deleteKey()s are idempotent SecItemDelete calls (controller.emergencyWipe
        // re-issues them harmlessly below).
        KeychainHelper.shared.deleteKey()          // Keychain device key
        SecureEnclaveHelper.shared.deleteKey()     // Lever-B Secure Enclave key
        inactivityCrypto.wipeKey()                 // zero the in-RAM device-key copy too
        // Latch the Tor bootstrap breadcrumb OFF for the rest of the process. Pure
        // in-RAM boolean — no I/O, so it cannot gate or delay the crypto-erase
        // above — and it must be set HERE, before `TorManager.shared.stop(...)`
        // further down, because that teardown would otherwise WRITE a breadcrumb
        // after the erase. "No write after erase" is the rule that keeps a wipe
        // from re-creating residue; clearWipeResidue() below deletes the record
        // itself. Idempotent and never thrown from.
        TorBootstrapBreadcrumbStore.suppressForWipe()
        // The APNs registration used to be dropped
        // here directly, as part of the crypto-erase; that call
        // moved into clearWipeResidue() below instead — this was its
        // ONLY call site besides setPushEnabled(false), so the three
        // launch-time wipes in runLaunchSecurityChecks() (which call
        // clearWipeResidue() but not this method) never reached it and a
        // device that hit those left itself APNs-registered indefinitely.
        // Still local-only / no network I/O, so moving it later in this
        // function (clearWipeResidue() runs after the irreversible key
        // destruction above) does not disturb crypto-erase-first.

        // Phase-3 (docs/RELAY_SPEC.md (push)): best-effort, NON-BLOCKING push-token
        // cleanup. Snapshot refs + fire the DELETE off detached — vault and
        // Tor are still alive at this exact point (right after the
        // irreversible crypto-erase above, before either gets torn down
        // below), but this must NEVER gate the wipe: every step after this
        // one proceeds immediately regardless of whether the network call
        // ever completes. A token this misses is harmless (contentless) and
        // stops mattering once the inbox itself expires server-side. This call
        // (unchanged) already precedes TorManager.shared.stop() below —
        // load-bearing, since stop() tears down the SOCKS listener this
        // DELETE needs.
        if pushEnabled { unregisterCurrentInboxesBestEffort() }

        // Now the slower / crash-prone steps, all AFTER the irreversible erase.
        stopRelayCheck()                           // cancel the pollers before the vault closes
        sessionGeneration &+= 1                    // a sweep still mid-/peek must not write after this
        // Tor teardown + CONFIRMED working-dir wipe. Runs BEFORE controller
        // .emergencyWipe() so that when the latter's own deleteTorData() runs the
        // daemon is already stopped — neither delete races a live tor_main.
        // `discardingState: true` is REQUIRED here: an ordinary stop() now
        // PRESERVES the working dir (guard + consensus reuse across relaunches —
        // see TorManager.preservesStateAcrossLaunches), so only the discarding
        // variant deletes it and arms the atexit backstop for an un-halted
        // tor_main. Android sibling: RunViewModel.performEmergencyWipe →
        // TorManager.stopAndDiscardState().
        TorManager.shared.stop(discardingState: true)
        // Ledger fence after the Tor stop, as in lock(): a send loop still
        // mid-backoff must not re-park plaintext + contactId into the process this
        // deniable path keeps alive (controller.emergencyWipe() below ends the
        // Kotlin-side session too; the second bump is idempotent).
        TransportFailedSends.companion.shared.endSession()
        controller.emergencyWipe()                 // wipeAllTables + UserDefaults sweep (incl. EULA) + DB files + SQLCipher close + (idempotent) deleteKey
        InactivityWipe.clear()
        BlockStore.clear()
        // EULA flag + wipediag.txt breadcrumb — the single residue helper
        // every wipe path calls, so a wiped device stays indistinguishable from
        // never-configured.
        clearWipeResidue()

        // The deniability latch below deliberately keeps THIS process alive on a
        // black screen, so the RAM-residue clears matter even more here than in
        // lock(): anything left populated survives a "deniable" wipe.
        clearInMemoryIdentifierMaps()
        clearPushSessionBookkeeping()
        // Unlike lock() this DOES also drop the cached device token: the wipe
        // already reset the push level to OFF above (clearWipeResidue), so
        // nothing would use it again this session, and a wipe is the strongest
        // "destroy everything" boundary.
        lastPushDeviceToken = nil

        isUnlocked = false
        isConfigured = false
        // "Move to new device": the vault (and with it `mig_frozen`/`mig_handle`)
        // is gone, so this device is no longer the old phone of anything. Clearing
        // both here keeps ContentView from routing a WIPED install to the frozen
        // screen, and drops the new-phone handle — which carries the one-time code
        // — from the RAM of a process the deniable path deliberately keeps alive.
        isMoveFrozen = false
        pendingMoveHandle = nil
        // Latch the in-session-wipe flag so ContentView holds a
        // black screen (deniability) instead of falling through to PinSetupView
        // now that isConfigured is false. Only a relaunch clears it.
        wipedThisSession = deniable
        transport.torState = .disconnected
        // Session is over (Tor stopped above) — retract the connect hint and disarm
        // the watchdog so it can't fire onto a wiped/black screen. A fresh unlock
        // re-arms it from startTorOrDirect().
        transport.clearTorBootstrapStall()
        // A WIPE REVOKES DEBUG-MODE CONSENT IN-PROCESS, not only on disk
        // (2026-09-14). `controller.emergencyWipe()` above already swept
        // the persisted flag with the rest of the Keychain kv service, but the
        // deniable path keeps THIS process alive: without the four lines below
        // LoggingState stayed true, LogBuffer kept filling with post-wipe lines,
        // the uploader's cursor still pointed into the pre-wipe stream, and the
        // Settings toggle still read "on" — a wiped device going on collecting
        // and uploading diagnostics for a consent record that no longer exists.
        // The upload TASKS (periodic loop + the jittered "connect" flush) were
        // cancelled by stopRelayCheck() further up. `#if DEBUG` mirrors
        // RunApp.init / Android's `LoggingState.enabled = BuildConfig.DEBUG`: a
        // debug build enables logging for its own reasons and must keep it.
        // The four revocation lines themselves live in clearWipeResidue() (called
        // above) so the three launch-time wipes get them too.
        // Android parity (WipeRoutine clears both): the connection-log ring is
        // live in RELEASE too, so a deliberately-kept-alive post-wipe process
        // would otherwise hold this session's narration in RAM. No marker line
        // — a wipe leaves nothing, deniably. The Kotlin wipe
        // (IosAppController.emergencyWipe) clears LogBuffer + ConnectionLog too;
        // keep both (defence in depth: neither side relies on the other's clear).
        ConnectionLog.shared.clear()
        LogBuffer.shared.append(level: "W", tag: "AppState", message: "emergency wipe complete — all data destroyed")
    }

    /// Erase the residue that must NOT survive ANY wipe path (the panic
    /// wipe above + every launch-time wipe in runLaunchSecurityChecks), so a wiped
    /// device is indistinguishable from never-configured. Factored into one
    /// helper called by every path so no path is missed. Also the
    /// home for dropping the APNs registration — see the comment
    /// on the first statement below for why it lives here.
    private func clearWipeResidue() {
        // Drop the APNs registration here — the one helper
        // EVERY wipe path already calls (verified: the in-session panic wipe
        // above AND all three launch-time wipes in runLaunchSecurityChecks —
        // reinstall-over-surviving-Keychain, orphaned credentials, the 7-day
        // inactivity self-wipe — each call clearWipeResidue()), so no path
        // can miss it the way the panic-only call site used to (see the
        // comment in emergencyWipe() above). The relay's push is a
        // contentless ALERT, so SpringBoard renders the "Rún / Notification"
        // banner WITHOUT ever launching the app — the in-app
        // pushEnabled/wipedThisSession guard in handleRemotePushWake() never
        // runs for a terminated process, so it cannot suppress that render.
        // A phone that hit its unattended 7-day self-wipe kept showing that
        // banner as peers wrote to it: the deniability failure that matters
        // most here, previously closed only on the
        // panic path. Local-only (no network I/O) — cannot block or reorder
        // crypto-erase-first. The relay-side DELETE
        // (unregisterCurrentInboxesBestEffort) is genuinely impossible to
        // reach from the launch-time wipe paths — no vault is open and Tor
        // hasn't started at that point — so the relay keeps this device's
        // push registration until the inbox itself expires server-side; an
        // known limitation, not something local-only code can close.
        UIApplication.shared.unregisterForRemoteNotifications()
        // External SOCKS proxy setting: a KeyValueStore (Keychain) row, so the
        // controller's kvDeleteAll() sweep has already removed it on every wipe
        // path — this is the explicit Swift-side belt, same posture as the EULA
        // flag below. The RUNNING process keeps its frozen mode (never flips to
        // the embedded Tor mid-process); the next launch starts clean.
        _ = IosExternalProxyStore.shared.clear()
        // A deniably-wiped install must not keep a stale badge either —
        // same "surface nothing" posture as the unregister call above. The
        // relay's aps.badge:1 may have already been applied by SpringBoard
        // before this wipe ran; clear it so the app icon is indistinguishable
        // from a never-configured install.
        setAppIconBadge(false)

        // The EULA-accepted flag is unambiguous proof of prior setup — written
        // only after the user taps "I Agree & Continue" — and is an iOS-only
        // @AppStorage key, NOT part of the shared vault state. The
        // Kotlin sweep (controller.emergencyWipe → IosUserDefaultsKeys.all) now
        // clears it on every path too; clear it here as a belt so the Swift side
        // is self-sufficient if that enumeration is ever refactored.
        let defaults = UserDefaults.standard
        defaults.removeObject(forKey: EulaConsent.storageKey)
        // Phase-3 (docs/RELAY_SPEC.md (push)): reset the Tier-2 opt-in on every wipe path
        // too — a wiped device must come back up at the Tier-0 default, same as
        // fresh install. (The actual server-side token cleanup, when reachable,
        // is the best-effort DELETE in emergencyWipe() above — this is just the
        // local preference residue.)
        defaults.removeObject(forKey: PushPreference.storageKey)
        // The opt-out pending-dereg flag (2026-08-11): a wipe destroys the
        // vault, so a flag surviving it could never be cleared (no vault → no
        // caps → the sweep can never run) and — written only from the
        // Settings opt-out, i.e. an unlocked, configured session — its mere
        // presence is the same proof-of-prior-setup residue class as the two
        // keys above. The wipe paths themselves never arm it
        // (unregisterCurrentInboxesBestEffort's wipe leg stays one-shot).
        // Android sibling: WipeRoutine → SecurePrefs.clear().
        defaults.removeObject(forKey: PushDeregPending.storageKey)
        // The LEGACY store-review counters (ReviewPromptStore): the live
        // counters are vault `_meta`
        // now and die with the vault on this same wipe; these three keys are
        // only ever non-empty on an install not yet migrated (see
        // ReviewPromptStore.recordUnlock), same residue class as the two keys
        // above: presence on a supposedly never-configured install is proof
        // of prior setup. Android sibling: WipeRoutine → SecurePrefs.clear()
        // (same file as push_dereg_pending, swept as a unit there).
        defaults.removeObject(forKey: ReviewPromptStore.firstUnlockAtKey)
        defaults.removeObject(forKey: ReviewPromptStore.unlockCountKey)
        defaults.removeObject(forKey: ReviewPromptStore.promptedKey)
        // removeObject, NOT `pushEnabled =
        // false`. That setter calls persistNotifLevel(false), which WRITES
        // "off" into notif_level — a key every OTHER writer only ever touches
        // from unlocked-vault code paths, so its mere presence on a
        // supposedly never-configured install is proof of prior setup (the
        // same deniability class as the EULA flag and the mtime probe
        // above). Absence reads back as OFF: `pushEnabled`'s getter falls
        // through to `defaults.bool(forKey: PushPreference.storageKey)` when
        // notif_level is unset, and that legacy key is removed on the line
        // above too, so a missing Bool reads false without re-seeding
        // notif_level. Also swept by the Kotlin side — see
        // IosUserDefaultsKeys.NOTIF_LEVEL — as belt-and-suspenders.
        // objectWillChange.send() manually since we're bypassing the
        // `pushEnabled` setter (which normally fires it) to avoid its
        // breadcrumb-planting side effect above.
        objectWillChange.send()
        defaults.removeObject(forKey: NotifLevelPreference.storageKey)
        // The sealed consent proof goes with it. `kvDeleteAll()` already
        // sweeps the whole Keychain KV service on a full wipe; this covers the
        // residue-clearing paths that do not erase, so a proof can never outlive
        // the preference it authorises.
        controller.clearPushConsent()
        // The iOS sibling of Android's matching sweep: the in-app
        // language override (LanguagePickerView → UserDefaults "AppleLanguages")
        // is a user-attributable record — it is written ONLY by the in-app picker,
        // so its presence on a supposedly never-configured install proves both
        // "this app was used" and which language its user chose. Exactly the
        // deniability class as the EULA flag and the notif level above, and it
        // survived every wipe path until now. Removing the key returns the app to
        // "follow system"; it is NOT in IosUserDefaultsKeys.all deliberately (see
        // RunApp.init), so this helper is the only place it can be cleared.
        defaults.removeObject(forKey: "AppleLanguages")
        #if DEBUG
        // …and the e2e harness pin stays wipe-exempt, the same convention Android
        // uses (MainActivity runs TestHooks.handleTestLanguage AFTER the TEST_WIPE
        // hook — see the wipe-resets-app-locale lesson). The launch ARGUMENT
        // `-AppleLanguages (en)` already wins for THIS process (argument domain
        // beats the persistent one), so this only restores the persisted copy the
        // arg-less cold relaunches (Tor recovery, jetsam) depend on. Release
        // builds have no such branch, so the production residue is unconditional.
        // Guard: this ProcessInfo read must stay inside an active #if DEBUG.
        if let langArg = ProcessInfo.processInfo.arguments.first(where: { $0.hasPrefix("--test-language=") }) {
            defaults.set([String(langArg.dropFirst("--test-language=".count))], forKey: "AppleLanguages")
        }
        #endif
        defaults.synchronize()
        // The Tor stuck-bootstrap breadcrumb (Keychain, diagnostic service —
        // TorBootstrapBreadcrumbStore / TorManager.swift). Same residue class as
        // the keys above: it is written ONLY from a Tor start/teardown, which is
        // only reachable from an unlocked, configured session, so its presence on
        // a supposedly never-configured install is proof of prior setup. It also
        // records how recently the app was used, at day granularity.
        //
        // Ordering is deliberate and matches the whole helper: this runs in the
        // POST-crypto-erase, best-effort phase — it never gates or precedes the
        // key destruction. `suppressForWipe()` first so nothing can re-plant the
        // record after this delete (the launch-time wipe paths call
        // clearWipeResidue() without ever having stopped Tor, and a later
        // startTorOrDirect() in the same process would otherwise write one).
        //
        // Belt, not the only strap: KeychainHelper.kvDeleteAll() sweeps the entire
        // diagnostic service, and that call is already made by
        // IosAppController.emergencyWipe() (every production wipe path) and by the
        // DEBUG e2e wipe in RunApp.swift.
        TorBootstrapBreadcrumbStore.suppressForWipe()
        TorBootstrapBreadcrumbStore.erase()
        // The wipediag.txt breadcrumb (a prior DEBUG/beta build may have written
        // it; wipeDiag is a Release no-op). It was once deleted only on the panic path,
        // stranding a timestamped forensic log on the three launch-time wipes —
        // including the unattended 7-day inactivity self-wipe.
        deleteWipeDiagFile()
        // Every wipe path must also sweep delivered/pending notification-
        // center records — see clearDeliveredNotifications().
        clearDeliveredNotifications()
        // Debug mode: a wipe REVOKES the diagnostic-upload
        // consent IN THIS PROCESS on every wipe path, not only the panic one —
        // the launch-time wipes in runLaunchSecurityChecks() kvDeleteAll() the
        // persisted flag but the process lives on (falls through to setup),
        // RunApp.init already set LoggingState from the old flag, and
        // AppState.init cached `debugMode`. `#if DEBUG` mirrors RunApp.init /
        // Android's `LoggingState.enabled = BuildConfig.DEBUG`: a debug build
        // enables logging for its own reasons and must keep it.
        debugMode = false
        #if DEBUG
        LoggingState.shared.enabled = true
        #else
        LoggingState.shared.enabled = false
        #endif
        LogBuffer.shared.clear()
        DebugLogUploader.shared.resetCursor()
    }

    /// User-initiated erase of an unopenable vault (the "Erase and start over"
    /// action on the unlock screen — see PinEntryView.orphanedVault).
    ///
    /// Same destruction as [emergencyWipe] but WITHOUT the deniability latch: a
    /// panic wipe holds a black screen so nothing suggests the app was ever set
    /// up, whereas this user just asked to start over and must land on setup.
    /// Erasing the vault file is also what makes setup safe again — the routing
    /// check and the provision guard both key on that file, so with it gone the
    /// normal first-run flow is no longer destructive.
    func eraseOrphanedVault() {
        LogBuffer.shared.append(level: "W", tag: "AppState",
                                message: "user erased an orphaned vault — starting over")
        emergencyWipe(deniable: false)
    }

    // -----------------------------------------------------------------------
    // Tor lifecycle
    // -----------------------------------------------------------------------

    /// Non-blocking TCP probe of `127.0.0.1:<port>`. Calls `completion(true)`
    /// if the loopback socket completes the connect within `timeoutMs`, else
    /// `completion(false)`.
    ///
    /// Implemented with raw BSD sockets + `inet_pton` on a 127.0.0.1 literal —
    /// deliberately NOT the higher-level Apple networking APIs. The DNS-leak
    /// CI guard (scripts/check-network-api-usage.sh) bans those because they
    /// can resolve hostnames locally; we have no hostname to resolve, so a
    /// plain `socket()` + `connect()` to a literal IP is provably leak-free
    /// and stays out of the allowlist.
    nonisolated private func probeSocksPort(
        _ port: UInt16,
        timeoutMs: Int = 500,
        completion: @Sendable @escaping (Bool) -> Void,
    ) {
        DispatchQueue.global(qos: .userInitiated).async {
            let fd = Darwin.socket(AF_INET, SOCK_STREAM, 0)
            guard fd >= 0 else { completion(false); return }
            defer { Darwin.close(fd) }

            // Non-blocking connect, so we can bound the wait with poll().
            let flags = fcntl(fd, F_GETFL, 0)
            _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)

            // 127.0.0.1 literal — NO DNS, no allowlist bump needed.
            var loopback = in_addr()
            guard inet_pton(AF_INET, "127.0.0.1", &loopback) == 1 else {
                completion(false); return
            }
            var addr = sockaddr_in(
                sin_len: UInt8(MemoryLayout<sockaddr_in>.size),
                sin_family: sa_family_t(AF_INET),
                sin_port: in_port_t(port).bigEndian,
                sin_addr: loopback,
                sin_zero: (0, 0, 0, 0, 0, 0, 0, 0)
            )

            let connRes = withUnsafePointer(to: &addr) { ptr -> Int32 in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    Darwin.connect(fd, sa, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
            // TCP connect alone can't tell Tor from a local squatter that just
            // accepts the port — verify the listener actually speaks SOCKS5.
            if connRes == 0 { completion(Socks5Greeting.succeeds(fd: fd, timeoutMs: timeoutMs)); return }
            // EINPROGRESS = connect is in flight, wait via poll(); anything
            // else (ECONNREFUSED, ENETDOWN, EHOSTUNREACH, …) = port is gone.
            guard errno == EINPROGRESS else { completion(false); return }

            var pfd = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
            let pollRes = withUnsafeMutablePointer(to: &pfd) { ptr in
                Darwin.poll(ptr, 1, Int32(timeoutMs))
            }
            guard pollRes > 0 else { completion(false); return }

            var sockErr: Int32 = 0
            var len = socklen_t(MemoryLayout<Int32>.size)
            let optRes = getsockopt(fd, SOL_SOCKET, SO_ERROR, &sockErr, &len)
            guard optRes == 0 && sockErr == 0 else { completion(false); return }
            // TCP is up — now the SOCKS5 handshake proves it's really Tor.
            completion(Socks5Greeting.succeeds(fd: fd, timeoutMs: timeoutMs))
        }
    }

    // -----------------------------------------------------------------------
    // Bounded Tor keep-alive after backgrounding (2026-10-23)
    //
    // The vault still locks and wipes its key material on EVERY `.background`,
    // exactly as before (ContentView). What moved is the Tor teardown + the
    // process recycle: a healthy Tor is kept running for the background-task
    // budget iOS grants (re-read when the task starts, minus a 3 s margin,
    // clamped to [5 s, 170 s] — BackgroundTorKeepAlive.windowSeconds), and only
    // then — if the app is STILL in the background at that instant — stopped
    // and the process exit(0)ed while invisible, as it used to be at once.
    // A return inside the window reuses the running Tor (no bootstrap; the
    // in-RAM onion descriptor and circuits survive).
    //
    // Why bounded and not "until iOS suspends us": exit(0) also clears the
    // freed-heap residue of the unlocked session (forensic threat model). The
    // bound is ABSOLUTE, not per stretch: a process is kept
    // alive INVISIBLE only until RESIDUE_CAP_SEC (170 s, wall clock) after the
    // lock() that ended its last UNLOCKED session, however many warm returns and
    // re-backgrounds happen in between — each window is min(budget window, cap
    // left), and with ≤ 5 s left the immediate stop + exit(0) is taken. (Time
    // spent visible on the PIN screen after a warm return is the user's, not a
    // background stretch; the cap keeps running through it. A
    // process that never held an unlocked session has no such residue and is
    // bounded per stretch only.) And a suspended process would need a
    // resume-health story for Tor that we do not have (a suspended tor_main
    // thread is the dead-Tor wedge relaunchRequired exists for).
    //
    // THE EXIT RACE. Three deadline sources — the budget timer, the background
    // task's expiration handler (the hard backstop), and the device-lock
    // notification — and the foreground transition all run on the MAIN actor,
    // and every one of them decides against the single keeper
    // (`torKeepAlive`): a deadline carries the token of the arm it belongs to,
    // `foreground()` invalidates every outstanding token, and a deadline is
    // honoured only while `applicationState == .background` at that moment
    // (`.inactive` = the user is coming back). So a foregrounded process never
    // exits — the 2026-10-23 "vanishes every other launch" report was exactly
    // an exit(0) that landed after the user had re-tapped the icon.
    // TorManager.stop() itself BLOCKS the main thread for up to 2 s, so the exit
    // is decided one main-runloop turn after it (finishTorKeepAliveTeardown):
    // a foreground return queued behind stop() reaches the keeper first and
    // vetoes the exit. Such a process does NOT exit; Tor is
    // gone, so relaunchRequired shows the close-and-reopen hint and the next
    // background recycles at once.
    //
    // Exceptions that keep the old immediate exit (BackgroundTorKeepAlive
    // .shouldKeepAlive): relaunchRequired, external SOCKS proxy mode, any wipe,
    // a Tor that is not Connected, an UNLOCKED session that never reached the
    // relay (leave-and-return is the user's restart remedy), a device lock
    // under way, and MAXIMUM. A device lock also ends a running window at once
    // (NSFileProtectionComplete on the Tor dir — see
    // TorManager.applyDataProtection — and the seized-locked-phone residue
    // argument). Gated on `.background` only — never `.inactive` (the
    // Lever-B lesson). Android sibling: TorKeepAlive.kt (a parked child process,
    // 120 s); the panel reuse line is word for word the same.
    // -----------------------------------------------------------------------

    /// Why a keep-alive window ended — log-only, fixed words.
    private enum TorKeepAliveEnd: String {
        case window = "window over"
        case expired = "background task expiring"
        case deviceLocked = "device locking"
    }

    /// How many times a "not a budget yet" read is retried (1 s apart) before
    /// the window falls back to the cap (the expiration handler still bounds it).
    private static let torKeepAliveBudgetRereads = 3

    /// True while Tor is being kept across a background. `lock()` reads it so a
    /// background lock does not stop the kept daemon.
    var isKeepingTorAlive: Bool { torKeepAlive.isKeeping }

    /// ContentView's `.background` branch, FIRST — before the vault locks: the
    /// tier read needs the device key the lock wipes, and the wedged test reads
    /// this session's relay evidence. Returns true when Tor is now being KEPT
    /// (the caller must then neither stop Tor nor exit); false = today's
    /// immediate teardown applies.
    func armTorKeepAliveOnBackground() -> Bool {
        let tor = TorManager.shared
        var torConnected = false
        if case .connected = tor.state, tor.socksPort > 0 { torConnected = true }
        let isWipe = wipedThisSession
        let relaunch = tor.relaunchRequired
        let external = ExternalProxyMode.shared.isExternalThisProcess
        // An unlocked session whose transport never reached the relay over this
        // Tor must not hand it on (Android: notKnownWedged). Pre-unlock passes.
        let notKnownWedged = !isUnlocked || relayAnsweredThisSession
            || (controller.messageManager?.hasCompletedRelayRoundTrip() ?? false)
        // A power-button lock can post will-become-unavailable before `.background`.
        let deviceLocking = deviceLockPending
        // ABSOLUTE residue cap: measured from the lock() that ended the last
        // UNLOCKED session — which is THIS backgrounding's lock when the vault is
        // open right now (the lock runs just after this gate) — never per stretch.
        let now = ProcessInfo.processInfo.systemUptime
        let residueLeft = BackgroundTorKeepAlive.companion.residueLeftSeconds(
            sinceLastUnlockedLockSec: lastUnlockedSessionLockUptime.map { KotlinDouble(value: now - $0) },
            unlockedNow: isUnlocked
        )?.doubleValue
        // DEBUG measurement mode (`--test-tor-keepalive-unbounded`) bypasses the
        // residue cap and the tier gate below — the test iPhones are passcodeless
        // and therefore forced to MAXIMUM — and nothing else.
        let unbounded = torKeepAliveUnbounded
        let residueAllows = unbounded || BackgroundTorKeepAlive.companion.residueAllowsKeepAlive(
            residueLeftSec: residueLeft.map { KotlinDouble(value: $0) }
        )
        // Short-circuit before the device-key read when the answer is already no.
        guard !isWipe, !relaunch, !external, torConnected, notKnownWedged, !deviceLocking, residueAllows else {
            LogBuffer.shared.append(level: "D", tag: "TorKeepAlive",
                message: "refused (wipe=\(isWipe), relaunch=\(relaunch), external=\(external), connected=\(torConnected), wedged=\(!notKnownWedged), locking=\(deviceLocking), residueSpent=\(!residueAllows)) — immediate teardown")
            return false
        }
        let tierAllowed = unbounded || controller.torKeepAliveTierAllows(sessionTierAllowed: sessionTierAllowsKeepAlive)
        guard BackgroundTorKeepAlive.companion.shouldKeepAlive(
            isWipe: isWipe, relaunchRequired: relaunch, externalProxy: external,
            torConnected: torConnected, notKnownWedged: notKnownWedged,
            deviceLocking: deviceLocking, residueAllows: residueAllows, tierAllowed: tierAllowed
        ) else {
            LogBuffer.shared.append(level: "D", tag: "TorKeepAlive", message: "refused by the tier gate — immediate teardown")
            return false
        }
        // A background → inactive → background bounce that never reached
        // `.active` re-arms: the old task, timer and observer go first.
        clearTorKeepAliveTimers()
        endTorKeepAliveBackgroundTask()
        let token = torKeepAlive.arm()
        guard token != BackgroundTorKeepAlive.companion.NO_TOKEN else { return false }
        // The HARD BACKSTOP. Called synchronously on the main thread shortly
        // before the budget runs out; it must either exit or end the task, or iOS
        // terminates the process for overrunning it.
        let task = UIApplication.shared.beginBackgroundTask(withName: "tor-keep-alive") { [weak self] in
            MainActor.assumeIsolated {
                self?.torKeepAliveDeadline(token: token, cause: .expired)
            }
        }
        guard task != .invalid else {
            torKeepAlive.disarm()
            LogBuffer.shared.append(level: "W", tag: "TorKeepAlive", message: "no background task granted — immediate teardown")
            return false
        }
        torKeepAliveTask = task
        torKeepAliveToken = token
        torKeepAliveBackgroundedAtUptime = now
        // Fixed NOW, so the budget re-reads below cannot stretch it.
        torKeepAliveResidueDeadlineUptime = residueLeft.map { now + $0 }
        if unbounded {
            // Measurement mode: no window deadline at all. The expiration handler
            // ends the task (see torKeepAliveDeadline) and the process suspends
            // with Tor kept; only a device lock still tears down.
            let line = "tor keep-alive window unbounded (test mode)"
            torKeepAliveWindowLine = line
            LogBuffer.shared.append(level: "W", tag: "TorKeepAlive", message: line)
            ConnectionLog.shared.append(kind: ConnectionLog.Kind.system, text: line)
            return true
        }
        scheduleTorKeepAliveDeadline(token: token, reread: 0)
        return true
    }

    /// Installs the two PERMANENT device-lock observers (once, from init). A
    /// device lock ends a running keep-alive at once — the Tor dir is
    /// NSFileProtectionComplete and its Class-A keys go ~10 s after
    /// will-become-unavailable — and, because that notification can precede the
    /// scene's `.background` on a power-button lock, also makes the next
    /// `armTorKeepAliveOnBackground` refuse (`deviceLockPending`).
    private func observeDeviceLockForTorKeepAlive() {
        guard torKeepAliveDeviceLockObservers.isEmpty else { return }
        let center = NotificationCenter.default
        torKeepAliveDeviceLockObservers.append(center.addObserver(
            forName: UIApplication.protectedDataWillBecomeUnavailableNotification,
            object: nil, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self else { return }
                self.deviceLockPending = true
                if self.torKeepAlive.isKeeping {
                    self.torKeepAliveDeadline(token: self.torKeepAliveToken, cause: .deviceLocked)
                }
            }
        })
        torKeepAliveDeviceLockObservers.append(center.addObserver(
            forName: UIApplication.protectedDataDidBecomeAvailableNotification,
            object: nil, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated {
                self?.deviceLockPending = false
            }
        })
    }

    /// Reads the budget the OS granted and schedules the end of the window at
    /// budget − margin (clamped). UIKit can still report "suitably large" for a
    /// moment after the transition, so an unknown read is retried 1 s later, up
    /// to [torKeepAliveBudgetRereads] times, then falls back to the cap — the
    /// expiration handler still ends it at the OS's real limit.
    private func scheduleTorKeepAliveDeadline(token: Int64, reread: Int) {
        let remaining = UIApplication.shared.backgroundTimeRemaining
        let known = BackgroundTorKeepAlive.companion.windowSeconds(backgroundTimeRemainingSec: remaining)?.doubleValue
        if known == nil, reread < AppState.torKeepAliveBudgetRereads {
            let work = DispatchWorkItem { [weak self] in
                MainActor.assumeIsolated {
                    guard let self, self.torKeepAlive.isKeeping else { return }
                    self.scheduleTorKeepAliveDeadline(token: token, reread: reread + 1)
                }
            }
            torKeepAliveDeadlineWork = work
            DispatchQueue.main.asyncAfter(deadline: .now() + 1, execute: work)
            return
        }
        // min(budget window, absolute residue cap left NOW).
        let residueLeftNow = torKeepAliveResidueDeadlineUptime.map {
            KotlinDouble(value: $0 - ProcessInfo.processInfo.systemUptime)
        }
        let window = BackgroundTorKeepAlive.companion.composeWindow(
            budgetWindowSec: known ?? BackgroundTorKeepAlive.companion.MAX_WINDOW_SEC,
            residueLeftNowSec: residueLeftNow
        )
        let line = BackgroundTorKeepAlive.companion.windowPhrase(windowSec: window, budgetSec: known == nil ? nil : KotlinDouble(value: remaining))
        torKeepAliveWindowLine = line
        // Numbers only (window + OS budget). Uncoded: never on the wire.
        LogBuffer.shared.append(level: "D", tag: "TorKeepAlive", message: line)
        ConnectionLog.shared.append(kind: ConnectionLog.Kind.system, text: line)
        let work = DispatchWorkItem { [weak self] in
            MainActor.assumeIsolated {
                self?.torKeepAliveDeadline(token: token, cause: .window)
            }
        }
        torKeepAliveDeadlineWork = work
        DispatchQueue.main.asyncAfter(deadline: .now() + window, execute: work)
    }

    /// Any deadline source. Tears Tor down and exits ONLY when the keeper says so
    /// (current token, still keeping, app in the background right now).
    private func torKeepAliveDeadline(token: Int64, cause: TorKeepAliveEnd) {
        let inBackground = UIApplication.shared.applicationState == .background
        // LEAD hardening: a vault that came open in this background process (an
        // Argon2 unlock finishing after the user left, with the SwiftUI re-lock
        // delivered late) is locked FIRST — before any keep-alive decision, so no
        // path below can exit or keep running with it open. Background-gated, so
        // a stale deadline firing while the user is unlocked in the foreground
        // can never lock them out.
        if inBackground { relockIfUnlockedInBackground(site: "keep-alive deadline") }
        // DEBUG measurement mode: only a device lock tears down. The expiration
        // handler still ends its task (or iOS kills the process for overrunning
        // it) — the process then SUSPENDS with Tor kept, which is the thing
        // tests/adhoc/tor-suspend-survival.spec.ts measures.
        if torKeepAliveUnbounded && cause != .deviceLocked {
            if cause == .expired { endTorKeepAliveBackgroundTask() }
            LogBuffer.shared.append(level: "W", tag: "TorKeepAlive", message: "unbounded test mode — not tearing down (\(cause.rawValue)), process may suspend")
            return
        }
        guard torKeepAlive.deadline(deadlineToken: token, stillInBackground: inBackground) else {
            // Refused: stale token, or the user is coming back (`.inactive`) and
            // the `.active` handler will reuse Tor. The expiration handler must
            // still end its task, or iOS kills the process for overrunning it.
            if cause == .expired { endTorKeepAliveBackgroundTask() }
            return
        }
        clearTorKeepAliveTimers()
        LogBuffer.shared.append(level: "W", tag: "TorKeepAlive",
            message: "keep-alive ended (\(cause.rawValue)) — stopping Tor and recycling the process while invisible")
        // The same ordinary, state-PRESERVING teardown the old `.background`
        // path ran (HALT + bounded guard-state flush; latches relaunchRequired).
        // It BLOCKS the main thread for up to 2 s, so nothing that happened
        // meanwhile (a foreground return) has been delivered yet when it returns.
        TorManager.shared.stop()
        // Yield one main-runloop turn so a foreground transition queued
        // behind the blocking stop() is processed (it reaches the keeper through
        // ContentView's `.active` → endTorKeepAliveOnForeground → foreground(), which
        // vetoes the exit), THEN decide. The background task is still held, so
        // the process is not suspended in between.
        hopToMain { [weak self] in
            self?.finishTorKeepAliveTeardown()
        }
    }

    /// The exit itself, one runloop turn after the blocking stop(). Exits ONLY
    /// when the keeper still allows it (no `.active` arrived since the teardown
    /// began) AND the app is in the background at this moment. Otherwise Tor is
    /// gone but the process stays: relaunchRequired drives the honest
    /// close-and-reopen hint and the next `.background` recycles at once.
    private func finishTorKeepAliveTeardown() {
        let inBackground = UIApplication.shared.applicationState == .background
        guard torKeepAlive.exitStillAllowed(stillInBackground: inBackground) else {
            LogBuffer.shared.append(level: "W", tag: "TorKeepAlive",
                message: "app came forward during the Tor teardown — not exiting")
            endTorKeepAliveBackgroundTask()
            return
        }
        exit(0)
    }

    /// ContentView's `.active` branch. A WARM RETURN when Tor was being kept:
    /// end the window (timer, observer, background task) and adopt the running
    /// Tor as this new session's. A `.inactive` → `.active` bounce (Face ID,
    /// Control Center) kept nothing and does nothing.
    func endTorKeepAliveOnForeground() {
        guard torKeepAlive.foreground() else { return }
        // LEAD hardening: a kept process was LOCKED at `.background`; if it is
        // unlocked now, an unlock completed while it was invisible (the
        // late-delivered SwiftUI re-lock race). Lock before anything else so the
        // user meets the PIN screen, exactly as after any background. Only on a
        // WARM RETURN (foreground() true) — a Face ID `.inactive` → `.active`
        // bounce must never lock a session the user just opened (Lever B).
        if isUnlocked {
            LogBuffer.shared.append(level: "W", tag: "TorKeepAlive", message: "vault found unlocked on a warm return — locking")
            lock()
        }
        clearTorKeepAliveTimers()
        endTorKeepAliveBackgroundTask()
        adoptKeptTor()
        #if DEBUG
        // AFTER the adoption (which clears the panel ring), so the probe lines land
        // in the new session's ring next to TOR_REUSED.
        if torKeepAliveUnbounded { runTorSuspendProbe() }
        #endif
    }

    #if DEBUG
    /// e2e-only suspend-survival probe (`--test-tor-keepalive-unbounded`). On a
    /// warm return, judges the kept Tor WITHOUT changing anything: how long the
    /// process was backgrounded, whether tor_main's thread still runs, whether the
    /// AUTHENTICATED control socket answers GETINFO for the published SOCKS port
    /// (and how fast), and whether the SOCKS listener still greets. The first
    /// relay answer after the return is added later (noteTorSuspendProbeAnswer).
    /// A dead Tor is NOT handled here: the unlock's own control confirmation
    /// (startTorOrDirect) latches relaunchRequired exactly as for any user.
    /// Panel lines are fixed phrases + numbers (uncoded — never on the wire);
    /// the same values go to `torSuspendProbeSummary` for the spec.
    private func runTorSuspendProbe() {
        let tor = TorManager.shared
        let returnedAt = ProcessInfo.processInfo.systemUptime
        let bgSec = Int((returnedAt - (torKeepAliveBackgroundedAtUptime ?? returnedAt)).rounded())
        torSuspendProbeSeq += 1
        let seq = torSuspendProbeSeq
        let threadAlive = tor.threadAliveForProbe
        torSuspendProbe = TorSuspendProbe(seq: seq, backgroundedSec: bgSec, threadAlive: threadAlive,
                                          returnUptime: returnedAt)
        publishTorSuspendProbe()
        torSuspendProbeLine("tor suspend probe: backgrounded for \(bgSec) s")
        torSuspendProbeLine(threadAlive ? "tor suspend probe: tor thread alive" : "tor suspend probe: tor thread not running")
        let port = tor.socksPort
        let ctlStart = ProcessInfo.processInfo.systemUptime
        tor.confirmSocksPortViaControl { [weak self] confirmedPort in
            guard let self, var probe = self.torSuspendProbe, probe.seq == seq else { return }
            let ms = Int(((ProcessInfo.processInfo.systemUptime - ctlStart) * 1000).rounded())
            let ok = port > 0 && confirmedPort == port
            probe.controlOk = ok
            probe.controlMs = ms
            self.torSuspendProbe = probe
            self.publishTorSuspendProbe()
            self.torSuspendProbeLine(ok ? "tor suspend probe: control GETINFO ok in \(ms) ms"
                                        : "tor suspend probe: control GETINFO failed after \(ms) ms")
            guard port > 0 else {
                self.noteTorSuspendProbeSocks(seq: seq, ok: false)
                return
            }
            self.probeSocksPort(port) { alive in
                Task { @MainActor [weak self] in
                    self?.noteTorSuspendProbeSocks(seq: seq, ok: alive)
                }
            }
        }
    }

    private func noteTorSuspendProbeSocks(seq: Int, ok: Bool) {
        guard var probe = torSuspendProbe, probe.seq == seq else { return }
        probe.socksOk = ok
        torSuspendProbe = probe
        publishTorSuspendProbe()
        torSuspendProbeLine(ok ? "tor suspend probe: SOCKS listener ok" : "tor suspend probe: SOCKS listener failed")
    }

    /// The first relay answer after a probed warm return: seconds since the
    /// return and since this session's unlock anchor (the spec's "secs to first
    /// relay answer"). Once per probe.
    private func noteTorSuspendProbeAnswer() {
        guard var probe = torSuspendProbe, probe.answerSec == nil else { return }
        let now = ProcessInfo.processInfo.systemUptime
        probe.answerSec = Int((now - probe.returnUptime).rounded())
        probe.answerAfterUnlockSec = connectStartUptime.map { Int((now - $0).rounded()) }
        torSuspendProbe = probe
        publishTorSuspendProbe()
        torSuspendProbeLine("tor suspend probe: first relay answer \(probe.answerSec ?? -1) s after return, \(probe.answerAfterUnlockSec ?? -1) s after unlock")
    }

    private func publishTorSuspendProbe() {
        torSuspendProbeSummary = torSuspendProbe?.summary(relaunchRequired: TorManager.shared.relaunchRequired)
    }

    private func torSuspendProbeLine(_ text: String) {
        LogBuffer.shared.append(level: "I", tag: "TorKeepAlive", message: text)
        ConnectionLog.shared.append(kind: ConnectionLog.Kind.tor, text: text)
    }
    #endif

    /// An UNLOCKED vault in a
    /// BACKGROUND process is locked at once. Called at the end of every unlock
    /// path (an Argon2 unlock can finish after the user left — and the bounded
    /// keep-alive means that process may now survive the background) and at the
    /// keep-alive deadline. `.background` only — never `.inactive`: Lever B's
    /// Face ID prompt drives the scene to `.inactive` WHILE the unlock finishes.
    /// lock() here does not stop a KEPT Tor (it checks the keeper).
    @discardableResult
    private func relockIfUnlockedInBackground(site: String) -> Bool {
        guard isUnlocked, UIApplication.shared.applicationState == .background else { return false }
        LogBuffer.shared.append(level: "W", tag: "AppState", message: "vault unlocked while in background (\(site)) — locking")
        lock()
        return true
    }

    /// The reuse half. The session teardown already ran at `.background` (vault
    /// closed, keys wiped, transport scrubbed); this only makes the kept daemon
    /// THIS session's Tor. It starts NOTHING: `speculativeTorStarted` is already
    /// latched for the process and `TorManager.start()` refuses on `started`, so
    /// no second tor_main can ever be attempted; the unlock reaches the live
    /// SOCKS port through startTorOrDirect's existing "Tor already up" branch
    /// (control-confirmed, then wired), whose first health probe is immediate —
    /// stale-after-suspension circuits are then the ordinary NEWNYM rungs' job.
    private func adoptKeptTor() {
        let tor = TorManager.shared
        guard !tor.relaunchRequired, case .connected = tor.state, tor.socksPort > 0 else {
            // Died while kept (or latched): nothing to adopt. The relaunch latch /
            // health loop decide from here, exactly as for any dead Tor.
            LogBuffer.shared.append(level: "W", tag: "TorKeepAlive", message: "kept Tor is no longer connected on return — not reused")
            return
        }
        // The ring holds the previous session's lock marker (and, pre-unlock, its
        // whole connect narration): with no TOR_START to follow, the coded reuse
        // line is this session's timeline ANCHOR — Android parity
        // (RunViewModel.adoptWarmTorFromPreviousSession).
        ConnectionLog.shared.clear()
        ConnectionLog.shared.append(
            kind: ConnectionLog.Kind.tor,
            text: BackgroundTorKeepAlive.companion.PHRASE_REUSED,
            code: ConnectionLog.Code.torReused
        )
        if let line = torKeepAliveWindowLine {
            ConnectionLog.shared.append(kind: ConnectionLog.Kind.system, text: line)
        }
        torKeepAliveWindowLine = nil
        LogBuffer.shared.append(level: "D", tag: "TorKeepAlive", message: "adopted the Tor kept warm across the background — no bootstrap")
        beginWarmTorSession()
        // Descriptor race: a DECIDED race keeps its cached descriptor (no
        // refetch); only an undecided one is re-run. The DescriptorHedge is not
        // touched (it is driven by Tor's own HS_DESC events, as on every connect).
        tor.rerunUndecidedRelayAddressRace()
        // Pre-unlock warm-up (lever 1) for THIS session: one bare GET / over the
        // kept circuits — the earliest liveness check of a possibly-stale circuit,
        // run while the user types. No HSFETCH (the descriptor is cached).
        rendezvousWarmupFired = false
        warmRendezvousIfPreUnlock()
    }

    /// Everything a FRESH PROCESS would have started fresh, for the new session
    /// in a surviving one: the connect anchor + report latch (one telemetry
    /// report per session), `tor` = 0 (Tor was up before the anchor), no `boot`
    /// (no Tor process started), a fresh reveal latch, and the per-session
    /// NEWNYM budgets / relay-answered latch / once-per-session nudges. The
    /// per-PROCESS Tor ledgers (HsCircuitWatchdog, HsDirLedger, the descriptor
    /// race, the warm-NEWNYM hourly cap, the DescriptorHedge budget) carry over
    /// with the daemon they describe (iOS only for the DescriptorHedge budget:
    /// Android's adopted Tor drives a fresh per-session hedge — see review P7).
    private func beginWarmTorSession() {
        connectStartUptime = nil
        connectTelemetrySent = false
        torConnectedUptime = ProcessInfo.processInfo.systemUptime
        warmTorSession = true
        ConnectTelemetry.shared.startNewRevealSession()
        relayAnsweredThisSession = false
        controller.resetEarlyNewnyms()
        updateNudgeEvaluated = false
        reviewPromptEvaluated = false
        sessionTierAllowsKeepAlive = false
        if relayConnectPhase == .stalled { relayConnectPhase = .connecting }
    }

    /// Cancels the scheduled window end (or budget re-read). The device-lock
    /// observers are permanent; they consult the keeper, which `foreground()` /
    /// `deadline()` already moved off KEEPING.
    private func clearTorKeepAliveTimers() {
        torKeepAliveDeadlineWork?.cancel()
        torKeepAliveDeadlineWork = nil
    }

    private func endTorKeepAliveBackgroundTask() {
        guard torKeepAliveTask != .invalid else { return }
        UIApplication.shared.endBackgroundTask(torKeepAliveTask)
        torKeepAliveTask = .invalid
    }

    #if DEBUG
    /// One warm return's suspend-survival measurement (DEBUG measurement mode).
    /// Numbers and booleans only — nothing here can carry an identifier.
    private struct TorSuspendProbe {
        let seq: Int
        let backgroundedSec: Int
        let threadAlive: Bool
        let returnUptime: TimeInterval
        var controlOk: Bool?
        var controlMs: Int?
        var socksOk: Bool?
        var answerSec: Int?
        var answerAfterUnlockSec: Int?

        /// `v=1;seq=N;bg=N;thread=0|1;ctl=0|1|-;ctlMs=N|-;socks=0|1|-;answer=N|-;answerAfterUnlock=N|-;relaunch=0|1`
        /// — fixed keys, fixed order; parsed by tests/adhoc/tor-suspend-survival.spec.ts.
        func summary(relaunchRequired: Bool) -> String {
            func b(_ v: Bool?) -> String { v.map { $0 ? "1" : "0" } ?? "-" }
            func n(_ v: Int?) -> String { v.map(String.init) ?? "-" }
            return "v=1;seq=\(seq);bg=\(backgroundedSec);thread=\(threadAlive ? 1 : 0);ctl=\(b(controlOk));ctlMs=\(n(controlMs))"
                + ";socks=\(b(socksOk));answer=\(n(answerSec));answerAfterUnlock=\(n(answerAfterUnlockSec))"
                + ";relaunch=\(relaunchRequired ? 1 : 0)"
        }
    }
    #endif

    /// The UNLOCK-time connect path. Called from `unlock()` and
    /// `recoverWithCode()` only.
    ///
    /// Since the speculative launch-time start (lever 2) Tor is usually ALREADY
    /// running or bootstrapping when this runs, and that is a no-op by
    /// construction: `TorManager.start()` refuses a second call on its `started`
    /// guard (and, if Tor already ran and stopped, on `threadEverCreated` — which
    /// latches `relaunchRequired`, unchanged). Everything else here is the part
    /// that genuinely needs the just-opened vault: re-arming the watchdogs (now
    /// re-anchored onto the inherited bootstrap) and authenticating an
    /// already-published SOCKS port before the transport trusts it.
    private func startTorOrDirect() {
        // Connect-time telemetry anchor (ConnectTelemetry.kt). Set-once, so a
        // lock → re-unlock in the same process keeps measuring the user's ONE
        // wait rather than restarting the clock. Deliberately NOT moved to the
        // speculative start: that bootstrap overlaps credential entry, and
        // counting a slow typist's thinking time would make the number
        // meaningless. The bootstrap is not lost from the picture — it is
        // reported SEPARATELY as `tor` (see torConnectedUptime), which after
        // lever 2 is normally 0 because Tor connected before this anchor.
        if connectStartUptime == nil {
            connectStartUptime = ProcessInfo.processInfo.systemUptime
        }
        // Bounded Tor keep-alive: the tier decision from this AUTHENTICATED,
        // post-unlock read — the fallback when the live read at `.background`
        // races the device key (BackgroundTorKeepAlive.tierAllows).
        sessionTierAllowsKeepAlive = controller.torKeepAliveTierAllowsAuthenticated()
        let relayUrl = RelayConfig.shared.BASE_URL
        let torRequired = RelayConfig.shared.isTorRequired
        // Log a boolean, not the .onion prefix (kept out of git;
        // a prefix in the DEBUG log buffer is copyable into a bug report).
        LogBuffer.shared.append(level: "D", tag: "AppState", message: "startTorOrDirect: relayConfigured=\(!relayUrl.isEmpty), torRequired=\(torRequired)")
        // EXTERNAL SOCKS PROXY MODE — decided BEFORE either branch below, so it
        // also overrides the debug direct-HTTP branch (no direct fallback, ever).
        // Returns true for external / invalid / unreadable: no embedded Tor, no
        // hooks, no watchdog, no direct client in any of them.
        if connectViaExternalProxyIfConfigured() { return }
        if torRequired {
            LogBuffer.shared.append(level: "D", tag: "AppState", message: "starting Tor...")
            installDescriptorHedge()
            installNewCircuitHook()
            installHsCircuitGate()
            installBootstrapStallKick()
            TorManager.shared.start()
            // TIER 2: start() has just read the cross-launch breadcrumb and
            // decided whether this install has a history of failed bootstraps.
            // Read it back synchronously here rather than sinking $rebootHintWarranted
            // — start() sets it before returning, and a refused start (Tor already
            // ran in this process) correctly leaves the value this process computed
            // on its first pass. Copy only; nothing is gated on it.
            transport.refreshRebootHint()
            transport.armTorBootstrapWatchdog()
            // If Tor is already bootstrapped (lock + re-unlock within the same
            // process — a foreground re-unlock, or a WARM RETURN inside the
            // bounded keep-alive window, where start() above just refused on
            // `started` and the kept daemon is this session's Tor), re-wire the
            // MessageManager here so the CACHED port gets
            // AUTHENTICATED before it is trusted — the portCancellable sink
            // wires from a control-fresh port and has no way to tell a stale one
            // apart. The sink is now CombineLatest(port, isUnlocked), so it is no
            // longer the only path back: if this branch does nothing (port still 0
            // — Tor mid-bootstrap) the sink wires as soon as the port lands, and if
            // it wires nothing because the manager creation raced a lock, the
            // health loop's current-value self-heal picks it up on the next tick.
            let port = TorManager.shared.socksPort
            if port > 0 {
                // Don't trust the cached port blindly: iOS can kill the embedded
                // Tor thread silently (e.g. after a long background suspend), in
                // which case `socksPort` stays > 0 from a stale @Published value
                // and every relay-transport connect to 127.0.0.1:<port> gets POSIX 61
                // (Connection refused). Probe before re-wiring; on refused,
                // force a clean stop()/start() cycle and let the port-sink in
                // init() rewire the MessageManager when the new bootstrap
                // publishes the fresh port.
                // Authenticate liveness over Tor's control socket
                // FIRST. A local squatter can answer a SOCKS5 greeting on a freed
                // `auto` port, but cannot impersonate the cookie-authenticated
                // control socket — so if the control socket doesn't confirm THIS
                // exact port, treat Tor as gone (also covers a dead Tor thread
                // drops the control connection). Only on a control-confirmed port do
                // we additionally SOCKS5-probe (belt-and-suspenders) and re-wire.
                // The flag holds the current-value wiring paths off until this
                // confirmation resolves, so they can never wire an unauthenticated
                // cached port ahead of it. confirmSocksPortViaControl always calls
                // back (its own timeout completes with nil), so it always clears.
                cachedPortAuthenticationInFlight = true
                TorManager.shared.confirmSocksPortViaControl { [weak self] confirmedPort in
                    guard let self = self else { return }
                    self.cachedPortAuthenticationInFlight = false
                    guard confirmedPort == UInt16(port) else {
                        // Control socket says Tor is gone or on a different port.
                        // Tor's tor_main runs ONCE per process and CANNOT be
                        // re-initialized in-process (a second TORThread aborts with
                        // an NSAssertion — the `Tor 0x… + 77052` production crash),
                        // so surface disconnected and let the user relaunch.
                        LogBuffer.shared.append(level: "W", tag: "AppState",
                            message: "control socket did not confirm socksPort=\(port) (got \(confirmedPort.map(String.init) ?? "nil")) — Tor thread died; relaunch required")
                        // Latch the process-dead state (drives the honest UI hint
                        // + the on-background process recycle); the $state sink
                        // mirrors .disconnected into torState.
                        TorManager.shared.markThreadDead()
                        return
                    }
                    self.probeSocksPort(port) { alive in
                        Task { @MainActor [weak self] in
                            guard let self = self else { return }
                            if alive {
                                LogBuffer.shared.append(level: "D", tag: "AppState",
                                    message: "Tor already up (port=\(port), control-confirmed) — re-wiring MessageManager")
                            } else {
                                // The AUTHENTICATED control socket already confirmed this
                                // exact port is Tor's own listener, so the loopback-port
                                // squatter case is covered; the raw SOCKS5 greeting is only
                                // the belt-and-braces LIVENESS half, and it can miss on a
                                // momentarily busy listener. This branch used to be a
                                // silent terminal dead end — no transport, no health loop,
                                // no relaunch latch — so the app sat "Connecting…" forever
                                // and the relay saw zero requests with nothing left to
                                // change its mind. Wire the control-confirmed port and let
                                // the reachability loop's existing hysteresis judge it: if
                                // the listener really is gone every probe misses, NEWNYM
                                // fires at 8 and the manual-reconnect UI surfaces at 24.
                                LogBuffer.shared.append(level: "W", tag: "AppState",
                                    message: "socksPort=\(port) control-confirmed but SOCKS5 probe failed — wiring anyway, health loop will judge")
                            }
                            self.wireRelayTransport(socksPort: port, reason: "resume re-wire, control-confirmed")
                        }
                    }
                }
            }
        } else {
            // Clearnet relay = NO Tor (IP/metadata exposed). Intended only for
            // the simulator/dev override. In a RELEASE build a non-.onion relay
            // means a misconfigured relay shipped, so fail CLOSED rather than
            // silently routing direct — mirroring Android RunViewModel
            // (iOS parity).
            #if DEBUG
            LogBuffer.shared.append(level: "D", tag: "AppState", message: "using direct HTTP (no Tor) — dev/simulator")
            controller.connectDirect()
            transport.torState = .connected
            startRelayCheck()
            #else
            LogBuffer.shared.append(level: "E", tag: "AppState", message: "clearnet relay refused in release build — Tor unavailable, messaging disabled")
            transport.torState = .disconnected
            #endif
        }
    }
}

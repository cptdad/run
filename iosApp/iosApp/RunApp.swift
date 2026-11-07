import SwiftUI
import shared
import os

// WIPE FORENSICS — DEBUG-ONLY.
//
// The cross:multi §7 guard catches the iOS vault being DESTROYED mid-suite; wipeDiag
// names which wipe path fired via a public os_log line AND a Documents/wipediag.txt
// breadcrumb (idevicesyslog drops lines; the file is captured losslessly).
//
// BUT os_log %{public} is on-disk in the unified log outside the sandbox, and NO wipe
// path deleted wipediag.txt — so in a Release build every emergency/panic/inactivity
// wipe left a permanent, timestamped forensic record PROVING prior app use after a
// seizure, defeating the "black powered-off screen, wipe must not be provable"
// deniability. The entire diagnostic is therefore compiled OUT of Release: callers
// stay unconditional but the body is a no-op there (mirrors torLog).
#if DEBUG
private let wipeDiagLog = Logger(subsystem: "com.vg.run", category: "WipeDiag")
#endif
func wipeDiag(_ reason: String) {
    #if DEBUG
    wipeDiagLog.error("WIPEDIAG fired: \(reason, privacy: .public)")
    let ts = ISO8601DateFormatter().string(from: Date())
    let line = "\(ts) WIPEDIAG: \(reason)\n"
    if let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first {
        let f = docs.appendingPathComponent("wipediag.txt")
        if let data = line.data(using: .utf8) {
            if let h = try? FileHandle(forWritingTo: f) {
                h.seekToEndOfFile(); h.write(data); try? h.close()
            } else {
                try? data.write(to: f)
            }
        }
    }
    #endif
}

/// Best-effort removal of the wipediag.txt breadcrumb. Runs in ALL builds
/// (unlike wipeDiag, now DEBUG-only) so a wipe on a device that previously ran a
/// DEBUG/beta build still erases any residual forensic record.
func deleteWipeDiagFile() {
    if let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first {
        try? FileManager.default.removeItem(at: docs.appendingPathComponent("wipediag.txt"))
    }
}

class AppDelegate: NSObject, UIApplicationDelegate {
    func application(_ application: UIApplication,
                     supportedInterfaceOrientationsFor window: UIWindow?) -> UIInterfaceOrientationMask {
        return .portrait
    }

    /// Refuses third-party keyboards app-wide (the system keyboard is always used).
    /// WHY: a third-party keyboard with Full Access keeps its own learned-language
    /// store and personal dictionary in its own container, outside Rún's sandbox. No
    /// Rún wipe path reaches it, and an AFU full-filesystem extraction can read it, so
    /// message words, contact names and group names typed into the (non-secure)
    /// composer and other text fields would outlive even a panic wipe there. The
    /// system keyboard honours the `.password` content-type hint those fields set
    /// (noLearningComposerStyle); third-party keyboards need not. iOS already forces
    /// the system keyboard on SecureFields; this extends it to every field. The
    /// system keyboard covers all shipped locales.
    func application(_ application: UIApplication,
                     shouldAllowExtensionPointIdentifier extensionPointIdentifier: UIApplication.ExtensionPointIdentifier) -> Bool {
        extensionPointIdentifier != .keyboard
    }

    // -----------------------------------------------------------------------
    // Opt-in push (docs/RELAY_SPEC.md). APNs callbacks land HERE, never
    // in a View — [appState] is wired in `RunApp.body` via `.onAppear`, NOT in
    // `RunApp.init()`. `@StateObject` takes an @autoclosure, so no AppState
    // exists yet while the App struct's property defaults are applied; a weak
    // assignment made there would either dangle immediately or capture a
    // throwaway instance, which is exactly how APNs tokens were silently
    // dropped (root-caused on-device 2026-07-24 — see RunApp.init()'s closing
    // comment). Until that `.onAppear` runs, `appState` is legitimately nil,
    // which is why every use below is optional-guarded.
    // -----------------------------------------------------------------------

    /// Bridge to the single AppState instance. Weak: AppState (via
    /// @StateObject) owns the app's lifetime, not the other way around.
    weak var appState: AppState?

    func application(_ application: UIApplication,
                      didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        let hex = deviceToken.map { String(format: "%02x", $0) }.joined()
        // DIAG (2026-07-24): log BEFORE the (weak, optional) appState hop so a nil
        // appState — which would silently swallow the token — is distinguishable
        // from the token simply never arriving.
        LogBuffer.shared.append(level: "I", tag: "Push", message: "didRegister: token len=\(hex.count), appState=\(appState != nil ? "set" : "NIL")")
        appState?.registerPushToken(hex)
    }

    func application(_ application: UIApplication,
                      didFailToRegisterForRemoteNotificationsWithError error: Error) {
        LogBuffer.shared.append(level: "W", tag: "Push", message: "APNs registration failed: \(String(describing: type(of: error)))")
    }

    func application(_ application: UIApplication,
                      didReceiveRemoteNotification userInfo: [AnyHashable: Any],
                      fetchCompletionHandler completionHandler: @escaping (UIBackgroundFetchResult) -> Void) {
        guard let appState else { completionHandler(.noData); return }
        appState.handleRemotePushWake(completionHandler: completionHandler)
    }
}

// DEBUG-only e2e helper. Wipes all persisted vault material before any
// view loads. Mirrors the keys / Keychain entries / DB filenames used by
// IosAppController.emergencyWipe() — keep them in sync.
#if DEBUG
fileprivate func wipeAllPersistentStateForTest() {
    let defaults = UserDefaults.standard
    // Single source of truth — see IosUserDefaultsKeys docs in commonMain.
    for key in IosUserDefaultsKeys.shared.all {
        defaults.removeObject(forKey: key)
    }
    // The EULA-accepted flag is an iOS-only @AppStorage key (not part of the
    // shared IosUserDefaultsKeys set), so clear it explicitly — a test wipe must
    // be a true first-install, with the Guideline 1.2 Terms gate shown again.
    // The e2e suite relies on this (EulaHelper.passEulaIfPresent).
    defaults.removeObject(forKey: EulaConsent.storageKey)
    // Same story for the opt-out pending-dereg flag (2026-08-11): iOS-only
    // UserDefaults key, not in the shared list. Left armed, a previous e2e
    // session's failed opt-out would make the fresh session's control poll run
    // a spurious (harmless but noisy) dereg sweep against brand-new inboxes.
    // Production wipes clear it via AppState.clearWipeResidue().
    defaults.removeObject(forKey: PushDeregPending.storageKey)
    // Same story for the LEGACY store-review counters (ReviewPromptStore):
    // iOS-only UserDefaults keys, not in the shared list. The LIVE counters now live in the vault's `_meta`
    // table, which the run.db/run_b.db removal below already wipes — these
    // three keys only matter for an install not yet migrated, so clearing
    // them here is defense in depth for a fresh-install e2e run (a debug/e2e
    // build never asks for a review either way — ReviewPromptPolicy's
    // isDebugBuild gate). Production wipes clear these via
    // AppState.clearWipeResidue().
    defaults.removeObject(forKey: ReviewPromptStore.firstUnlockAtKey)
    defaults.removeObject(forKey: ReviewPromptStore.unlockCountKey)
    defaults.removeObject(forKey: ReviewPromptStore.promptedKey)
    defaults.synchronize()
    KeychainHelper.shared.deleteKey()
    // Vault verifier / wrapped DB key / wrong-PIN counters now live in the
    // Keychain (not NSUserDefaults) — clear them too, or a wipe-then-setup e2e
    // run would find a stale verifier and skip PIN setup.
    KeychainHelper.shared.kvDeleteAll()
    let fm = FileManager.default
    // Tor's working dir. Load-bearing since 2026-08-01: it is PRESERVED across
    // launches now (TorManager.preservesStateAcrossLaunches), so start() no longer
    // clears it and a test wipe that skipped it would carry the previous run's
    // guard/consensus state into a "fresh install". Android sibling: TestHooks →
    // WipeRoutine, which deletes both tor_direct trees. Uses the same helper the
    // manager itself wipes through, so device and simulator paths always agree.
    try? fm.removeItem(atPath: TorManager.workingDirPath())
    for searchDir in [
        FileManager.SearchPathDirectory.applicationSupportDirectory,
        .cachesDirectory,
    ] {
        for dir in NSSearchPathForDirectoriesInDomains(searchDir, .userDomainMask, true) {
            for name in ["run.db", "run_b.db"] {
                // -journal kept in sync with emergencyWipe() (see emergencyWipe).
                for suffix in ["", "-wal", "-shm", "-journal"] {
                    try? fm.removeItem(atPath: "\(dir)/\(name)\(suffix)")
                }
            }
        }
    }
}
#endif

@main
struct RunApp: App {

    @UIApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    @StateObject private var appState = AppState()

    init() {
        // FIRST: the Kotlin→Swift bridge holders. Everything below that touches
        // the shared framework (the build-type check is pure Kotlin, but
        // DebugMode.applyAtStartup constructs a KeyValueStore and reads the
        // Keychain) needs them, and no AppState has been constructed yet —
        // `@StateObject` is lazy. See AppState.registerBridges.
        AppState.registerBridges()
        // Fail loud at startup if a RELEASE app linked the DEBUG shared
        // xcframework — that would run Argon2id at the 1 MiB/1-pass debug cost and silently
        // provision every vault forensically-weak. We pass the APP's own build type.
        #if DEBUG
        BuildFlagsKt.assertKdfBuildIntegrity(appIsReleaseBuild: false)
        #else
        BuildFlagsKt.assertKdfBuildIntegrity(appIsReleaseBuild: true)
        #endif
        ScreenshotProtection.shared.enable()
        // Test wipe must run BEFORE AppState constructs IosAppController,
        // so we do it here rather than inside AppState.init. DEBUG-only.
        #if DEBUG
        // The e2e wipe flag carries a per-reset NONCE: --test-wipe-on-launch=<nonce>.
        // resetIos() passes a FRESH nonce each time it wants a clean slate (suite
        // start / mocha retry). But the flag re-applies on every subsequent process
        // launch — an activateApp cold-relaunch (Tor recovery, §7 background+resume
        // that iOS jetsammed) inherits the SAME args, so a bare "wipe on any flagged
        // launch" DESTROYED the provisioned vault mid-attempt (cross:multi §7 caught
        // the app resuming onto first-run setup; forensics 2026-07-15). Gate on the
        // nonce: wipe only when it DIFFERS from the last wipe we performed. A relaunch
        // reusing the same nonce is a mid-attempt relaunch → preserve the vault; a new
        // nonce is a genuine new attempt → wipe. The marker is re-set AFTER the wipe
        // (which clears UserDefaults), so it survives to gate the next relaunch.
        let wipeArg = ProcessInfo.processInfo.arguments.first { $0.hasPrefix("--test-wipe-on-launch") }
        if let wipeArg {
            let nonce = wipeArg.contains("=") ? String(wipeArg.split(separator: "=", maxSplits: 1)[1]) : "legacy"
            let lastNonce = UserDefaults.standard.string(forKey: "e2e_last_wipe_nonce")
            if nonce != lastNonce {
                wipeDiag("RunApp.test-wipe (nonce \(nonce) != last \(lastNonce ?? "nil")) — wiping")
                wipeAllPersistentStateForTest()
                UserDefaults.standard.set(nonce, forKey: "e2e_last_wipe_nonce")
            } else {
                wipeDiag("RunApp.test-wipe SKIPPED (nonce \(nonce) unchanged — mid-attempt relaunch, vault preserved)")
            }
            // E2E DETERMINISM: keep the screen awake for the whole automated run.
            // In a multi-device suite a device sits IDLE while another phone mints
            // or while a group invite propagates; if it auto-locks it backgrounds
            // the app, which (1) locks the vault → PIN screen and (2) lets iOS kill
            // the embedded Tor thread — so its runestone goes unlit and the suite
            // stalls at the relay-ready gate. Disabling the idle timer keeps idle
            // devices foregrounded so none of that happens. Test-only (gated on the
            // e2e launch arg); production keeps normal auto-lock.
            DispatchQueue.main.async { UIApplication.shared.isIdleTimerDisabled = true }
        }
        // English pin (PHASE 0 localization): --test-language=<tag> from the e2e
        // harness (AppLocale.ts's iOS counterpart — wdio.ios.conf.ts /
        // AppReset.ts / Device.ts). Persisted to UserDefaults' "AppleLanguages"
        // key (not just read from the launch argument) so an ARG-LESS cold
        // relaunch — Tor recovery, an iOS jetsam bring-back — still boots in the
        // pinned language; those relaunches don't necessarily carry the process
        // arguments again. Deliberately NOT added to IosUserDefaultsKeys.all: a
        // test wipe must not un-pin the language mid-suite. DEBUG-only, same as
        // the wipe/reauth args above — scripts/verify-release-clean.sh asserts
        // that EVERY ProcessInfo.processInfo.arguments read in this file (a
        // preprocessor-depth walk, not just "the file contains #if DEBUG
        // somewhere") sits inside an active #if DEBUG branch, so this one
        // (and --test-wipe-on-launch / --test-reauth-interval-ms alongside it)
        // must stay inside #if DEBUG or the pre-push gate fails the build.
        if let langArg = ProcessInfo.processInfo.arguments.first(where: { $0.hasPrefix("--test-language=") }) {
            let lang = String(langArg.dropFirst("--test-language=".count))
            UserDefaults.standard.set([lang], forKey: "AppleLanguages")
        }
        #endif
        // Flip the master logging kill switch BEFORE any log call. In DEBUG
        // builds this lets LogBuffer capture lines for the in-app log viewer;
        // it stays on-device only (the off-device Loki telemetry sink was
        // removed). Release builds leave it false, so LogBuffer.append is a
        // no-op: nothing is held in memory at all.
        #if DEBUG
        LoggingState.shared.enabled = true
        LogBuffer.shared.append(level: "I", tag: "DiagSwift", message: "RunApp.init")
        // Periodic random re-auth at MAXIMUM (docs/periodic-reauth-design.md):
        // --test-reauth-interval-ms=<n> arms a FIXED interval for e2e determinism
        // via ReauthPolicy.setTestIntervalOverrideMs. Independent of the wipe nonce
        // above — applies on every debug launch that passes it, not only a wiped
        // one (a relaunch inherits the SAME args, same as --test-wipe-on-launch).
        // Debug builds are OFF by default (ReauthPolicy.isEnabled); this is the
        // ONLY way to turn the touch-independent timer on in a debuggable binary,
        // and there is no equivalent path in a release build — the setter itself
        // refuses outside isDebugBuild.
        if let reauthArg = ProcessInfo.processInfo.arguments.first(where: { $0.hasPrefix("--test-reauth-interval-ms=") }),
           let ms = Int64(reauthArg.split(separator: "=", maxSplits: 1)[1]) {
            let armed = ReauthPolicy.shared.setTestIntervalOverrideMs(ms: ms)
            LogBuffer.shared.append(level: "W", tag: "DiagSwift", message: "test-reauth-interval-ms=\(ms) armed=\(armed)")
        }
        // e2e-only: force the update nudge's App-Store two-button variant to
        // render on this simulator/debug build, which has no real App Store
        // receipt (StoreInstall.isAppStoreInstall) to satisfy the ordinary
        // check. Android sibling: TestHooks.handleTestForceStoreInstall /
        // RunViewModel.isPlayInstall (`--ez TEST_FORCE_STORE_INSTALL true`).
        // No equivalent path exists in a release build — isAppStoreInstall's
        // #else branch (AppState.swift) never reads this flag at all.
        if ProcessInfo.processInfo.arguments.contains("--test-force-store-install") {
            StoreInstall.debugForceStoreInstall = true
            LogBuffer.shared.append(level: "W", tag: "DiagSwift", message: "test-force-store-install armed")
        }
        // e2e-only: the physical-phone A/B's NO-HEDGE CONTROL ARM for the descriptor hedge
        // (shared DescriptorHedge). XCUITest re-applies the launch arguments on
        // every later activateApp cold launch of the session, so the connect:cycle
        // relaunches keep it. Android sibling: TestHooks.handleTestDescriptorHedge
        // (`--ez TEST_DESCRIPTOR_HEDGE_OFF true`). setNoHedgeControl itself refuses
        // outside a debug build.
        if ProcessInfo.processInfo.arguments.contains("--test-descriptor-hedge-off") {
            let armed = DescriptorHedge.companion.setNoHedgeControl(on: true)
            LogBuffer.shared.append(level: "W", tag: "DiagSwift", message: "test-descriptor-hedge-off armed=\(armed)")
        }
        // e2e-only: the same A/B control arm for the RENDEZVOUS hedge (shared
        // RendezvousHedge, 2026-10-25). Android sibling: TestHooks
        // (`--ez TEST_REND_HEDGE_OFF true`). Refused outside a debug build.
        if ProcessInfo.processInfo.arguments.contains("--test-rend-hedge-off") {
            let armed = RendezvousHedge.shared.setNoHedgeControl(on: true)
            LogBuffer.shared.append(level: "W", tag: "DiagSwift", message: "test-rend-hedge-off armed=\(armed)")
        }
        // e2e-only MEASUREMENT (tests/adhoc/tor-suspend-survival.spec.ts): the
        // bounded Tor keep-alive never tears down on its window / expiration /
        // residue-cap deadline, so the process simply SUSPENDS with Tor kept, and
        // every warm return writes the suspend-survival probe (AppState). Device
        // lock and wipes still tear down. The static it sets exists only in DEBUG,
        // so a release binary has no path to an unbounded keep-alive at all.
        if ProcessInfo.processInfo.arguments.contains("--test-tor-keepalive-unbounded") {
            AppState.testUnboundedTorKeepAlive = true
            LogBuffer.shared.append(level: "W", tag: "DiagSwift", message: "test-tor-keepalive-unbounded armed")
        }
        #endif
        // Debug mode (settings row, ContactListView) may have been turned on in
        // a previous session — including a RELEASE session, since the toggle is
        // available in every build. DebugMode.applyAtStartup re-reads that
        // persisted (Keychain) choice and re-flips the master LoggingState kill
        // switch when it's on, UNCONDITIONALLY (not inside `#if DEBUG` above): a
        // DEBUG build already forced LoggingState on a few lines up, so this is a
        // harmless no-op there, but a RELEASE build otherwise never touches
        // LoggingState at all, and Debug-mode's periodic/connect/lock uploads
        // (AppState.swift) need it enabled to have anything to upload.
        //
        // A throwaway `KeyValueStore()` is used here rather than
        // `appState.controller`'s — see the comment on `appState` immediately
        // below for why reading the @StateObject this early is unsafe. This one
        // is safe to construct fresh: its init-time journal recovery is a
        // no-op when nothing is pending. The Keychain bridge it needs is
        // registered by `AppState.registerBridges()` at the TOP of this init —
        // NOT by `AppState()`: `@StateObject` takes an @autoclosure, so no
        // AppState has run yet at this point (the previous comment claimed it
        // had; that wrong assumption made this read throw and fold to OFF on
        // every launch until 2026-09-22 — see AppState.registerBridges).
        // The flag is a DEVICE-KEY AEAD blob now, so a
        // CryptoProvider goes with the store. Constructing one is lazy (it reads
        // the Keychain only when there is a value to open), and the same bridge
        // registration at the top of this init covers both.
        DebugMode.shared.applyAtStartup(store: KeyValueStore(), crypto: CryptoProvider())
        // Opt-in push (docs/RELAY_SPEC.md): the AppDelegate → AppState wire
        // is done in `body` via .onAppear, NOT here. Reading `appState` (a
        // @StateObject) inside init() returns a THROWAWAY instance — SwiftUI only
        // installs the real one when the view first mounts — so a weak assignment
        // here immediately dangled to nil. APNs device tokens then arrived at
        // didRegisterForRemoteNotificationsWithDeviceToken with appState == nil and
        // were SILENTLY DROPPED, so opt-in never registered a push token with the
        // relay (root-caused on-device 2026-07-24: "didRegister… appState=NIL").
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(appState)
                // Wire the AppDelegate's (weak) AppState ref to the REAL,
                // view-installed @StateObject instance — see init() for why this
                // can't be done there. Without it, APNs tokens are dropped
                // (appState nil). Idempotent: always the same instance, which the
                // @StateObject keeps alive for the app's lifetime.
                //
                // The APNs request that used to sit
                // here is GONE. It ran before unlock, gated on the PLAINTEXT
                // `pushEnabled` NSUserDefaults value, so a planted
                // `notif_level=vendor_push` still got Apple to mint this device a
                // live token — no relay row, but half a vendor identity created
                // from an unauthenticated value. The request now happens only
                // from the post-unlock paths, behind the same proven consent
                // `IosAppController.registerRefs` requires
                // (`AppState.registerApnsIfPushConsentProven`). Nothing is lost:
                // registering an inbox needs an OPEN VAULT to enumerate refs, so
                // a token obtained before unlock could never have been used
                // until then anyway.
                //
                // The WIRE below stays, and stays first: the AppDelegate's weak
                // `appState` must be live before any token can arrive, or
                // `didRegisterForRemoteNotificationsWithDeviceToken` drops it
                // (the "throwaway @StateObject → weak ref nil" bug fixed in
                // 51e38de). With the request moved to unlock it now happens long
                // before the first possible callback rather than in the same
                // turn of the run loop, which is strictly safer.
                .onAppear {
                    appDelegate.appState = appState
                }
                .preferredColorScheme(.dark)
                // App-wide default typeface. iOS has no global font setting, so
                // before this ONLY explicit `.font(.rune*)` call sites rendered in
                // Metamorphous — anything unstyled (the settings sheet's
                // `Label(title, systemImage:)` rows, for one) silently kept San
                // Francisco. This sets the inherited default; every explicit
                // `.font(...)` still wins, so the deliberate monospace surfaces
                // (log viewer, codes, forensic panel), the serif wordmark and
                // `.system(size:)` icon sizing are unaffected.
                .font(.runeBody)
        }
    }
}

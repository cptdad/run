import SwiftUI
import UIKit
import Combine
@preconcurrency import shared

// ---------------------------------------------------------------------------
// AppState+DebugLog.swift — the anonymous support channel to the relay: the bug
// report and Debug mode (consent toggle, the ~1 Hz periodic upload loop and its
// stop). The stored task handles
// (debugLogTask / debugLogConnectTask) stay in AppState.swift: an extension cannot
// hold stored properties.
// Extension members of the @MainActor AppState class stay main-actor isolated.
// The androidApp source guards read AppState.swift + every AppState+*.swift
// together (SourceScan.kt `iosAppStateSources()`), so their whole-file checks
// keep covering this code.
// ---------------------------------------------------------------------------

extension AppState {
    /// Anonymous "Report bug" — see `IosAppController.sendBugReport` /
    /// `BugReportSender` (commonMain). No vault access, no capability, no
    /// auth; nothing about the report is persisted on this device. `false`
    /// covers every failure uniformly (no relay connected yet, 413/429,
    /// any other status, transport error) — ContactListView shows one
    /// generic error copy for all of them.
    func sendBugReport(text: String) async -> Bool {
        let controller = self.controller
        return await Task.detached(priority: .userInitiated) {
            controller.sendBugReport(text: text)
        }.value
    }

    // -----------------------------------------------------------------------
    // Debug mode — opt-in upload of the rolling log buffer to the relay for
    // support triage (DebugMode.kt / DebugLogUploader.kt, commonMain). Off by
    // default in every build, including DEBUG. Three trigger sites:
    //   - "connect": checkRelayReachability, right where connectTelemetrySent
    //     is latched.
    //   - "periodic": [startDebugLogLoop] below, roughly once a second while
    //     unlocked, same session lifecycle as the relay health loop.
    //     DebugLogUploader.flush is cursor-based and a cheap no-op (no POST)
    //     whenever nothing is new since the last successful tick, which is
    //     what makes a 1 Hz cadence safe.
    //   - "lock": [lock] below, bounded to 3 s, before Tor/log teardown.
    // All three reuse the SAME live transport [sendBugReport] does
    // (`messageManager?.relayTransport()`), never a fresh client, and are
    // fire-and-forget: a dropped flush is simply retried on the next tick
    // (the cursor only advances on a confirmed 204). Never blocks the main
    // actor.
    // -----------------------------------------------------------------------

    /// Ceiling on the Debug-mode FINAL flush at lock ([lock]). That wait is
    /// SYNCHRONOUS on the main actor, so it is a hard cap on how long a lock can
    /// visibly stall. Lowered 3 s → 1.5 s (2026-09-14) and now paired
    /// with the skip-entirely gate for a session whose relay was not answering,
    /// so the budget is only ever spent on a circuit that just replied. Android
    /// sibling: `RunViewModel.DEBUG_LOG_LOCK_FLUSH_TIMEOUT_MS`.
    static let debugLogLockFlushTimeoutSec: Double = 1.5

    /// `CFBundleShortVersionString` — same value the About screen shows.
    /// DebugLogUploader does its own bounding/sanitizing on the Kotlin side
    /// (mirrors ConnectTelemetry's `sanitizeAppVersion`), so this is passed
    /// through as-is.
    var debugLogAppVersion: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "?"
    }

    /// Settings-sheet toggle (`settings_debug_mode` / `debug_mode_confirm`).
    /// Keychain-backed via [IosAppController.setDebugModeEnabled] — the SAME
    /// store instance vault credentials use — so the choice survives
    /// lock/unlock and a fresh process launch (RunApp.init's
    /// `DebugMode.applyAtStartup` reads it back on the next launch, even in a
    /// RELEASE build). [DebugMode.setEnabled] itself resets the uploader's
    /// cursor on BOTH directions (commonMain — consent is not retroactive),
    /// so nothing extra is needed here for that. Starts/stops the periodic
    /// upload loop immediately so a mid-session toggle takes effect without
    /// waiting for the next unlock.
    /// The flag comes from the RETURN VALUE, never from the requested `on`:
    /// turning Debug mode off can fail to persist (a Keychain that refuses both
    /// the delete and the explicit "0" overwrite while the keybag is locked),
    /// and the Settings toggle must then keep showing ON rather than claim a
    /// revocation the next launch will undo. Android sibling:
    /// `RunViewModel.setDebugMode`.
    func setDebugMode(_ on: Bool) {
        let persisted = controller.setDebugModeEnabled(on: on)
        debugMode = persisted
        LogBuffer.shared.append(level: "I", tag: "AppState", message: "debug mode set to \(on) (persisted \(persisted))")
        if on && persisted {
            startDebugLogLoop()
        } else {
            // OFF was requested ⇒ the loop stops, even in the rare case
            // where `persisted` came back true because the revocation could not
            // be written. Nothing would upload either way (DebugMode.setEnabled
            // has already flipped LoggingState off and flush() is a no-op while
            // that is false), but a 1 Hz task running against a consent the user
            // just revoked is not a state worth keeping.
            stopDebugLogLoop()
        }
    }

    /// Starts the ~1 Hz periodic debug-log flush, tied to the SAME session
    /// lifecycle as the relay health loop: called from [startRelayCheck]
    /// (session start) and from [setDebugMode] (mid-session toggle-on).
    /// IDEMPOTENT like [startRelayCheck] — a loop already running is left
    /// alone. No-op unless [debugMode] is currently on. Cancelled by
    /// [stopDebugLogLoop] ([stopRelayCheck] / [setDebugMode] toggle-off).
    ///
    /// `Task.detached`, never the main actor: [DebugLogUploader.flush] is a
    /// Kotlin suspend call that may do a full onion round trip when there IS
    /// something new to ship, and this loop must not pin a main-actor Task
    /// alive for that.
    func startDebugLogLoop() {
        // 2026-09-21: the loop runs even while `debugMode` reads OFF, and keeps
        // RE-READING the persisted consent until it reads ON. Rationale: the
        // launch-time and the vault-open reads of the unlocked-only Keychain
        // item can BOTH fail on a passcode-protected phone in the seconds
        // after the device unlocks (prod iPhone 1.6.27: flag persisted true,
        // Settings row ON, fresh process, zero uploads). A single rescue
        // read was not enough; only a retried read is. The tick is a cheap
        // no-op until it succeeds, and it only ever flips OFF → ON
        // (DebugMode.reapplyPersisted never revokes). While OFF the loop
        // must not upload — the guard inside the loop still requires
        // `debugMode`.
        if let existing = debugLogTask, !existing.isCancelled { return }
        let controller = self.controller
        let app = debugLogAppVersion
        debugLogTask = Task.detached(priority: .background) { [weak self] in
            var consentKnownOff = false
            // Diagnostic (2026-09-22): what the retried reads answered BEFORE
            // consent was seen, written out once logging is on — LogBuffer
            // drops lines while LoggingState is off, so it cannot be logged as
            // it happens. Counts and status codes only.
            var readsUnreadable = 0, readsOff = 0
            // NEVER voluntarily `break` on a business-logic condition (only on
            // cancellation / `self` gone) — [startRelayCheck]'s own
            // `!existing.isCancelled` idempotency check assumes a task that
            // hasn't been cancelled is still actively looping, which a stray
            // `break` here would silently violate (a later toggle-on would
            // then see a finished-but-not-cancelled task and skip starting a
            // new one). A tick with nothing to do simply `continue`s.
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 1_000_000_000)
                if Task.isCancelled { break }
                guard let self else { break }
                let (on, unlocked) = await MainActor.run { (self.debugMode, self.isUnlocked) }
                guard unlocked else { continue }
                if !on {
                    // Consent not yet seen in this process: retry the
                    // persisted read (see the kdoc above) while it is
                    // UNREADABLE; a definite OFF ends the retrying — the
                    // user revoked it, and the Settings toggle restarts this
                    // loop if they turn it back on. Only ever OFF → ON.
                    if consentKnownOff { continue }
                    switch controller.reapplyDebugModeTriState() {
                    case 1:
                        await MainActor.run { self.debugMode = true }
                        LogBuffer.shared.append(level: "I", tag: "AppState", message: "debug mode re-applied by the periodic loop after \(readsUnreadable) unreadable + \(readsOff) off read(s)")
                    case 0:
                        readsOff += 1
                        consentKnownOff = true
                    default:
                        readsUnreadable += 1
                    }
                    continue
                }
                if readsUnreadable + readsOff > 0 {
                    // Consent arrived by the Settings toggle after the loop had
                    // given up or was still retrying: say what it had seen.
                    LogBuffer.shared.append(level: "W", tag: "AppState", message: "debug mode consent came from the toggle; the loop's own reads before it: \(readsUnreadable) unreadable, \(readsOff) off")
                    readsUnreadable = 0; readsOff = 0
                }
                // THE 2026-09-22 ROOT CAUSE (prod iPhone with a passcode, three
                // earlier fixes notwithstanding): `debugMode` (this flag) and the
                // master LoggingState switch are set by TWO separate Keychain
                // reads at two moments — RunApp.init's applyAtStartup (first
                // instant of the process) flips LoggingState, AppState.init's
                // read moments later sets this flag. On a passcode-protected
                // phone the FIRST read fails → LoggingState stays off; the
                // second succeeds → Settings row ON, this loop runs — and
                // DebugLogUploader.flush returns "success" without collecting
                // a line while LoggingState is off. Every tick was a silent
                // no-op for the life of the process; the Settings toggle
                // worked because setEnabled flips LoggingState directly. The
                // the physical test phones never reproduced it: its phones have no passcode, so
                // the first read never fails there. Re-apply (a re-read that
                // only ever turns LoggingState ON) whenever the flag is true
                // but logging is not.
                if !LoggingState.shared.enabled {
                    if controller.reapplyDebugModeAfterUnlock() {
                        LogBuffer.shared.append(level: "I", tag: "AppState", message: "logging enabled by the periodic loop — the launch-time read had failed while the later flag read succeeded")
                    } else {
                        continue
                    }
                }
                let transport = controller.messageManager?.relayTransport()
                _ = try? await DebugLogUploader.shared.flush(
                    transport: transport, platform: "ios", app: app, reason: "periodic"
                )
            }
        }
    }

    /// See [startDebugLogLoop]. Called from [stopRelayCheck] (lock/wipe) and
    /// from [setDebugMode] toggle-off.
    ///
    /// Cancels the one-shot "connect" flush too: it sleeps 2-8 s before it
    /// uploads anything, so it is exactly the task most likely to still be in
    /// flight when a lock, a wipe or a consent toggle-off lands.
    func stopDebugLogLoop() {
        debugLogTask?.cancel()
        debugLogTask = nil
        debugLogConnectTask?.cancel()
        debugLogConnectTask = nil
    }
}

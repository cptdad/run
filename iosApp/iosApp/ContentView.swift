import SwiftUI
import UIKit
import LocalAuthentication
import shared

// ---------------------------------------------------------------------------
// ContentView — root navigation controller.
//
// Flow:
//   • Not configured → PinSetupView (first-run PIN creation)
//   • Configured, locked → PinEntryView
//   • Unlocked → ContactListView (with push navigation to Conversation/AddContact)
//
// Security: locks the vault when the app leaves the foreground, forcing
// PIN re-entry on resume. Mirrors Android's onStop() → finish() pattern.
// ---------------------------------------------------------------------------

struct ContentView: View {
    @EnvironmentObject private var appState: AppState
    @Environment(\.scenePhase) private var scenePhase
    // Guideline 1.2: the Terms of Use (with the zero-tolerance clause) must be
    // accepted before the user registers (PIN setup) OR logs in (PIN entry), so
    // the gate sits above the whole vault flow. @AppStorage so accepting it
    // re-renders the tree immediately; comparing against EulaConsent.version
    // re-prompts everyone if the terms change.
    @AppStorage(EulaConsent.storageKey) private var acceptedEulaVersion = 0
    @State private var navPath       = NavigationPath()
    @State private var showAddContact = false
    @State private var showChangePin  = false
    @State private var showCreateGroup = false

    /// Distinct route type so group conversations don't collide with the
    /// String-typed contact route in the same NavigationPath.
    struct GroupRoute: Hashable { let groupId: String }

    /// NO-PARK (2026-10-06): "Open group" from a GROUP_ECHO bubble — pop the screen
    /// showing it and push the group, so back returns to the contact list (Android:
    /// popBackStack + navigate in MainActivity).
    private func openGroupReplacingTop(_ groupId: String) {
        if !navPath.isEmpty { navPath.removeLast() }
        navPath.append(GroupRoute(groupId: groupId))
    }

    // Jailbreak detection is a bypassable HEURISTIC, not a boundary (external
    // review #6): surface it as a risk signal the user can acknowledge and
    // continue past, rather than hard-blocking jailbroken-for-privacy users whom
    // a real attacker would bypass anyway.
    @State private var integrityAck = false
    // One-time warning at first-run provisioning if the device has NO
    // passcode. The vault's device-key half is stored under kSecAttrAccessibleWhenPasscode
    // SetThisDeviceOnly — with no passcode that accessibility class degrades, silently
    // weakening the at-rest dual factor. Non-blocking (Continue anyway); shown BEFORE the
    // keychain item is written (before PinSetupView provisions), so "set a passcode →
    // return" produces a passcode-bound item. @State survives the frequent struct re-inits.
    @State private var passcodeWarnAck = false

    // Threat-level slider: a legacy vault (provisioned before the feature) has no level
    // yet — after unlocking it, choose one ONCE (first-run picks it before the PIN).
    // Flips true when done so the main app shows; the persisted level also guards it,
    // so it never reappears even if this @State is reset by a struct re-init.
    @State private var protectionMigrationDone = false
    @State private var protectionForcedDone = false

    /// "Move to new device" (docs/device-move.md), NEW-phone side. First-run only:
    /// nil = the chooser has not been answered yet. RAM-only and deliberately NOT
    /// persisted — a relaunch mid-onboarding re-asks, which is also what the
    /// RAM-only handle requires (a process death means rescan, Protocol B2).
    private enum SetupChoice { case setUpAsNew, moveFromOtherPhone }
    @State private var setupChoice: SetupChoice? = nil

    // Foreground inactivity auto-lock (hardening plan Lever C, D4): poll the
    // touch monitor and lock after AUTO_LOCK_TIMEOUT_MS idle while unlocked.
    // Backgrounding locks immediately below; this bounds the app-open-idle case.
    // @State so the publisher is created ONCE and survives the
    // frequent ContentView struct re-inits — any AppState @Published change recreates
    // the struct, and a plain `let` restarted the 10s countdown each time, which could
    // starve the 2-min auto-lock while the device sits idle but network-active.
    @State private var autoLockTimer = Timer.publish(
        every: Double(CredentialPolicy.shared.AUTO_LOCK_CHECK_INTERVAL_MS) / 1000.0,
        on: .main, in: .common
    ).autoconnect()
    // Lever-C warning countdown (threat-slider spec, 2026-07-16) AND the
    // periodic-re-auth warning (docs/periodic-reauth-design.md) share this one
    // overlay: seconds until WHICHEVER deadline is nearer, or nil when no
    // warning is due.
    @State private var lockCountdownSeconds: Int? = nil
    // True when [lockCountdownSeconds] reflects the periodic re-auth deadline
    // rather than Lever C's idle timeout — selects the overlay copy variant
    // and the reauth_countdown a11y id.
    @State private var lockCountdownIsReauth = false
    // True while the poll runs at the 1 s fine cadence near the deadline.
    @State private var autoLockFineTicks = false

    // Periodic random re-auth at MAXIMUM (docs/periodic-reauth-design.md): a
    // fixed uptime instant for the NEXT forced re-lock, armed on every unlock
    // (isUnlocked onChange below) when `controller.reauthEnabled()`, and
    // cleared in lockAndResetNavigation() on every lock. "Since unlock", not
    // "active time" — nothing here resets it on a touch.
    @State private var reauthDeadlineUptime: TimeInterval? = nil

    /// True ONLY when the device DEFINITELY has no passcode. Matches the fail-closed
    /// convention of the codebase's other three copies of this probe (KeychainHelper /
    /// UserSafety / SecureEnclaveHelper): on any AMBIGUOUS LAContext error (e.g. a
    /// transient lock) assume a passcode IS set, so this gate fires exactly when the
    /// keychain actually downgrades the device key — never over-warns on uncertainty.
    /// Read-only, no prompt.
    private var deviceHasNoPasscode: Bool {
        var err: NSError?
        if LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: &err) { return false }
        return err?.code == LAError.passcodeNotSet.rawValue   // fail closed: warn only on a DEFINITE no-passcode
    }

    /// A just-unlocked legacy vault that has never had a threat level set → show the
    /// one-time chooser before the main app. Short-circuits once done (no controller
    /// call), and the persisted level keeps it false thereafter.
    private var needsProtectionChoice: Bool {
        !protectionMigrationDone && !appState.controller.protectionLevelConfigured()
    }

    /// This vault's stored tier is BELOW the floor its device requires: the phone
    /// has no passcode, so the device key sits at AfterFirstUnlock (readable in any
    /// AFU extraction) and only a passphrase still protects the vault. Runs on
    /// EVERY unlock, not just at onboarding — a passcode can be removed after
    /// provisioning. On iOS that usually crypto-erases the vault outright (the
    /// WhenPasscodeSet purge takes the device key AND the recovery blob), but the
    /// path where it doesn't must not stay on a 6-digit PIN. Latch first so the
    /// controller call is skipped once handled (same shape as the chooser above).
    private var needsForcedProtection: Bool {
        !protectionForcedDone
            && appState.controller.needsForcedProtectionMigration(passcodeAbsent: deviceHasNoPasscode)
    }

    var body: some View {
        gatedRoot
        .overlay { lockCountdownOverlay }
        // E2E Lever-C keep-alive target (DEBUG only — e2e-tests/helpers/
        // KeepAwake.ts). XCUITest drives the app through the accessibility layer
        // and generates NO touches, so a multi-minute Tor wait reads as pure
        // touch-idle and the auto-lock tears the session down. The harness taps
        // this every few seconds; the tap reaches the window's catch-all
        // recognizer (InactivityAutoLock) exactly like a real one.
        //
        // Element, not a coordinate: XCUITest refuses to tap a NON-HITTABLE
        // element, so while a RuneDialogOverlay scrim is up the poke fails
        // harmlessly — a blind coordinate tap would land on that scrim, whose
        // onTapGesture can dismiss the dialog out from under the test. Trailing
        // edge (the leading edge owns the interactive back-swipe) and 6 pt, so
        // it sits inside every screen's horizontal padding.
        .overlay(alignment: .trailing) { keepAlivePokeOverlay }
        // E2E suspend-survival probe (DEBUG only — the
        // `--test-tor-keepalive-unbounded` measurement mode, AppState
        // runTorSuspendProbe): the last warm return's probe as a fixed-key,
        // numbers-only accessibility VALUE, readable on every screen (the
        // connection-log panel is reachable only while the connecting caption is
        // up, which a fast warm reveal skips). Absent until the first probe, and
        // in RELEASE an EmptyView overlay — no test surface.
        .overlay(alignment: .topLeading) { torSuspendProbeOverlay }
        .onChange(of: scenePhase) { phase in
            // Only `.active` and `.background` — NEVER the transient `.inactive`
            // (Face ID / Control Center; the Lever-B re-lock lesson).
            if phase == .active { handleSceneBecameActive() }
            if phase == .background { handleSceneEnteredBackground() }
        }
        .onReceive(autoLockTimer) { _ in onAutoLockTick() }
        .onChange(of: appState.isUnlocked) { unlocked in onUnlockedChanged(unlocked) }
        // #18 + IOS-SEC-2: blank the app-switcher snapshot. iOS captures it
        // during .inactive (which precedes .background, where we lock), so
        // unlocked content would otherwise be written to the on-disk snapshot
        // store. The cover is applied to the root here AND (above, at the call
        // sites) to the AddContact sheet + ChangePin fullScreenCover — those
        // present in a SEPARATE layer above the root, so the root cover alone
        // does not reach them. (Android handles this with FLAG_SECURE.)
        .privacyCovered()
    }

    /// The root gate: exactly one full-screen state, in precedence order —
    /// integrity notice, EULA, move-frozen old phone, pending move import, the two
    /// protection-tier gates, the unlocked app, the deniable post-wipe black cover,
    /// unlock, the setup chooser, move-from-other-phone, the no-passcode warning,
    /// and first-run setup.
    @ViewBuilder
    private var gatedRoot: some View {
        if appState.isDeviceCompromised && !integrityAck {
            GateNoticeScreen(
                icon: "exclamationmark.shield.fill",
                tint: .red,
                title: L10n.gateCompromisedTitle,
                message: L10n.gateCompromisedBodyJailbroken
            ) {
                Button {
                    integrityAck = true
                } label: {
                    gateButtonLabel(L10n.gateCompromisedContinue)
                }
                .foregroundColor(.white)
                .padding(.top, 8)
            }
        } else if acceptedEulaVersion < EulaConsent.version && !appState.wipedThisSession {
            // Deniability: a DENIABLE panic wipe clears
            // the EULA-accepted flag (clearWipeResidue), resetting
            // acceptedEulaVersion to 0. This gate sits ABOVE the wipedThisSession
            // black cover below, so without `&& !appState.wipedThisSession` it
            // would re-render the full Terms-of-Use screen after a panic wipe —
            // revealing the wipe instead of the powered-off-looking black cover
            // the V-2 latch exists for. The non-deniable launch-time wipes leave
            // wipedThisSession=false, so they still (correctly) route to setup
            // via the EULA screen; only the deniable in-session path is guarded.
            EulaView(onAccept: { acceptedEulaVersion = EulaConsent.version })
        } else if appState.isUnlocked && appState.isMoveFrozen {
            // "Move to new device" D2: this vault is the OLD phone of a move. It
            // never polls and never sends again, so the contact list is
            // unreachable — every unlock lands here until the user wipes, or a
            // cancel PROVES the bundle was never picked up. Deliberately ABOVE the
            // protection-tier gates: nagging a phone that is on its way to being
            // wiped about its tier is noise, and the forced-tier flow would rotate
            // a credential on a vault whose whole job now is to be erased.
            MoveToNewDeviceView()
                .environmentObject(appState)
        } else if appState.isUnlocked, let handle = appState.pendingMoveHandle {
            // First post-unlock action with a handle in RAM (Protocol B4). The
            // handle is dropped on success AND on "continue without it", so this
            // screen can never trap a working phone.
            MoveImportView(
                handle: handle,
                onFinished: {
                    appState.pendingMoveHandle = nil
                    setupChoice = nil
                }
            )
            .environmentObject(appState)
        } else if appState.isUnlocked && needsProtectionChoice {
            ProtectionLevelMigrationView(onDone: { protectionMigrationDone = true })
        } else if appState.isUnlocked && needsForcedProtection {
            // Forced tier change. Reuses the settings flow because that is the
            // one place that drives the CREDENTIAL change inline — persisting
            // the tier alone would claim a passphrase this vault doesn't have.
            //
            // The forced ROUTE correctly
            // removes Back (ProtectionLevelView passes onBack: nil when
            // forced), but the credential-change sheet it delegates to still
            // has its own Cancel — dismissing that used to blind-latch
            // protectionForcedDone = true for the rest of the process
            // lifetime, so a single Cancel tap permanently escaped the gate.
            // Reachable on a real upgrade install: a vault stored at `casual`
            // on a passcode-less iPhone. Re-EVALUATE the policy on dismiss
            // instead: a genuine credential change clears
            // needsForcedProtectionMigration (so this re-check yields
            // `true` → done), while a Cancel leaves the vault still under
            // the floor (re-check yields `false` → the gate re-presents
            // immediately, same as `needsForcedProtection` recomputing on
            // every unlock already does at launch).
            ProtectionLevelSettingsView(
                onDismiss: {
                    protectionForcedDone = !appState.controller.needsForcedProtectionMigration(
                        passcodeAbsent: deviceHasNoPasscode
                    )
                },
                forced: true
            )
        } else if appState.isUnlocked {
            unlockedRoot
        } else if appState.wipedThisSession {
            // After an in-session emergency wipe, hold a black
            // screen indistinguishable from powered-off until relaunch, rather
            // than revealing the wipe with a fresh setup screen. Mirrors
            // Android, whose startDestination is computed once per launch.
            Color.black.ignoresSafeArea()
                .accessibilityIdentifier("wiped_cover")
        } else if appState.isConfigured {
            PinEntryView()
        } else if setupChoice == nil {
            // "Move to new device" (docs/device-move.md, Protocol B1): the first
            // thing a FRESH install shows, before anything is provisioned.
            //
            // Placed ABOVE the no-passcode warning, not below it: the warning
            // exists to fire "BEFORE PinSetupView provisions the vault" and
            // it still does — the chooser writes nothing. Putting it first would
            // instead bury the chooser behind a modal gate on exactly the devices
            // (passcode-less) the move e2e runs on.
            SetupChooserView(
                onSetUpAsNew: { setupChoice = .setUpAsNew },
                onMoveFromOtherPhone: { setupChoice = .moveFromOtherPhone }
            )
        } else if setupChoice == .moveFromOtherPhone && appState.pendingMoveHandle == nil {
            MoveFromDeviceView(
                onHandle: { handle in
                    // RAM only — never written anywhere (Protocol B2). From here
                    // onboarding is the UNCHANGED PinSetupView path; the import
                    // runs on the first unlock.
                    appState.pendingMoveHandle = handle
                },
                onBack: { setupChoice = nil }
            )
        } else if deviceHasNoPasscode && !passcodeWarnAck {
            // First-run + no device passcode. Warn (non-blocking)
            // BEFORE PinSetupView provisions the vault, so the user can set a passcode
            // first and get a passcode-bound device key. Mirrors the jailbreak-ack gate
            // structure (in-body buttons, not a .alert) so the e2e suites can tap through
            // reliably — the physical test iPhones have no passcode, so this DOES fire.
            GateNoticeScreen(
                icon: "lock.slash",
                tint: .yellow,
                title: L10n.gatePasscodeWarningTitle,
                message: L10n.gatePasscodeWarningMessage
            ) {
                Button {
                    if let url = URL(string: UIApplication.openSettingsURLString) {
                        UIApplication.shared.open(url)
                    }
                } label: {
                    gateButtonLabel(L10n.gatePasscodeWarningOpenSettings)
                }
                .foregroundColor(.white)
                .padding(.top, 8)
                .accessibilityIdentifier("passcode_warning_settings")
                Button {
                    passcodeWarnAck = true
                } label: {
                    gateButtonLabel(L10n.gatePasscodeWarningContinueAnyway)
                }
                .foregroundColor(.gray)
                .accessibilityIdentifier("passcode_warning_continue")
            }
            // localization PHASE 0: containerA11yId so this gate's own id
            // surfaces as a CONTAINER (matches EulaView) instead of shadowing
            // passcode_warning_settings/passcode_warning_continue below it.
            .containerA11yId("passcode_warning")
        } else {
            PinSetupView()
        }
    }

    /// A gate-notice button label: ONE line, never a mid-word break (2026-09-11) —
    /// shrink to fit instead.
    private func gateButtonLabel(_ text: String) -> some View {
        Text(text).lineLimit(1).minimumScaleFactor(0.5)
    }

    /// The unlocked app: the navigation stack over the contact list with its
    /// sheets, plus the invisible `unlocked_root` marker.
    @ViewBuilder
    private var unlockedRoot: some View {
        ZStack {
            NavigationStack(path: $navPath) {
                ContactListView(
                    onContactTapped: { id in navPath.append(id) },
                    onAddContact:    { showAddContact = true },
                    onChangePin:     { showChangePin = true },
                    onGroupTapped:   { id in navPath.append(GroupRoute(groupId: id)) },
                    onCreateGroup:   { showCreateGroup = true }
                )
                .navigationDestination(for: String.self) { contactId in
                    // NO-PARK: a GROUP_ECHO's "Open group" REPLACES this
                    // conversation (back then returns to the contact list).
                    ConversationView(contactId: contactId, onOpenGroup: { gid in
                        openGroupReplacingTop(gid)
                    })
                }
                .navigationDestination(for: GroupRoute.self) { route in
                    GroupConversationView(groupId: route.groupId, onOpenGroup: { gid in
                        openGroupReplacingTop(gid)
                    })
                }
                .sheet(isPresented: $showAddContact) {
                    AddContactView(onDismiss: { showAddContact = false })
                        .coveredDarkSheet()
                }
                .sheet(isPresented: $showCreateGroup) {
                    CreateGroupView(
                        onDismiss: { showCreateGroup = false },
                        onCreated: { id in
                            showCreateGroup = false
                            navPath.append(GroupRoute(groupId: id))
                        }
                    )
                    .privacyCovered()
                }
                .fullScreenCover(isPresented: $showChangePin) {
                    ChangePinView(
                        onDone:   { showChangePin = false },
                        onCancel: { showChangePin = false }
                    )
                    .coveredDarkSheet()
                }
            }
            // Invisible marker so Appium can verify unlocked state
            // without collapsing NavigationStack's a11y tree.
            Text("Unlocked")
                .font(.system(size: 1))
                .foregroundColor(Color.black.opacity(0.001))
                .accessibilityIdentifier("unlocked_root")
                .allowsHitTesting(false)
        }
    }

    /// The Lever-C / periodic re-auth countdown — the root `.overlay` content
    /// (see the comment inside for the behaviour).
    @ViewBuilder
    private var lockCountdownOverlay: some View {
        // Lever-C warning countdown (threat-slider spec, 2026-07-16): the last
        // AUTO_LOCK_WARNING_MS before the idle lock. Purely informational — the
        // deadline is unchanged; any touch resets the idle clock through the
        // window-level catch-all recognizer and the next tick hides this.
        // onTapGesture consumes the "stay" tap so it can't also trigger the
        // control underneath. Known gap: a presented sheet / fullScreenCover
        // draws ABOVE this overlay, so idling inside one warns invisibly — the
        // lock itself is unchanged (best-effort warning, same class as
        // Android's separate-window dialog blind spot).
        //
        // Since docs/periodic-reauth-design.md this ALSO renders the periodic
        // re-auth warning (lockCountdownIsReauth true) — same overlay, "Passphrase
        // check in N…" copy, reauth_countdown a11y id, and deliberately NO "tap
        // anywhere to stay unlocked" text: that deadline never moves regardless
        // of touches (the tap is still consumed below so it can't fall through
        // to whatever is underneath, but it does nothing).
        if let secondsLeft = lockCountdownSeconds {
            ZStack {
                Color.black.opacity(0.85).ignoresSafeArea()
                if lockCountdownIsReauth {
                    VStack(spacing: 12) {
                        Text(L10n.gateReauthCountdown(secondsLeft))
                            .font(.runeHeadline)
                            .foregroundColor(.white)
                            .accessibilityIdentifier("reauth_countdown")
                    }
                } else {
                    VStack(spacing: 12) {
                        Text(L10n.gateLockCountdown(secondsLeft))
                            .font(.runeHeadline)
                            .foregroundColor(.white)
                        Text(L10n.gateLockCountdownTapToStay)
                            .font(.runeFootnote)
                            .foregroundColor(.gray)
                    }
                }
            }
            .contentShape(Rectangle())
            .onTapGesture { }   // consume the "stay" tap; the recognizer already reset the clock (Lever C only — the re-auth deadline never moves)
        }
    }

    // Debug test overlays (both compile to an EmptyView overlay in RELEASE; the
    // `#if DEBUG` stays INSIDE each ViewBuilder — see the comments).

    /// E2E Lever-C keep-alive target (`keepalive_poke`).
    @ViewBuilder
    private var keepAlivePokeOverlay: some View {
        // #if lives INSIDE the ViewBuilder (not in the modifier chain) so
        // the syntax is valid on every Swift version we build with; in
        // RELEASE this resolves to an EmptyView overlay — no test surface.
        #if DEBUG
        Color.clear
            .frame(width: 6, height: 6)
            .contentShape(Rectangle())
            .accessibilityIdentifier("keepalive_poke")
        #endif
    }

    /// E2E suspend-survival probe (`tor_suspend_probe`).
    @ViewBuilder
    private var torSuspendProbeOverlay: some View {
        #if DEBUG
        if let probe = appState.torSuspendProbeSummary {
            Color.clear
                .frame(width: 6, height: 6)
                .contentShape(Rectangle())
                .accessibilityElement()
                .accessibilityIdentifier("tor_suspend_probe")
                .accessibilityLabel(Text(probe))
                .accessibilityValue(Text(probe))
        }
        #endif
    }

    /// Locks the vault and resets every presentation state — shared by the
    /// background lock, the inactivity auto-lock, and the periodic re-auth
    /// lock so none of the three paths can drift (a lock that leaves a
    /// sheet's @State true re-presents it over the PIN screen on the next
    /// in-process unlock — a coercion-context surprise). Also clears the
    /// periodic-re-auth deadline (docs/periodic-reauth-design.md) — nothing
    /// survives a lock, and the next unlock's isUnlocked onChange re-arms it
    /// fresh either way.
    ///
    /// [inForegroundScene] = an IN-SCENE lock (re-auth / Lever C, `.active` or
    /// `.inactive`): routed through AppState.lockInForegroundScene so Tor keeps
    /// running for the PIN-screen re-unlock. The default (false) is the plain
    /// lock() every `.background` / background-unlock path keeps using.
    private func lockAndResetNavigation(inForegroundScene: Bool = false) {
        if inForegroundScene {
            appState.lockInForegroundScene()
        } else {
            appState.lock()
        }
        reauthDeadlineUptime = nil
        navPath = NavigationPath()
        showAddContact = false
        showCreateGroup = false
        showChangePin = false
    }

    /// scenePhase → `.active` (see the `.onChange(of: scenePhase)` in body).
    private func handleSceneBecameActive() {
            // FIRST, before anything else on the way back: a re-auth deadline (or,
            // in release, the Lever-C idle timeout) that passed while the scene was
            // `.inactive` (Control Center, app switcher) locks NOW, in this same
            // update, instead of leaving the content readable until the next timer
            // tick (up to 10 s) once the privacy cover is gone. A `.background`
            // return finds the vault already locked: no-op.
            lockIfDeadlinePassed(includeIdle: true)
            // Bounded Tor keep-alive (AppState "Bounded Tor keep-alive"): a
            // return inside the window ends it — timer, device-lock observer
            // and background task — and REUSES the running Tor (no exit, no
            // relaunch latch, no second tor_main). A `.inactive` → `.active`
            // bounce (Face ID, Control Center) kept nothing: no-op. Before the
            // panel line below, because the reuse clears the panel ring and writes this
            // session's TOR_REUSED anchor; the "app foregrounded" line below
            // then lands in the new session's ring instead of being cleared.
            appState.endTorKeepAliveOnForeground()
            // Live connection-log panel (ConnectionLog.kt). Deliberately only
            // `.active` / `.background` — NEVER the transient `.inactive`
            // (Face ID / Control Center; the Lever-B re-lock lesson), which
            // would otherwise spam the panel on every biometric prompt.
            // CODED: the connect timeline and the debug-log uploader's
            // "worth a tick" test both read ConnectionLog.Code, and this
            // producer is why APP_FOREGROUNDED existed in the enum without
            // ever being emitted. Text unchanged. Android sibling:
            // MainActivity.onResume.
            ConnectionLog.shared.append(
                kind: ConnectionLog.Kind.system,
                text: "app foregrounded",
                code: ConnectionLog.Code.appForegrounded
            )
            // (Re)install the catch-all touch recognizer and reset the idle
            // clock — returning to the foreground is itself user activity.
            InactivityAutoLock.shared.installOnWindows()
            InactivityAutoLock.shared.touch()
    }

    /// scenePhase → `.background` (never `.inactive`; the caller gates on it).
    private func handleSceneEnteredBackground() {
            // Coded for the same reason as "app foregrounded" above.
            // Android sibling: MainActivity.onStop.
            ConnectionLog.shared.append(
                kind: ConnectionLog.Kind.system,
                text: "app backgrounded",
                code: ConnectionLog.Code.appBackgrounded
            )
            // BOUNDED TOR KEEP-ALIVE (2026-10-23) — decided FIRST, before the
            // lock below wipes the device key its tier read needs. true = a
            // healthy Tor is kept for the background-task budget (AppState
            // "Bounded Tor keep-alive"): nothing below may stop it or exit;
            // the keep-alive's own deadline does both, and only while the app
            // is still in the background. false = exactly the old path. The
            // vault lock + key wipe + RAM scrubs below run identically either
            // way — the keep-alive defers ONLY the Tor teardown and the exit.
            let keepingTor = appState.armTorKeepAliveOnBackground()
            if appState.isUnlocked {
                // lock() (state now != .active) also stops Tor unless it is
                // being kept; its working dir is deliberately PRESERVED for the
                // next launch's warm start (TorManager.preservesStateAcrossLaunches).
                lockAndResetNavigation()
            } else {
                // After a prior FOREGROUND idle auto-lock the vault
                // is already locked (isUnlocked=false) but Tor was left running,
                // so lock() is NOT called here to tear it down. On a genuine
                // background — never the transient `.inactive` (Face ID / Control
                // Center — the Lever-B re-lock lesson); this whole block is
                // `.background`-gated — stop Tor. The working dir under
                // <Caches>/tor is KEPT (guard + consensus reuse; the control
                // cookie and socket are still dropped, and the files carry
                // NSFileProtectionComplete) — see
                // TorManager.preservesStateAcrossLaunches. Idempotent if Tor was
                // already stopped.
                //
                // Since the speculative launch-time start (connect-speed lever
                // 2, AppState.startSpeculativeTor) this branch also covers the
                // NEVER-UNLOCKED backgrounding: the app was opened, Tor started
                // while the PIN screen was up, and the user left without
                // unlocking. A Connected speculative Tor is KEPT for the window
                // like any other (same benefit: a quick return skips the
                // bootstrap). Otherwise stopping a Tor that really ran latches
                // relaunchRequired, so the exit(0) below recycles the process
                // while it is invisible — correct and wanted, because tor_main
                // runs once per process and a recycle is the only way this app
                // can have Tor again.
                if !keepingTor { TorManager.shared.stop() }
                // This is the LOCKED
                // backgrounding — the one that `lock()`'s notification sweep can never
                // reach (every lock() call site is gated on a prior unlock),
                // while being exactly the state in which a push wake posts a
                // "Notification" banner. Those DELIVERED records live outside the
                // sandbox in a standard forensic-parser target, so sweep them
                // here too. Cheap, local-only, idempotent.
                appState.sweepDeliveredNotificationsWhileLocked()
                // A5-1 sibling: this is the PRE-UNLOCK backgrounding, the one
                // lock() can never reach (every lock() call site is gated on a
                // prior unlock) — and it is exactly the window in which the
                // new phone holds a scanned transfer handle: scanned by
                // MoveFromDeviceView, then the whole PIN/passphrase onboarding
                // runs before the first unlock consumes it. Left alone, a read
                // capability plus the one-time code that decrypts the old
                // phone's whole exported vault sat in the RAM of a backgrounded,
                // never-unlocked process. Android drops it on every background
                // (onStop -> finishAndRemoveTask -> onCleared -> lockSession);
                // this is that parity. Safe direction: the bundle still sits on
                // the relay for its TTL and ContentView routes a nil handle back
                // to MoveFromDeviceView, so the user rescans (or the old phone
                // re-issues) — nothing is exported and no vault is touched.
                appState.pendingMoveHandle = nil
            }
            // External SOCKS proxy mode: no embedded Tor ever ran, so nothing
            // latches relaunchRequired — recycle anyway, for parity with the
            // embedded-Tor process (which recycles on every background it is
            // not kept across, via the stop() latch) and so a proxy setting
            // changed in Settings takes effect on the user's next open
            // ("applies at next launch"). External mode is never kept.
            //
            // Kept Tor ⇒ NO exit here: the process stays alive (vault locked)
            // for the window, and the keep-alive's deadline exits it only if it
            // is still invisible then — never a foregrounded process.
            if !keepingTor,
               TorManager.shared.relaunchRequired || ExternalProxyMode.shared.isExternalThisProcess {
                // Tor can never be re-initialized in this process (tor_main is
                // once-per-process; the thread is dead, terminally failed, or
                // stopped by the teardown above) — NEWNYM and Reconnect cannot
                // help. Exit while INVISIBLE so the user's next open gets a fresh
                // process with a working Tor: the manual force-quit users would
                // otherwise have to discover becomes an automatic, unnoticeable
                // recycle. Runs AFTER the lock/stop above (vault closed, keys
                // wiped, DB shut, Tor stopped — its working dir preserved for
                // the fresh process to start warm from).
                LogBuffer.shared.append(level: "W", tag: "ContentView", message: "backgrounded with Tor relaunch-required — recycling process")
                exit(0)
            }
    }

    /// The deadline half of [onAutoLockTick] with no scenePhase guard: locks iff the
    /// vault is unlocked and the periodic re-auth deadline has passed, or (release
    /// only, [includeIdle]) the Lever-C idle timeout has. Returns true when it locked.
    /// Called from the tick while `.inactive` (re-auth only) and synchronously at the
    /// top of handleSceneBecameActive (both). The re-auth deadline exists only after
    /// an unlock (armed in onUnlockedChanged, cleared on every lock), so a Lever-B
    /// unlock's Face ID `.inactive` can never meet a past-due one.
    ///
    /// Both locks are IN-SCENE (`lockAndResetNavigation(inForegroundScene: true)`):
    /// a re-auth fired while `.inactive` locks the vault but keeps Tor, exactly
    /// like the `.active` one, so the PIN-screen re-unlock reconnects without a
    /// relaunch. If the user then backgrounds instead, the `.background` handler's
    /// locked branch decides Tor as for any locked backgrounding (MAXIMUM: no
    /// keep-alive → stop + recycle).
    @discardableResult
    private func lockIfDeadlinePassed(includeIdle: Bool) -> Bool {
        guard appState.isUnlocked else { return false }
        if let deadline = reauthDeadlineUptime, ProcessInfo.processInfo.systemUptime >= deadline {
            lockCountdownSeconds = nil
            LogBuffer.shared.append(level: "W", tag: "ContentView", message: "periodic re-auth — locking vault")
            lockAndResetNavigation(inForegroundScene: true)
            return true
        }
        #if !DEBUG
        if includeIdle {
            let timeoutSeconds = Double(appState.controller.autoLockTimeoutMs()) / 1000.0
            if InactivityAutoLock.shared.idleSeconds >= timeoutSeconds {
                lockCountdownSeconds = nil
                LogBuffer.shared.append(level: "W", tag: "ContentView", message: "inactivity auto-lock — locking vault")
                lockAndResetNavigation(inForegroundScene: true)
                return true
            }
        }
        #endif
        return false
    }

    /// One auto-lock timer tick: Lever C idle lock + periodic re-auth + countdown.
    private func onAutoLockTick() {
        // `.inactive` (Control Center, app switcher, a system prompt): the scene
        // is still on screen behind the privacy cover, so an OVERDUE re-auth
        // fires here too — otherwise holding the scene `.inactive` would keep
        // the vault unlocked without bound. Lever C stays `.active`-only (no
        // touches can reach the app while `.inactive`; the return to `.active`
        // checks it). Never `.background`: that path locks on its own.
        if scenePhase == .inactive {
            lockCountdownSeconds = nil
            lockIfDeadlinePassed(includeIdle: false)
            return
        }
        // Shared guard for BOTH Lever C (idle auto-lock, D4) and the
        // periodic re-auth timer (docs/periodic-reauth-design.md) below —
        // neither may fire in `.background` or pre-unlock.
        guard scenePhase == .active, appState.isUnlocked else {
            lockCountdownSeconds = nil
            return
        }

        // Lever C (idle auto-lock, D4) measures pure touch-idle, which is
        // fundamentally incompatible with UI automation: WDIO/XCUITest
        // drives the app via accessibility queries that generate NO touch
        // events, so the e2e's multi-minute no-touch Tor waits
        // (waitForRelayWarm, mint, message delivery) would trip the 2-min
        // lock and tear the session down. Debug/e2e builds therefore skip
        // it; RELEASE keeps the full 2-min auto-lock. This is now the
        // ONLY branch still compiled out of DEBUG — the periodic re-auth
        // below runs in EVERY build; see ReauthPolicy.isEnabled's own
        // debug-off-by-default gate, which a release binary can never
        // override.
        var leverCRemaining = Double.infinity
        #if !DEBUG
        // iOS half of "modals must feed the idle
        // clock": the catch-all touch recognizer is installed per WINDOW, and
        // was only (re)installed on a scenePhase→active transition. A window
        // created LATER while the app stays active — a UIAlertController-backed
        // alert, a share sheet — carried no recognizer, so touches inside it
        // read as idle and the auto-lock could fire mid-interaction. Re-running
        // the install each tick is idempotent (it skips windows that already
        // have one) and covers any window that appeared since.
        InactivityAutoLock.shared.installOnWindows()
        // Per-level auto-lock (threat-level slider); a legacy vault keeps the current default.
        let timeoutSeconds = Double(appState.controller.autoLockTimeoutMs()) / 1000.0
        leverCRemaining = timeoutSeconds - InactivityAutoLock.shared.idleSeconds
        #endif

        // Periodic random re-auth at MAXIMUM (docs/periodic-reauth-design.md):
        // "since unlock", not "active time" — reauthDeadlineUptime is a fixed
        // instant armed once per unlock (isUnlocked onChange below) and never
        // moves; nothing here resets it on a touch.
        var reauthRemaining = Double.infinity
        if let deadline = reauthDeadlineUptime {
            reauthRemaining = deadline - ProcessInfo.processInfo.systemUptime
        }

        let reauthIsNearer = reauthRemaining <= leverCRemaining
        let remaining = reauthIsNearer ? reauthRemaining : leverCRemaining

        if remaining <= 0 {
            lockCountdownSeconds = nil
            if reauthIsNearer {
                LogBuffer.shared.append(level: "W", tag: "ContentView", message: "periodic re-auth — locking vault")
            } else {
                LogBuffer.shared.append(level: "W", tag: "ContentView", message: "inactivity auto-lock — locking vault")
            }
            lockAndResetNavigation(inForegroundScene: true)
            return
        }
        // Warning countdown (threat-slider spec, 2026-07-16; re-auth copy per
        // docs/periodic-reauth-design.md): shown for the last WARNING_MS INSIDE
        // the nearer window — the deadline never moves (a grace period would
        // widen the D4 exposure bound / defeat the re-auth's hard bound). A
        // touch resets the IDLE clock via the catch-all recognizer, which only
        // affects Lever C; the next tick hides the overlay again once neither
        // is close.
        let warningSeconds = Double(ReauthPolicy.shared.WARNING_MS) / 1000.0
        if remaining <= warningSeconds {
            lockCountdownSeconds = Int(remaining.rounded(.up))
            lockCountdownIsReauth = reauthIsNearer
        } else {
            lockCountdownSeconds = nil
        }
        // Near the deadline, tick at 1 s — that drives the countdown AND makes
        // the lock punctual (the coarse 10 s poll alone could fire it up to
        // ~10 s late). Swapping the @State publisher restarts the cadence,
        // which is safe here: swaps happen only on zone TRANSITIONS, never
        // every tick, so this cannot starve the lock the way the per-re-init
        // recreation M4 fixed could.
        let wantFine = remaining <= Double(CredentialPolicy.shared.AUTO_LOCK_FINE_WINDOW_MS) / 1000.0
        if wantFine != autoLockFineTicks {
            autoLockFineTicks = wantFine
            autoLockTimer = Timer.publish(
                every: Double(wantFine
                    ? CredentialPolicy.shared.AUTO_LOCK_FINE_CHECK_INTERVAL_MS
                    : CredentialPolicy.shared.AUTO_LOCK_CHECK_INTERVAL_MS) / 1000.0,
                on: .main, in: .common
            ).autoconnect()
        }
    }

    /// `appState.isUnlocked` changed.
    private func onUnlockedChanged(_ unlocked: Bool) {
        // If the unlock COMPLETED while we're not in the
        // foreground (the user backgrounded during the off-thread Argon2 unlock),
        // the .background handler above couldn't lock — isUnlocked was still false
        // then — so the vault would sit UNLOCKED in the background and render with
        // no PIN on next foreground. Lock immediately instead of proceeding.
        //
        // Gate on `.background`, NOT `!= .active`: Lever B's unlock unwraps the DB
        // key through a Secure-Enclave key that requires a Face ID / passcode
        // prompt, and that system prompt drives the scene to `.inactive` WHILE the
        // off-thread unlock finishes — so on every auth-bound unlock `isUnlocked`
        // flips true during `.inactive`. `!= .active` therefore re-locked the vault
        // the instant it opened, making a Lever-B vault impossible to enter. A
        // transient `.inactive` (Face ID, Control Center, call banner) is not "sitting
        // unlocked in the background": its content is already hidden by
        // .privacyCovered(), and a genuine background still locks — via the
        // scenePhase→.background handler above (if isUnlocked was already true) or
        // via this handler (if isUnlocked flips true once we're actually
        // `.background`). So only `.background` should force the re-lock.
        if !unlocked {
            // Periodic re-auth (docs/periodic-reauth-design.md): the deadline
            // must be nil whenever the vault is locked, and
            // lockAndResetNavigation() is NOT the only way to get there.
            // `AppState.lock()` is also called directly from
            // `controller.onVaultSessionRetired` (AppState.swift — a re-key
            // that did not verifiably commit), and `emergencyWipe()` sets
            // `isUnlocked = false` itself; neither goes through this view, so
            // both used to leave an ALREADY-PAST deadline sitting in @State.
            // The `.onReceive` guard makes that inert only while
            // `isUnlocked` is false — it does NOT cover the window between
            // the NEXT unlock's `isUnlocked = true` and the `if unlocked`
            // re-arm below, and SwiftUI gives no ordering guarantee between a
            // main-run-loop Timer delivery and the view update that carries
            // this handler. A tick landing in that window would read
            // `remaining <= 0` and re-lock the vault the instant it opened.
            // Clearing on the lock TRANSITION closes it from one place, for
            // every lock path, present and future: the deadline is nil for
            // the whole locked stretch, so there is nothing stale to fire.
            // (Fails safe either way — the re-arm below is unconditional on
            // the next unlock.) AppState is deliberately untouched: the
            // design keeps the deadline entirely in this view.
            reauthDeadlineUptime = nil
        }
        if unlocked && scenePhase == .background {
            lockAndResetNavigation()
            return
        }
        if unlocked {
            // A fresh unlock starts a fresh idle window (the unlock itself may
            // have involved no touches on our windows — e.g. Face ID).
            InactivityAutoLock.shared.touch()
            // Periodic random re-auth at MAXIMUM (docs/periodic-reauth-design.md):
            // draw a fresh deadline on EVERY unlock — a re-auth's own re-unlock
            // is itself an unlock, so "after every successful auth" and "on
            // every unlock" coincide. Tier gate is re-read here (reauthEnabled(),
            // not cached), so a mid-session tier change takes effect on the next
            // unlock.
            reauthDeadlineUptime = appState.controller.reauthEnabled()
                ? ProcessInfo.processInfo.systemUptime + Double(appState.controller.nextReauthIntervalMs()) / 1000.0
                : nil
        }
    }
}

/// The full-screen black gate notice (device-compromised gate, no-passcode warning):
/// icon, title, message, then the caller's buttons as direct VStack children. Ids and
/// `.containerA11yId` stay at the call site.
private struct GateNoticeScreen<Actions: View>: View {
    let icon: String
    let tint: Color
    let title: String
    let message: String
    let actions: Actions

    init(icon: String, tint: Color, title: String, message: String,
         @ViewBuilder actions: () -> Actions) {
        self.icon = icon
        self.tint = tint
        self.title = title
        self.message = message
        self.actions = actions()
    }

    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()
            VStack(spacing: 16) {
                Image(systemName: icon)
                    .font(.system(size: 48))
                    .foregroundColor(tint)
                Text(title)
                    .font(.runeHeadline)
                    .foregroundColor(.white)
                Text(message)
                    .font(.runeFootnote)
                    .foregroundColor(.gray)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)
                actions
            }
        }
    }
}

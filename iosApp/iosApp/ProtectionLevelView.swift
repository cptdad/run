import SwiftUI
import shared
import UIKit
import LocalAuthentication

// ---------------------------------------------------------------------------
// Threat-level slider UI (iOS mirror of Android's ProtectionLevelScreen /
// RecoveryCodeScreen / RecoveryEntryScreen). Levels are bridged as their storage
// strings ("casual"/"private"/"maximum"). Private needs a Secure Enclave; without
// one it shows greyed + non-selectable (spec #8).
// ---------------------------------------------------------------------------

private struct LevelCard: Identifiable {
    let id: String            // storage value ("casual"/"private"/"maximum")
    let runestone: String     // per-level art (plain → base ring → full forcefield)
}

// Tier display names + taglines are single-sourced in shared ProtectionLevelContent
// (keyed by storageValue) so Android and iOS never drift; only the art lives here.
private let levelCards: [LevelCard] = [
    LevelCard(id: "casual", runestone: "runestone_dim"),
    LevelCard(id: "private", runestone: "runestone_dim_ring"),
    LevelCard(id: "maximum", runestone: "runestone_dim_forcefield"),
]

// Device base security panel — temporarily disabled (2026-07-28) at the product's
// request. The panel code (DevicePanel + DeviceBaseline detection below) is kept
// intact; flip this to true to bring it back in "Choose your protection".
private let showDeviceBaselinePanel = false

/// The protection tier that HONESTLY reflects the key actually backing the
/// vault, given the [chosen] tier and whether its Lever B auth-binding
/// actually engaged. A hardened tier (PRIVATE ⇒ Lever B / Secure-Enclave
/// auth-bound DB key) is honest only when Lever B is really on; otherwise the
/// DB key is plain-wrapped and the honest tier is CASUAL. MAXIMUM never uses
/// Lever B (its strength is the passphrase instead), so it is always honest
/// regardless of [leverBEnabled]. Persisting THIS — rather than the raw
/// chosen tier — keeps "persisted tier <= what the key backs"
/// (tier atomicity): a cancelled biometric or a failed enable settles in
/// the under-claiming (safe) direction, never the dangerous
/// PRIVATE-labelled-but-plain-keyed over-claim. Mirrors Android's
/// `honestPersistedLevel` (ProtectionLevelSettingsScreen.kt); shared by
/// onboarding (PinSetupView) and Settings (ProtectionLevelSettingsView) here.
func honestPersistedLevel(_ chosen: String, leverBEnabled: Bool) -> String {
    (chosen == "private" && !leverBEnabled) ? "casual" : chosen
}

struct ProtectionLevelView: View {
    @EnvironmentObject private var appState: AppState
    let hardwareSupported: Bool
    let currentLevel: String?          // nil = onboarding (bare-forced); non-nil = Settings
    let confirmLabel: String
    let onConfirm: (String) -> Void
    var onBack: (() -> Void)? = nil

    @State private var selected: String?
    /// A tier the user did not choose has to be acknowledged before it applies —
    /// it brings a 7-day inactivity self-wipe with it.
    @State private var showForcedNotice = false
    /// Continuous slider position (the draggable thumb), in [0, levelCards.count-1].
    /// Drives the hero morph — the runestone cross-fades between adjacent tier
    /// images as the thumb slides. Starts on the pre-selected stop (or the first
    /// stone when nothing is picked yet, so the chooser is never blank).
    @State private var pos: Double
    @State private var dragging = false

    init(hardwareSupported: Bool, currentLevel: String?, confirmLabel: String,
         onConfirm: @escaping (String) -> Void, onBack: (() -> Void)? = nil) {
        self.hardwareSupported = hardwareSupported
        self.currentLevel = currentLevel
        self.confirmLabel = confirmLabel
        self.onConfirm = onConfirm
        self.onBack = onBack
        _selected = State(initialValue: currentLevel)
        let idx = currentLevel.flatMap { c in levelCards.firstIndex { $0.id == c } } ?? 0
        _pos = State(initialValue: Double(idx))
    }

    private var selectedIndex: Int? { selected.flatMap { s in levelCards.firstIndex { $0.id == s } } }

    /// Both greyed-stop rules — the device-lock floor and Private's hardware
    /// requirement — decided by shared code (DeviceLockPolicy), so iOS and
    /// Android can't drift on which tiers a device may pick.
    private func disabled(_ i: Int) -> Bool {
        !appState.controller.isProtectionLevelSelectable(
            level: levelCards[i].id, passcodeAbsent: passcodeNotSet, leverBSupported: hardwareSupported)
    }

    /// Non-nil when this phone has NO passcode: the device key then falls back to
    /// AfterFirstUnlock (KeychainHelper logs the downgrade) and is readable in any
    /// AFU extraction, so only the passphrase tier still protects the vault.
    private var forcedLevel: String? {
        appState.controller.forcedProtectionLevel(passcodeAbsent: passcodeNotSet)
    }

    /// The reason a greyed tier can't be picked — shown ONLY when the CHOSEN /
    /// displayed tier (the thumb's current stop) is itself unavailable, prefixed with
    /// "Not possible to select level." Copy lives in shared code: a stop the user can
    /// act on must name the fix.
    private var stopReason: String? {
        let idx = liveDisplayIndex
        guard idx >= 0, idx < levelCards.count,
              let reason = appState.controller.protectionLevelStopReason(
                level: levelCards[idx].id, passcodeAbsent: passcodeNotSet, leverBSupported: hardwareSupported)
        else { return nil }
        return "\(ProtectionLevelContent.shared.stopReasonPrefix) \(reason)"
    }

    /// True ONLY when the device DEFINITELY has no passcode (same fail-closed
    /// check as ContentView's setup warning). Distinguishes the user-fixable
    /// cause of a greyed Private stop (no passcode — the SE key needs one) from
    /// genuinely missing Secure Enclave hardware.
    private var passcodeNotSet: Bool {
        var err: NSError?
        LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: &err)
        return err?.code == LAError.passcodeNotSet.rawValue
    }

    /// Which stop the detail panel + label highlight track: the thumb live while
    /// dragging (round(pos)), the committed selection at rest (-1 = none yet).
    private var liveDisplayIndex: Int {
        dragging ? min(max(Int(pos.rounded()), 0), levelCards.count - 1) : (selectedIndex ?? -1)
    }

    /// Apply is enabled only when a tier is picked AND it is actually selectable on
    /// this device — the thumb can now rest on a greyed stop, which must not commit.
    private var canApply: Bool { selected.map { isSelectableId($0) } ?? false }

    /// Selectability by storageValue (the slider is string-keyed) — same shared
    /// DeviceLockPolicy decision as `disabled`, exposed for the Apply gate.
    private func isSelectableId(_ id: String) -> Bool {
        appState.controller.isProtectionLevelSelectable(
            level: id, passcodeAbsent: passcodeNotSet, leverBSupported: hardwareSupported)
    }

    var body: some View {
        ZStack {
            Color.runBackground.ignoresSafeArea()
            ScrollView {
                VStack(spacing: 16) {
                    Text(ProtectionLevelContent.shared.title)
                        .font(.runeTitle2).fontWeight(.semibold)
                        .foregroundColor(.runTextPrimary)
                        .multilineTextAlignment(.center)
                        .accessibilityIdentifier("protection_level_title")

                    // Hero: bare (Decent) → shielded (Secure) → chained + locked
                    // (Maximum). Two stacked runestones, the upper at opacity=frac, so
                    // sliding cross-fade-MORPHS the ring/forcefield in — opaque, aligned
                    // PNGs make a whole-frame dissolve read as a morph.
                    ZStack {
                        let last = levelCards.count - 1
                        let p = min(max(pos, 0), Double(last))
                        let lo = Int(p.rounded(.down))
                        let hi = Int(p.rounded(.up))
                        Image(levelCards[lo].runestone)
                            .resizable().scaledToFit()
                            .frame(maxWidth: .infinity).frame(height: 250)
                        if hi != lo {
                            Image(levelCards[hi].runestone)
                                .resizable().scaledToFit()
                                .frame(maxWidth: .infinity).frame(height: 250)
                                .opacity(p - Double(lo))
                        }
                    }
                    .frame(height: 250)
                    .clipShape(RoundedRectangle(cornerRadius: 18))
                    .accessibilityIdentifier("protection_level_runestone")
                    .accessibilityLabel(L10n.protectionLevelAccessibilityLabel(ProtectionLevelContent.shared.displayName(storageValue: levelCards[min(max(Int(pos.rounded()), 0), levelCards.count - 1)].id)))

                    LevelSlider(pos: $pos, dragging: $dragging, displayIndex: liveDisplayIndex,
                                disabled: disabled,
                                onSelect: { i in selected = levelCards[i].id })

                    if let stopReason = stopReason {
                        Text(stopReason)
                            .font(.runeCaption).foregroundColor(Color(hex: 0xD4463A)).multilineTextAlignment(.center)
                            .accessibilityIdentifier("protection_level_stop_reason")
                    }

                    Group {
                        if liveDisplayIndex >= 0 {
                            // Name is already on the slider label above — show the tagline.
                            Text(ProtectionLevelContent.shared.tagline(storageValue: levelCards[liveDisplayIndex].id))
                                .font(.runeCaption).foregroundColor(.runTextSecondary)
                                .multilineTextAlignment(.center)
                                .frame(maxWidth: .infinity, alignment: .center)
                        } else {
                            Text(ProtectionLevelContent.shared.emptyState)
                                .font(.runeFootnote).foregroundColor(.runTextSecondary).frame(maxWidth: .infinity, alignment: .center)
                        }
                    }
                    .padding(16).background(Color.runSurface).clipShape(RoundedRectangle(cornerRadius: 14))

                    if showDeviceBaselinePanel {
                        DevicePanel(hardwareSupported: hardwareSupported)
                    }

                    Button(action: {
                        // A tier the user did not choose has to be acknowledged first.
                        if forcedLevel != nil { showForcedNotice = true }
                        else if let s = selected { onConfirm(s) }
                    }) {
                        // ONE line, never a mid-word break (2026-09-11): shrink to fit instead.
                        Text(selected == nil ? L10n.protectionPickALevel : confirmLabel)
                            .lineLimit(1)
                            .minimumScaleFactor(0.5)
                            .fontWeight(.semibold).frame(maxWidth: .infinity).padding()
                            .background(canApply ? Color.runTextPrimary : Color.runSurface)
                            .foregroundColor(canApply ? .runBackground : .runTextSecondary)
                            .clipShape(RoundedRectangle(cornerRadius: 12))
                    }
                    .disabled(!canApply)
                    .accessibilityIdentifier("protection_level_confirm")

                    if let onBack = onBack {
                        Button(L10n.commonCancel, action: onBack)
                            .foregroundColor(.runTextSecondary)
                            .accessibilityIdentifier("protection_level_back")
                    }
                }
                .padding(.horizontal, 24)
                .padding(.top, 20)
            }
        }
        // The forced tier is pre-selected (it is the only selectable stop, so an
        // empty slider would just be a dead end). Done in onAppear, not init:
        // the environment isn't available yet when the State is seeded.
        .onAppear {
            if let forced = forcedLevel {
                selected = forced
                if let fi = levelCards.firstIndex(where: { $0.id == forced }) { pos = Double(fi) }
            }
        }
        // Forced-tier notice. The security half is one sentence; the rest is the
        // COST, stated as what happens to the user rather than as a mechanism —
        // and the 7-day erase is body text with its own acknowledgment, not a
        // footnote, because it is the one irreversible consequence of a tier
        // they did not pick. The way out (set a passcode) is named in the same
        // breath, and the reflex-safe left slot is the non-committing one.
        .runeDialog(
            isPresented: $showForcedNotice,
            title: ProtectionLevelContent.shared.forcedNoticeTitle,
            message: ProtectionLevelContent.shared.forcedNoticeBody,
            a11yId: "protection_forced_notice",
            // Consent gate: no scrim dismissal. Two independent things were
            // otherwise tapping this dialog away behind our backs — the e2e
            // keep-alive poke target (a root overlay, so it sits ABOVE the
            // dialog and its tap lands on the scrim) and any scroll gesture.
            // A forced tier must be answered, not dismissed, anyway.
            dismissable: false,
            actions: [
                .secondary(L10n.commonNotNow, a11yId: "protection_forced_cancel") { },
                RuneDialogAction(L10n.commonUnderstood, a11yId: "protection_forced_ack") {
                    // Confirm the FORCED level, recomputed here, rather than the
                    // @State `selected`. The dialog only opens when the tier is
                    // forced, so this is the same value by construction — and it
                    // cannot be nil the way a state read captured into a stored
                    // action array can be (observed on device: the ack tapped,
                    // the dialog closed, and nothing advanced, six times over).
                    onConfirm(forcedLevel ?? selected ?? "maximum")
                },
            ]
        )
    }
}

// MARK: - The dynamic (draggable) three-stop slider

private struct LevelSlider: View {
    @Binding var pos: Double
    @Binding var dragging: Bool
    let displayIndex: Int
    let disabled: (Int) -> Bool
    let onSelect: (Int) -> Void

    private var n: Int { levelCards.count }

    var body: some View {
        // Force LTR on the whole control (track, stops, thumb, AND labels
        // together): centreX/xToPos and the drag maths operate on raw view
        // coordinates, so under an auto-mirrored RTL HStack the visual stops
        // and the math would disagree (thumb tracks the wrong stop; drag runs
        // backwards). A continuous slider position is direction-agnostic the
        // same way the PIN keypad is — forcing LTR here keeps thumb, stops,
        // drag, and the labels underneath all consistent, rather than making
        // three separate call sites (track math, thumb position, drag
        // gesture) individually RTL-aware. Mirrors the Android LevelSlider fix.
        content
            .environment(\.layoutDirection, .leftToRight)
    }

    private var content: some View {
        VStack(spacing: 6) {
            GeometryReader { geo in
                let width = geo.size.width
                let count = CGFloat(n)
                // Stop i centre sits at (i+0.5)/N of the width; pos maps the same way,
                // so the thumb, the drag maths, and the hero blend all agree.
                let centreX: (Double) -> CGFloat = { p in (CGFloat(p) + 0.5) / count * width }
                let xToPos: (CGFloat) -> Double = { x in
                    min(max(Double(x / width * count - 0.5), 0), Double(n - 1))
                }
                let landed = min(max(Int(pos.rounded()), 0), n - 1)
                let thumbWhite = dragging || !disabled(landed)

                ZStack(alignment: .leading) {
                    // Track line — spans the outer dot centres ((N-1)/N of the width).
                    Rectangle().fill(Color(hex: 0x2A313C))
                        .frame(width: width * (count - 1) / count, height: 2)
                        .position(x: width / 2, y: 15)

                    // Fixed anchor stops: full-height tap targets keeping their
                    // level_${id} a11y ids (the cross suites tap these to pick a tier).
                    HStack(spacing: 0) {
                        ForEach(levelCards.indices, id: \.self) { i in
                            let off = disabled(i)
                            Button(action: { select(i) }) {
                                Circle()
                                    .fill(off ? Color(hex: 0x20262F) : Color(hex: 0x3A424E))
                                    .frame(width: 8, height: 8)
                                    .frame(maxWidth: .infinity, minHeight: 30)
                                    .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                            .accessibilityIdentifier("level_\(levelCards[i].id)")
                        }
                    }

                    // Draggable thumb — white while dragging / at rest on a selectable
                    // tier, grey when it rests on an unavailable one. Non-interactive
                    // (allowsHitTesting false) so it never shadows a stop button's tap;
                    // the drag rides on the container's simultaneousGesture below, whose
                    // 8pt minimum keeps a quick a11y tap flowing to the buttons.
                    Circle()
                        .fill(thumbWhite ? Color.runTextPrimary : Color(hex: 0x606A76))
                        .overlay(Circle().stroke(thumbWhite ? Color.runTextPrimary : Color(hex: 0x2A313C), lineWidth: 2))
                        .frame(width: 22, height: 22)
                        .position(x: centreX(pos), y: 15)
                        .allowsHitTesting(false)
                }
                .coordinateSpace(name: "sliderTrack")
                .contentShape(Rectangle())
                .simultaneousGesture(
                    DragGesture(minimumDistance: 8, coordinateSpace: .named("sliderTrack"))
                        .onChanged { v in
                            dragging = true
                            pos = xToPos(v.location.x)
                        }
                        .onEnded { v in
                            dragging = false
                            let target = min(max(Int(xToPos(v.location.x).rounded()), 0), n - 1)
                            withAnimation(.easeOut(duration: 0.18)) { pos = Double(target) }
                            onSelect(target)
                        }
                )
            }
            .frame(height: 30)

            HStack(spacing: 0) {
                ForEach(levelCards.indices, id: \.self) { i in
                    Text(ProtectionLevelContent.shared.displayName(storageValue: levelCards[i].id))
                        .font(.system(size: 10))
                        .foregroundColor(disabled(i) ? Color(hex: 0x606A76) : (displayIndex == i ? .runTextPrimary : .runTextSecondary))
                        .frame(maxWidth: .infinity)
                }
            }
        }
    }

    private func select(_ i: Int) {
        withAnimation(.easeOut(duration: 0.18)) { pos = Double(i) }
        onSelect(i)
    }
}

// MARK: - Device baseline panel (this actual iPhone)

private struct DevicePanel: View {
    let hardwareSupported: Bool

    private var osLabel: String { "iOS \(UIDevice.current.systemVersion)" }
    private var lockSet: Bool {
        var err: NSError?
        return LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: &err)
    }
    private var baseline: DeviceBaselineTier {
        DeviceBaseline.shared.assess(lockSet: lockSet, secureElement: hardwareSupported, patchesCurrent: true)
    }

    @State private var expanded = false

    var body: some View {
        let sevColor = DeviceBaseline.shared.severity(t: baseline) == "bad" ? Color(hex: 0xE0524A) : Color(hex: 0xD9A441)
        let fill = Int(DeviceBaseline.shared.fill(t: baseline))
        VStack(alignment: .leading, spacing: 0) {
            // Header — always visible; tap to expand. The tier label is an at-a-glance
            // status, keeping the chooser short by default.
            Button(action: { withAnimation(.easeInOut(duration: 0.2)) { expanded.toggle() } }) {
                HStack {
                    Text(L10n.protectionDevicePanelTitle).font(.system(size: 12)).fontWeight(.medium).foregroundColor(.runTextPrimary)
                    Spacer()
                    Text(DeviceBaseline.shared.label(t: baseline))
                        .font(.system(size: 11, design: .monospaced)).fontWeight(.semibold).foregroundColor(sevColor)
                    // chevron.forward (not chevron.right): auto-mirroring under RTL
                    // to point toward reading-start, matching chevron.backward above.
                    Image(systemName: expanded ? "chevron.down" : "chevron.forward")
                        .font(.system(size: 10)).foregroundColor(Color(hex: 0x808A96)).padding(.leading, 8)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityIdentifier("device_baseline_toggle")

            if expanded {
                VStack(alignment: .leading, spacing: 9) {
                    HStack(spacing: 8) {
                        Text(L10n.protectionDevicePanelDetectedLabel).font(.system(size: 8.5, design: .monospaced)).foregroundColor(Color(hex: 0x606A76))
                        Text(L10n.protectionDevicePanelDetectedValue(iosDeviceName(), osLabel)).font(.system(size: 10.5, design: .monospaced)).foregroundColor(.runTextSecondary)
                    }
                    Rectangle().fill(Color(hex: 0x20262F)).frame(height: 1)
                    HStack {
                        Text(L10n.protectionDevicePanelBaselineLabel).font(.system(size: 8.5, design: .monospaced)).foregroundColor(Color(hex: 0x606A76))
                        Spacer()
                        HStack(spacing: 3) {
                            ForEach(0..<4, id: \.self) { i in
                                RoundedRectangle(cornerRadius: 2)
                                    .fill(i < fill ? sevColor : Color(hex: 0x2A313C))
                                    .frame(width: 15, height: 5)
                            }
                        }
                    }
                    Text(DeviceBaseline.shared.note(t: baseline)).font(.system(size: 11)).foregroundColor(.runTextSecondary)
                    Text(DeviceBaseline.shared.CAVEAT).font(.system(size: 9.5)).foregroundColor(Color(hex: 0x606A76))
                }
                .padding(.top, 11)
            }
        }
        .padding(12).frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.runSurface).clipShape(RoundedRectangle(cornerRadius: 10))
        .accessibilityIdentifier("device_baseline_panel")
    }
}

// Machine identifier → marketing name (recent iPhones), fallback to the identifier.
private func iosDeviceName() -> String {
    var sysinfo = utsname()
    uname(&sysinfo)
    let id = Mirror(reflecting: sysinfo.machine).children.reduce(into: "") { acc, el in
        if let v = el.value as? Int8, v != 0 { acc.append(Character(UnicodeScalar(UInt8(v)))) }
    }
    let map: [String: String] = [
        "iPhone12,1": "iPhone 11", "iPhone12,3": "iPhone 11 Pro", "iPhone12,5": "iPhone 11 Pro Max",
        "iPhone12,8": "iPhone SE (2nd gen)", "iPhone13,1": "iPhone 12 mini", "iPhone13,2": "iPhone 12",
        "iPhone13,3": "iPhone 12 Pro", "iPhone13,4": "iPhone 12 Pro Max", "iPhone14,4": "iPhone 13 mini",
        "iPhone14,5": "iPhone 13", "iPhone14,2": "iPhone 13 Pro", "iPhone14,3": "iPhone 13 Pro Max",
        "iPhone14,6": "iPhone SE (3rd gen)", "iPhone14,7": "iPhone 14", "iPhone14,8": "iPhone 14 Plus",
        "iPhone15,2": "iPhone 14 Pro", "iPhone15,3": "iPhone 14 Pro Max", "iPhone15,4": "iPhone 15",
        "iPhone15,5": "iPhone 15 Plus", "iPhone16,1": "iPhone 15 Pro", "iPhone16,2": "iPhone 15 Pro Max",
    ]
    return map[id] ?? (id.isEmpty ? "iPhone" : id)
}

// MARK: - Recovery code display (after Lever B enable)

struct RecoveryCodeView: View {
    let code: String
    let onDone: () -> Void
    @State private var acknowledged = false
    @State private var showAckHint = false

    private var grouped: String { Base32.shared.formatGrouped(code: code, group: 4, separator: "-") }

    var body: some View {
        ZStack {
            Color.runBackground.ignoresSafeArea()
            ScrollView {
                VStack(spacing: 16) {
                    Text(L10n.protectionRecoveryCodeTitle)
                        .font(.runeTitle2).fontWeight(.semibold)
                        .foregroundColor(.runTextPrimary)
                        .accessibilityIdentifier("recovery_code_title")
                    Text(L10n.protectionRecoveryCodeBodyIos)
                        .font(.runeFootnote)
                        .foregroundColor(.runTextSecondary)
                        .multilineTextAlignment(.center)

                    Text(grouped)
                        .font(.system(.title3, design: .monospaced))
                        .foregroundColor(.runTextPrimary)
                        .multilineTextAlignment(.center)
                        .padding(20)
                        .frame(maxWidth: .infinity)
                        .background(Color.runSurface)
                        .clipShape(RoundedRectangle(cornerRadius: 14))
                        .accessibilityIdentifier("recovery_code_value")

                    Toggle(isOn: $acknowledged) {
                        Text(L10n.protectionRecoveryAckLabel).foregroundColor(.runTextPrimary)
                    }
                    .tint(Color(hex: 0xD4463A))
                    .accessibilityIdentifier("recovery_ack_toggle")

                    // Stays tappable even before the toggle is on, so a tap surfaces
                    // the hint below instead of silently doing nothing (the reported bug).
                    Button(action: { if acknowledged { onDone() } else { showAckHint = true } }) {
                        // ONE line, never a mid-word break (2026-09-11): shrink to fit instead.
                        Text(L10n.commonContinue)
                            .lineLimit(1)
                            .minimumScaleFactor(0.5)
                            .fontWeight(.semibold)
                            .frame(maxWidth: .infinity).padding()
                            .background(acknowledged ? Color.runTextPrimary : Color.runSurface)
                            .foregroundColor(acknowledged ? .runBackground : .runTextSecondary)
                            .clipShape(RoundedRectangle(cornerRadius: 12))
                    }
                    .accessibilityIdentifier("recovery_done_button")
                    if showAckHint && !acknowledged {
                        Text(L10n.protectionRecoveryAckHintIos)
                            .font(.runeFootnote)
                            .foregroundColor(Color(hex: 0xD4463A))
                            .multilineTextAlignment(.center)
                            .accessibilityIdentifier("recovery_ack_hint")
                    }
                }
                .padding(.horizontal, 28).padding(.top, 28)
            }
        }
    }
}

// MARK: - Recovery code entry (lock-screen escape hatch)

struct RecoveryEntryView: View {
    @EnvironmentObject private var appState: AppState
    let onRecovered: () -> Void
    let onCancel: () -> Void
    @Environment(\.scenePhase) private var scenePhase

    @State private var code = ""
    @State private var credential = ""
    @State private var processing = false
    @State private var error: String?
    // This counter now
    // mirrors the DURABLE store PinEntryView uses (appState.controller.pinAttempts),
    // not a RAM-only per-session value — recovery guesses the SAME credential as the
    // lock screen, so both share one durable budget (reuse the shared attempt
    // store, never invent a separate RAM counter). See readAttempts()/attempt() below.
    @State private var recoveryAttempts = 0
    // Mirrors PinEntryView.counterDeferred: set when the durable store couldn't be
    // read because the device key was transiently unavailable. While set, the
    // pre-eval write is skipped so a stale 0 can't clobber a real durable count.
    @State private var counterDeferred = false
    // Same durable-count backoff as the lock screen (PinEntryView): the counter is
    // shared, so recovery entry must not be a backoff-free side door.
    @State private var backoff = UnlockBackoffGate()
    private let backoffTick = Timer.publish(every: 0.25, on: .main, in: .common).autoconnect()

    private var passphraseMode: Bool { appState.controller.isPassphraseMode() }
    private var maxAttempts: Int { Int(appState.controller.maxConsecutiveAttempts()) }

    /// Durable read of the SAME consecutive-attempt counter PinEntryView owns
    /// A dangling increment left by a force-quit
    /// mid-recovery is picked up here (or, after a real relaunch, by
    /// PinEntryView.readAttempts() on the very next onAppear) instead of starting
    /// back at zero. A genuine AEAD-tamper read (nil) wipes immediately, exactly
    /// like the lock screen; a transient key-unavailable read defers — never wipes
    /// — and skips the pre-eval write in attempt() below.
    ///
    /// Deliberately carries NO launch-time interrupted-wipe re-trigger, unlike its
    /// Android sibling RecoveryEntryScreen: this view's only presenter is
    /// PinEntryView's fullScreenCover, and PinEntryView.readAttempts() runs that
    /// check on appear AND again at the top of every submit, so a second copy here
    /// could not fire in any state the first one has not already covered (Android
    /// needs its own because Compose restores the "recover" route directly after
    /// process death). If one is ever added, it MUST compare against
    /// vaultSelector.maxConsecutiveAttemptsForInterruptedWipe(), never
    /// `maxAttempts` — that budget can shrink retroactively below a
    /// counter accumulated under the older, larger one, which would wipe a
    /// legitimate legacy vault on first launch after an upgrade.
    private func readAttempts() -> Int {
        counterDeferred = false
        guard UIApplication.shared.isProtectedDataAvailable else { counterDeferred = true; return 0 }
        do {
            guard let count = try appState.controller.pinAttempts.readOrNullOnTamper() else {
                appState.emergencyWipe()
                return 0
            }
            return count.intValue
        } catch {
            counterDeferred = true
            return 0
        }
    }

    private func attempt() {
        guard !processing, !backoff.active, !code.isEmpty, !credential.isEmpty else { return }
        processing = true; error = nil

        // Durable pre-eval write BEFORE
        // recoverWithCode's guaranteed 5s enforceChangePinDelay floor — mirrors
        // PinEntryView.handlePinComplete's tryWrite exactly, so force-quitting
        // inside that floor still leaves a counted attempt instead of a free,
        // uncounted guess.
        let attemptCount = recoveryAttempts + 1
        recoveryAttempts = attemptCount
        if !counterDeferred {
            _ = appState.controller.pinAttempts.tryWrite(count: Int32(attemptCount))
        }

        appState.recoverWithCode(code.trimmingCharacters(in: .whitespacesAndNewlines), credential: credential) { outcome in
            switch outcome {
            case .opened:
                appState.controller.pinAttempts.reset()
                onRecovered()
            case .denied:
                let windowExhausted = appState.controller.pinAttempts.recordWrongAttemptInWindowAndCheckLimit()
                if attemptCount >= maxAttempts || windowExhausted {
                    // Budget exhausted → crypto-erase. emergencyWipe flips AppState so
                    // ContentView drops to the black deniability screen.
                    appState.emergencyWipe()
                    processing = false
                    return
                }
                let credWord = passphraseMode ? L10n.protectionCredentialTypePassphrase : L10n.protectionCredentialTypePin
                error = L10n.protectionRecoveryWrongCredential(credWord)
                backoff.start(ms: CredentialPolicy.shared.unlockBackoffMs(failedAttempts: Int32(attemptCount)))
                processing = false
            // Recovery IS the escape hatch from a dead hardware key, so a
            // .recoveryRequired here has nowhere further to route the user — surface
            // it as the same retryable error rather than pointing back at recovery.
            case .error, .recoveryRequired:
                // Correct-credential path could not complete (no recovery code on file,
                // or a transient device-key outage) — NOT a wrong guess: roll back the
                // pre-eval increment (mirrors PinEntryView's .error/.recoveryRequired).
                let rolledBack = attemptCount - 1
                recoveryAttempts = rolledBack
                if !counterDeferred {
                    _ = appState.controller.pinAttempts.tryWrite(count: Int32(rolledBack))
                }
                error = L10n.protectionRecoveryGenericError
                processing = false
            }
        }
    }

    var body: some View {
        ZStack {
            Color.runBackground.ignoresSafeArea()
            VStack(spacing: 14) {
                Text(L10n.protectionRecoveryEntryTitle)
                    .font(.runeTitle2).fontWeight(.semibold)
                    .foregroundColor(.runTextPrimary)
                    .accessibilityIdentifier("recovery_entry_title")
                Text(L10n.protectionRecoveryEntrySubtitle(passphraseMode ? L10n.protectionCredentialTypePassphrase : L10n.protectionCredentialTypePin))
                    .font(.runeFootnote).foregroundColor(.runTextSecondary)
                    .multilineTextAlignment(.center)

                TextField(L10n.protectionRecoveryCodePlaceholder, text: $code)
                    .font(.system(.body, design: .monospaced))
                    .textFieldStyle(.plain)
                    .autocorrectionDisabled(true)
                    .textInputAutocapitalization(.characters)
                    // Autocorrection-off alone
                    // does not exclude a field from the QuickType lexicon — only a
                    // recognized secure contentType does (see PassphraseField above).
                    // .oneTimeCode keeps the code visible for typing off paper while
                    // still opting the field out of learning/cloud-synced suggestions.
                    .textContentType(.oneTimeCode)
                    .foregroundColor(.runTextPrimary)
                    .padding(14)
                    .background(Color.runSurface.opacity(0.4))
                    .clipShape(RoundedRectangle(cornerRadius: 10))
                    .accessibilityIdentifier("recovery_code_input")

                PassphraseField(placeholder: passphraseMode ? L10n.pinPassphrasePlaceholder : L10n.protectionCredentialTypePin,
                                text: $credential, identifier: "recovery_credential_input",
                                disabled: processing || backoff.active, onSubmit: attempt)

                if let error = error {
                    Text(error).font(.runeCaption).foregroundColor(.runError).multilineTextAlignment(.center)
                }
                if backoff.active {
                    Text(L10n.pinBackoffHint(backoff.secondsLeft))
                        .font(.runeCaption).foregroundColor(.runTextSecondary).multilineTextAlignment(.center)
                        .accessibilityIdentifier("pin_backoff_hint")
                }

                Spacer()

                Button(action: attempt) {
                    // ONE line, never a mid-word break (2026-09-11): shrink to fit instead.
                    Text(processing ? L10n.protectionRecoveryButtonRecovering : L10n.protectionRecoveryButtonRecover)
                        .lineLimit(1)
                        .minimumScaleFactor(0.5)
                        .fontWeight(.semibold)
                        .frame(maxWidth: .infinity).padding()
                        .background((code.isEmpty || credential.isEmpty || processing || backoff.active) ? Color.runSurface : Color.runTextPrimary)
                        .foregroundColor((code.isEmpty || credential.isEmpty || processing || backoff.active) ? .runTextSecondary : .runBackground)
                        .clipShape(RoundedRectangle(cornerRadius: 12))
                }
                .disabled(code.isEmpty || credential.isEmpty || processing || backoff.active)
                .accessibilityIdentifier("recovery_submit_button")

                Button(L10n.commonBack, action: onCancel)
                    .foregroundColor(.runTextSecondary)
                    .accessibilityIdentifier("recovery_cancel_button")
            }
            .padding(.horizontal, 28).padding(.top, 40).padding(.bottom, 24)
        }
        .onAppear {
            recoveryAttempts = readAttempts()
            backoff.start(ms: CredentialPolicy.shared.launchBackoffMs(persistedFailedAttempts: Int32(recoveryAttempts)))
        }
        .onReceive(backoffTick) { _ in
            if backoff.active { backoff.refresh() }
        }
        // Background-clear the typed
        // recovery code + credential — this screen had no scenePhase handler at
        // all, so both lingered in un-zeroable @State. Gated on .background only,
        // never the transient .inactive (Face ID / Control Center), per the
        // Lever-B re-lock rule — see ProtectionLevelSettingsView.body below, the
        // same pattern used for the same class of credential buffer in this file.
        .onChange(of: scenePhase) { newPhase in
            if newPhase == .background { code = ""; credential = "" }
        }
    }
}

// MARK: - Settings level-picker (change the tier after onboarding)
//
// The SINGLE security control: applies the TIMER tier immediately
// (setProtectionLevel — safe, already unlocked; a downgrade confirms first) AND
// drives the credential type (PIN ↔ passphrase) and the hardware auth-bound key
// (Lever B) inline, mirroring onboarding (spec #7). A Lever B enable that fails
// leaves the vault working at plain — nothing is bricked.

private enum LevelChangePhase { case pick, changeCred, enabling, showRecovery }

struct ProtectionLevelSettingsView: View {
    @EnvironmentObject private var appState: AppState
    let onDismiss: () -> Void
    /// Entered from the forced route (this device has no passcode, so the vault
    /// must move up to MAXIMUM — DeviceLockPolicy). [onDismiss] then means DONE,
    /// not "cancel": the chooser offers no way out, because leaving would drop
    /// the user into the app at a tier this device cannot honour. The way out is
    /// setting a device passcode, which retires the forcing on the next unlock —
    /// named in the chooser's own stop-reason copy.
    var forced: Bool = false

    @Environment(\.scenePhase) private var scenePhase

    @State private var phase: LevelChangePhase = .pick
    @State private var pendingDowngrade: String?
    @State private var persistFailed = false
    // Set when a requested Lever B enable did not engage — we committed the
    // honest (lower) tier and must tell the user instead of silently
    // finishing "Private" (mirrors Android's
    // leverBFailed, ProtectionLevelSettingsScreen.kt).
    @State private var leverBFailed = false
    // Set while an inline credential / Lever B flow runs for the chosen level.
    @State private var credentialTarget: CredentialChangeTarget?
    @State private var enableLeverB = false
    @State private var stashedCredential = ""
    // The SECOND independent full-vault-decrypt path
    // (docs/vault-relay-internals.md), equal in power to the credential — gets the
    // same lifetime discipline as stashedCredential: dropped as soon as it's used
    // (RecoveryCodeView's onDone, below) and again on .onDisappear in case the user
    // backs out without reaching "Continue". NOTE: Swift String is copy-on-write but
    // still can't be zeroed in place — clearing this only drops the reference and
    // shortens the window, it does not remove the value from memory (same known limitation
    // (an unwipeable immutable String) as stashedCredential's comment
    // below; a [UInt8]-backed holder would close that gap but is a separate
    // refactor, not undertaken here).
    @State private var recoveryCode = ""
    /// Tier chosen but NOT yet persisted — committed only once its credential /
    /// Lever-B chain succeeds. Cancelling leaves it unwritten.
    @State private var pendingLevel: String? = nil
    @State private var dropLeverBOnCommit = false

    /// Proactive "why + what now" explanation shown ABOVE the chooser ONLY on
    /// the forced route (this device has no passcode — DeviceLockPolicy). Before
    /// this, the only place that named the passcode escape hatch was the LAST
    /// sentence of the acknowledgment dialog you only reach by tapping Apply
    /// (ProtectionLevelView.forcedNoticeBody) — App Store users churned on a
    /// screen that reappeared every launch with no visible way out. This surfaces
    /// both paths up front; the dialog (and the rule it enforces) is unchanged.
    ///
    /// No Settings deep link on iOS: App-Prefs:* URL schemes are private API (an
    /// App Store rejection risk) and UIApplication.openSettingsURLString opens
    /// Rún's OWN settings pane, not the system passcode screen — misleading.
    /// Plain instructions instead, styled as the primary (visually heaviest) card.
    private struct ForcedProtectionExplainer: View {
        var body: some View {
            VStack(alignment: .leading, spacing: 14) {
                // Reuses the single-sourced shared title verbatim (same wording as
                // the acknowledgment dialog below) rather than inventing new copy
                // that could drift from it.
                Text(ProtectionLevelContent.shared.forcedNoticeTitle)
                    .font(.runeHeadline).foregroundColor(.runTextPrimary)
                Text(L10n.protectionForcedExplainerIntro)
                    .font(.runeFootnote).foregroundColor(.runTextSecondary)

                // Primary path — visually first and heaviest. Once this phone has a
                // passcode, DeviceLockPolicy stops forcing Maximum and every level
                // is selectable again the moment you come back to this screen.
                VStack(alignment: .leading, spacing: 6) {
                    Text(L10n.protectionForcedExplainerCtaTitleIos)
                        .font(.runeBody).fontWeight(.semibold).foregroundColor(.runBackground)
                    Text(L10n.protectionForcedExplainerCtaBodyIos)
                        .font(.runeFootnote).foregroundColor(Color(hex: 0x2A2A2A))
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(14)
                .background(Color.runTextPrimary)
                .clipShape(RoundedRectangle(cornerRadius: 12))
                .accessibilityIdentifier("forced_passcode_hint")

                Text(L10n.protectionForcedExplainerOutroIos)
                    .font(.runeFootnote).foregroundColor(.runTextSecondary)
            }
            .padding(16)
            .padding(.top, 6)
        }
    }

    // Compact, non-blocking notice that the vault's
    // Lever B key is on the legacy device-credential-openable scheme and
    // needs a disable→enable cycle to re-harden. It only points at the
    // chooser below — no automatic re-mint runs from here. Mirrors Android's
    // LeverBRehardenNotice (ProtectionLevelSettingsScreen.kt).
    private struct LeverBRehardenNotice: View {
        var body: some View {
            Text(L10n.protectionLeverBRehardenNotice)
                .font(.runeFootnote)
                .foregroundColor(.runError)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 14)
                .padding(.vertical, 10)
                .background(Color.runSurface)
                .clipShape(RoundedRectangle(cornerRadius: 10))
                .padding(.horizontal, 16)
                .padding(.vertical, 6)
                .accessibilityIdentifier("lever_b_reharden_notice")
        }
    }

    private let order = ["casual", "private", "maximum"]
    private var current: String { appState.currentProtectionLevel }
    // The vault's Lever B key can be on the legacy
    // device-credential-openable scheme that unlock-time reconcile couldn't
    // upgrade — appState.needsLeverBReharden is the signal, but it had no UI
    // consumer on either platform. Reached (and therefore evaluated) only
    // once the vault is unlocked, since this view requires that; also gated
    // on Lever B actually being on, since the notice's remedy (disable →
    // enable) is meaningless otherwise. Mirrors Android's
    // showLeverBRehardenNotice (ProtectionLevelSettingsScreen.kt).
    private var showLeverBRehardenNotice: Bool {
        appState.biometricUnlockEnabled && appState.needsLeverBReharden
    }
    // Display tier name (Decent / Secure / Maximum) — single-sourced with Android
    // in shared ProtectionLevelContent so the rename stays consistent everywhere.
    private func displayName(_ level: String) -> String { ProtectionLevelContent.shared.displayName(storageValue: level) }
    private func rank(_ level: String) -> Int { order.firstIndex(of: level) ?? 0 }

    // Apply the chosen level: persist timers, drop Lever B when unused, then run the
    // credential change and/or Lever B enable inline. Credential change happens
    // BEFORE Lever B enable (the enable binds to the final credential).
    private func apply(_ level: String) {
        // The level persist is the FIRST mutation and aborts the
        // whole apply on failure (transient device-key outage — nothing written).
        // Proceeding anyway would rotate the credential / toggle Lever B to match
        // the NEW tier while the persisted level and every enforcement timer
        // stayed at the OLD one, silently. Nothing below may run after a failed
        // persist; the alert keeps the user on the chooser to retry.
        //
        // Persisting FIRST meant
        // picking Maximum then CANCELLING the passphrase screen left the vault
        // claiming Maximum (art, timers) while still on the OLD PIN — the UI
        // OVERSTATING protection. A tier with a credential/Lever-B chain ahead of it
        // is now committed only once that chain succeeds (commitLevel); the
        // abort-on-failure still governs the no-chain case.
        //
        // The UPGRADE half asks for PROOF, not for the
        // fail-OPEN widget reader. isPassphraseMode() answers `true` for a DAMAGED
        // vlt_m (the keypad would hard-lock a passphrase user out), so that
        // slot decided "a passphrase is already set" and "upgrade to Maximum"
        // became a pure metadata write: an AUTHENTICATED vlt_lvl=maximum over the
        // unchanged PIN, permanently satisfying the lock-less floor. Only
        // credentialKindProven() == true may skip the rotation; the shared
        // ProtectionUpgradePlan holds the rule so Android cannot drift from it.
        // The DOWNGRADE half keeps the fail-open reader deliberately: "cannot
        // tell" there already means "rotate to a PIN anyway".
        //
        // The `usesPassphrase &&` prefix SHORT-CIRCUITS the accessor so exactly ONE
        // `vlt_m` AEAD decrypt happens per apply (this one for a passphrase target,
        // isPassphraseMode()'s for a PIN target) — the plan answers `false` for a
        // non-passphrase target anyway, so no decision changes.
        let usesPassphrase = (level == "maximum")
        let usesLeverB = (level == "private")
        let needPassphrase = usesPassphrase && ProtectionUpgradePlan.shared.needsCredentialChangeForStorage(
            targetStorageValue: level,
            credentialKindProven: appState.controller.credentialKindProven()
        )
        let needPin = !usesPassphrase && appState.controller.isPassphraseMode()
        let doEnableLeverB = usesLeverB && !appState.biometricUnlockEnabled
        let dropLeverB = !usesLeverB && appState.biometricUnlockEnabled

        // Casual→Private keeps the PIN, but we re-enter it (target .same) to obtain
        // the plaintext the recovery-enable needs.
        let target: CredentialChangeTarget? = needPassphrase ? .toPassphrase
            : needPin ? .toPin
            : doEnableLeverB ? .same
            : nil
        enableLeverB = doEnableLeverB
        credentialTarget = target
        pendingLevel = level
        dropLeverBOnCommit = dropLeverB

        if target != nil {
            // Chain first; commitLevel() persists the HONEST tier once it
            // settles, and the Lever-B drop rides along there so a cancel
            // can't weaken the tier.
            phase = .changeCred
        } else {
            // Nothing follows — this persist IS the whole apply. Lever B
            // isn't changing state here (doEnableLeverB is false), so the raw
            // level is already honest: either it doesn't use Lever B, or Lever
            // B is already bound.
            let finish = { if commitLevel(level) { dismissOrRearm() } }
            if dropLeverB { appState.setBiometricUnlock(false) { _ in finish() } } else { finish() }
        }
    }

    /// On the FORCED route `onDismiss` is a
    /// REQUEST, not a guarantee — ContentView re-evaluates the floor and keeps
    /// this view up while it still applies. That re-read can DECLINE right after a
    /// genuine, proven MAXIMUM write (a transient device-key outage reads the
    /// floor as unproven), and by then the credential step is finished,
    /// input-disabled and — by design — shows no Cancel: a dead end. So after
    /// asking to leave, fall back to the chooser, where the retry and the "Open
    /// security settings" escape both remain reachable (Android's credential-step
    /// BackHandler is the twin). Unforced, the dismissal always lands and the
    /// phase reset is invisible.
    private func dismissOrRearm() {
        onDismiss()
        if forced { phase = .pick }
    }

    /// Commits [level] AFTER its credential/Lever-B chain settled (or
    /// immediately for the no-chain case above). Callers pass the HONEST tier
    /// ([honestPersistedLevel]) for what the key now backs, so a failed Lever
    /// B enable commits the lower tier, never PRIVATE-over-a-plain-key
    /// A failure here leaves the OLD level
    /// with the NEW (stronger) credential — under-claiming protection, the
    /// safe direction, versus over-claiming. Returns false (and sets
    /// persistFailed) if the persist failed.
    @discardableResult
    private func commitLevel(_ level: String) -> Bool {
        guard appState.setProtectionLevel(level) else { persistFailed = true; return false }
        pendingLevel = nil
        return true
    }

    // Called when the inline credential rotation finishes: enable Lever B (with
    // the stashed final credential) THEN commit the tier the enable result
    // actually earned, or show the recovery code / finish.
    //
    // Sequencing: commitLevel used to run
    // BEFORE enableLeverBWithRecovery even started, so a cancelled/failed
    // enable left the raw chosen PRIVATE persisted over a plain-wrapped key —
    // the exact over-claim the deferred commit was meant to close. The enable now runs first;
    // its result decides which tier — honestPersistedLevel(chosen, ...) — gets
    // committed, on this method's own scope (not a transient view task), so a
    // torn-down credential screen can't split "enabled" from "committed".
    private func onCredentialDone() {
        let doDrop = dropLeverBOnCommit
        let doEnable = enableLeverB
        let chosen = pendingLevel ?? current
        dropLeverBOnCommit = false
        enableLeverB = false
        // Hand the stash to the enable and drop our
        // copy right away. The rotated plaintext credential otherwise stayed in
        // @State until view disposal, exempt from the scenePhase buffer-clearing
        // hygiene every other credential field gets.
        let credential = stashedCredential
        stashedCredential = ""

        // Leave .changeCred before any async key work: the finished credential
        // view must not linger interactively (it would re-present "Confirm new
        // PIN" and feed re-typed digits into its stale confirm step while the
        // drop/enable runs).
        if doDrop || doEnable { phase = .enabling }

        func afterDrop() {
            guard doEnable else {
                // No Lever B enable requested for this tier — either it
                // doesn't use Lever B, or Lever B is already bound, so `true`
                // is honest here (mirrors Android's `leverBActive = true`).
                if commitLevel(honestPersistedLevel(chosen, leverBEnabled: true)) {
                    dismissOrRearm()
                } else {
                    phase = .pick
                }
                return
            }
            appState.enableLeverBWithRecovery(credential) { code in
                if let code = code {
                    // Two-phase: the strict key is only PREPARED (held; DB key
                    // still plain). Commit the HONEST BASE tier now; promote to PRIVATE
                    // atomically at finalize when the user acknowledges the code
                    // (RecoveryCodeView.onDone). Never persist PRIVATE-over-plain.
                    _ = commitLevel(honestPersistedLevel(chosen, leverBEnabled: false))
                    recoveryCode = code
                    phase = .showRecovery
                } else {
                    // Requested Lever B but it never engaged (cancelled Face ID,
                    // unsupported hardware, or a transient SE error) — commit the honest
                    // (lower) tier and surface it instead of silently finishing at
                    // "Private"; never brick. A persist failure returns to the chooser.
                    if commitLevel(honestPersistedLevel(chosen, leverBEnabled: false)) {
                        leverBFailed = true
                    } else {
                        phase = .pick
                    }
                }
            }
        }

        if doDrop {
            appState.setBiometricUnlock(false) { dropped in
                // RUN-01, Secure → Maximum: the credential change above could not
                // re-key (Lever B + the recovery code were still live), so re-key now
                // that the drop has removed both. Same shared rule as Android;
                // best-effort — the vault-side gates decide, and the tier committed in
                // afterDrop() is honest either way.
                if ProtectionUpgradePlan.shared.rotatesDbKeyAfterLeverBDropForStorage(
                    chosenStorageValue: chosen,
                    droppedLeverB: dropped,
                    hasCredential: !credential.isEmpty
                ) {
                    appState.rotateDbKeyAfterTierUpgrade(credential) { _ in afterDrop() }
                } else {
                    afterDrop()
                }
            }
        } else {
            afterDrop()
        }
    }

    var body: some View {
        phaseBody
            // Join the credential-buffer hygiene every other credential surface
            // has — a backgrounded device must not leave the rotated plaintext
            // credential sitting in @State. Gated on .background, never the transient
            // .inactive (Face ID / Control Center), per the Lever-B re-lock rule.
            .onChange(of: scenePhase) { newPhase in
                if newPhase == .background { stashedCredential = "" }
            }
    }

    @ViewBuilder
    private var phaseBody: some View {
        switch phase {
        case .pick:
            pickBody
        case .changeCred:
            if let target = credentialTarget {
                ChangeCredentialView(
                    target: target,
                    onDone: { onCredentialDone() },
                    // Unreachable while `forced` (no Cancel is rendered). Kept as
                    // the plain unforced path: `onDismiss` on the forced route is
                    // ContentView's re-evaluation, which refuses to clear the
                    // gate while the floor still applies, so even a reachable
                    // Cancel could not escape it.
                    onCancel: { stashedCredential = ""; onDismiss() },
                    onCredentialSet: { cred in stashedCredential = cred },
                    // Parity with Android: the forced migration's credential
                    // step carries the gate, so it offers no one-tap escape.
                    cancellable: !forced
                )
            }
        case .enabling:
            enablingBody
        case .showRecovery:
            RecoveryCodeView(code: recoveryCode, onDone: {
                // Code acknowledged: commit the prepared auth-bound key + promote to
                // PRIVATE atomically (finalizeLeverB). Until now the vault was a working
                // base PIN vault, so a death here never bricked or over-claimed. A
                // finalize failure keeps that safe base vault and returns to the chooser.
                //
                // Only clear on the SUCCESS
                // path, once finalize truly settles — clearing unconditionally before
                // starting the async work both blanked the code on screen while
                // finalize was still running and, on the failure branch, discarded a
                // code the user might still need before they ever left this screen. A
                // failed finalize leaves recoveryCode in @State (still the safe base PIN
                // vault) until the user backs out and .onDisappear clears it.
                appState.finalizeLeverB("private") { ok in
                    if ok {
                        recoveryCode = ""
                        onDismiss()
                    } else {
                        persistFailed = true
                        phase = .pick
                    }
                }
            })
            .onDisappear { recoveryCode = "" }
        }
    }

    // Shown while the Lever B enable runs after the credential rotation (a full
    // credential re-verification plus Secure Enclave work, then the system
    // Face ID / passcode prompt from the auth-bound round-trip verify). Replaces
    // the finished credential view so nothing interactive lingers, and tells the
    // user why the system prompt is about to appear.
    private var enablingBody: some View {
        ZStack {
            Color.runBackground.ignoresSafeArea()
            VStack(spacing: 12) {
                Text(L10n.protectionEnablingTitle)
                    .font(.runeBody)
                    .foregroundColor(Color.runTextPrimary)
                    .accessibilityIdentifier("level_enabling")
                Text(L10n.protectionEnablingBodyIos)
                    .font(.runeFootnote)
                    .foregroundColor(Color.runTextSecondary)
                    .multilineTextAlignment(.center)
            }
            .padding(.horizontal, 32)
        }
        // Lever B enable failed: the honest
        // (lower) tier is already committed by onCredentialDone by the time
        // this shows — never a scrim-dismissable no-op, since OK is what
        // actually leaves this screen.
        .runeDialog(
            isPresented: $leverBFailed,
            title: L10n.pinHardwareLockNotEnabledTitle,
            message: L10n.protectionLeverBFailedMessage,
            a11yId: "level_lever_b_failed_notice",
            dismissable: false,
            actions: [
                RuneDialogAction(L10n.commonOk, a11yId: "level_lever_b_failed_ok") { leverBFailed = false; onDismiss() },
            ]
        )
    }

    private var pickBody: some View {
        VStack(spacing: 0) {
            // Forced-only: the explainer sits ABOVE the chooser, not inside the
            // shared ProtectionLevelView — onboarding's own bare-forced pick
            // (PinSetupView, currentLevel: nil) and the post-unlock migration
            // screen (ProtectionLevelMigrationView) reuse that same component and
            // must not gain this card too; only this Settings/forced route does.
            if forced {
                ForcedProtectionExplainer()
            }
            if showLeverBRehardenNotice {
                LeverBRehardenNotice()
            }
            ProtectionLevelView(
                hardwareSupported: appState.biometricUnlockAvailable,
                currentLevel: current,
                confirmLabel: L10n.protectionApplyButton,
                onConfirm: { newLevel in
                    if newLevel == current { onDismiss() }
                    else if rank(newLevel) < rank(current) { pendingDowngrade = newLevel }
                    else { apply(newLevel) }
                },
                onBack: forced ? nil : onDismiss
            )
        }
        .overlay {
            if let l = pendingDowngrade {
                RuneDialogOverlay(
                    title: L10n.protectionDowngradeTitle,
                    message: L10n.protectionDowngradeMessageIos(displayName(l)),
                    onScrimTap: { pendingDowngrade = nil },
                    // Destructive LAST (safety rule — see RuneDialog in UIComponents).
                    actions: [
                        .secondary(L10n.protectionDowngradeKeep) { pendingDowngrade = nil },
                        RuneDialogAction(L10n.protectionDowngradeReduce, color: .runeDanger) { pendingDowngrade = nil; apply(l) },
                    ]
                )
            }
        }
        .runeDialog(isPresented: $persistFailed, title: L10n.protectionPersistFailedTitle,
                    message: L10n.protectionPersistFailedMessage,
                    actions: [RuneDialogAction(L10n.commonOk) { }])
    }
}

// MARK: - Post-unlock migration (legacy vault with no level configured)
//
// Shown ONCE right after a legacy vault (provisioned before the threat-level
// slider) is unlocked — its `protectionLevelConfigured()` is false. First-run
// picks the level before the PIN; an existing vault has none yet, so we ask now.
// A choice is required (bare-forced, no cancel) and ALWAYS persisted (even
// Casual), so it never reappears. The TIMER tier applies immediately; a
// passphrase / hardware-key upgrade is pointed to Settings › Protection level
// (mirrors the Android ProtectionLevelMigrationScreen).

struct ProtectionLevelMigrationView: View {
    @EnvironmentObject private var appState: AppState
    let onDone: () -> Void

    // Carries BOTH the chosen tier and the HONEST persisted tier so the finish
    // note can state what is ACTUALLY in force, not what was picked. When they differ, the chosen tier's timings/wipe are
    // NOT set — only Settings can finish the upgrade.
    @State private var finishNoteFor: (chosen: String, persisted: String)?
    @State private var persistFailed = false

    // Display tier name (Decent / Secure / Maximum) — single-sourced with Android
    // in shared ProtectionLevelContent so the rename stays consistent everywhere.
    private func displayName(_ level: String) -> String { ProtectionLevelContent.shared.displayName(storageValue: level) }

    /// Honest finish-note copy (mirrors Android ProtectionLevelMigrationScreen's
    /// `message` branch). When the persisted tier differs
    /// from the chosen one, this bare-forced migration did NOT actually engage the
    /// chosen tier's stronger unlock (it neither rotates the credential nor enables
    /// Lever B inline), so we must NOT claim "<chosen>'s timings are set now" —
    /// that would over-claim protections (e.g. the 7-day inactivity self-wipe) the
    /// vault does not enforce. Instead name the tier truly in force and point to
    /// Settings. Only when persisted == chosen is the affirmative copy honest.
    private func migrationFinishMessage(chosen: String, persisted: String) -> String {
        let chosenName = displayName(chosen)
        guard persisted != chosen else {
            return L10n.protectionMigrationFinishSame(chosenName)
        }
        let persistedName = displayName(persisted)
        if chosen == "maximum" {
            // MAXIMUM's strength is a passphrase this screen deliberately never sets.
            return L10n.protectionMigrationFinishMaximum(chosenName, persistedName)
        } else {
            // PRIVATE's strength is the hardware (Lever B) key, not engaged here.
            return L10n.protectionMigrationFinishPrivate(chosenName, persistedName)
        }
    }

    private func confirm(_ level: String) {
        // Sibling of the persist-abort rule: the persist must be checked — a transient
        // device-key outage writes nothing, and dismissing the one-time chooser
        // anyway would leave the old-tier timers silently in force. Abort and
        // keep the chooser up so the user retries (it would also re-appear next
        // unlock, but never silently proceed). Always persisted → won't prompt again.
        // This bare-forced migration does NOT rotate the
        // credential or enable Lever B inline — it only nudges the user to finish in
        // Settings. Persisting the raw chosen tier therefore over-claims: MAXIMUM's
        // strength IS the passphrase, so persisting it while the credential is still
        // a 6-digit PIN labels the vault stronger than the key backs; likewise
        // PRIVATE over a plain (Lever-B-off) key. Persist the HONEST tier instead
        // (CASUAL until the passphrase / Lever B is actually in place), which also
        // makes the "finish in Settings" trip real (persisted != chosen, so the
        // Settings chooser runs the credential/Lever-B chain instead of no-opping).
        // Mirrors Android migrationPersistedLevel's passphrase+LeverB honesty.
        //
        // The FOURTH consumer of the fail-OPEN mode
        // reader, reached when vlt_lvl is damaged too (the floor read → nil → this
        // one-time chooser). isPassphraseMode() answers `true` for a damaged
        // vlt_m, so a planted pair let this screen persist an AUTHENTICATED
        // `maximum` over a live 6-digit PIN — the same over-claim again, and with it
        // a permanently retired forced-migration gate. Require PROOF, through the
        // same shared rule Android runs.
        //
        // Review 2026-09-22: the finish-note predicate is now the SHARED rule
        // (ProtectionUpgradePlan.needsFinishInSettings = Android's
        // `mustRotateCredential || persistedLevel != level`). It used to carry an
        // extra fail-OPEN disjunct Android never had — `!usesPassphrase &&
        // isPassphraseMode()` — which both promised a "finish in Settings" trip
        // that has nothing to finish (a passphrase vault picking a PIN tier keeps
        // its credential, and the persisted tier IS the chosen one) and cost a
        // second `vlt_m` decrypt. The `usesPassphrase &&` prefix short-circuits the
        // remaining read for a PIN tier, so this screen now does at most ONE.
        let usesPassphrase = (level == "maximum")
        let mustRotateCredential = usesPassphrase && ProtectionUpgradePlan.shared.needsCredentialChangeForStorage(
            targetStorageValue: level,
            credentialKindProven: appState.controller.credentialKindProven()
        )
        let honest = mustRotateCredential
            ? "casual"
            : honestPersistedLevel(level, leverBEnabled: appState.biometricUnlockEnabled)
        guard appState.setProtectionLevel(honest) else {
            persistFailed = true
            return
        }
        // Carry the honest persisted tier alongside the chosen one so the note is
        // truthful when they differ.
        let needsFinish = ProtectionUpgradePlan.shared.needsFinishInSettingsForStorage(
            chosenStorageValue: level,
            persistedStorageValue: honest,
            mustRotateCredential: mustRotateCredential
        )
        if needsFinish { finishNoteFor = (chosen: level, persisted: honest) } else { onDone() }
    }

    var body: some View {
        ProtectionLevelView(
            hardwareSupported: appState.biometricUnlockAvailable,
            currentLevel: nil,               // bare-forced — a first, explicit choice
            confirmLabel: L10n.commonContinue,
            onConfirm: { level in confirm(level) },
            onBack: nil                      // a choice is required to continue
        )
        .overlay {
            if let note = finishNoteFor {
                RuneDialogOverlay(
                    title: L10n.protectionMigrationAlmostThereTitle,
                    message: migrationFinishMessage(chosen: note.chosen, persisted: note.persisted),
                    onScrimTap: { finishNoteFor = nil; onDone() },
                    actions: [RuneDialogAction(L10n.commonGotIt) { finishNoteFor = nil; onDone() }]
                )
            }
        }
        .runeDialog(isPresented: $persistFailed, title: L10n.protectionPersistFailedTitle,
                    message: L10n.protectionPersistFailedMessage,
                    actions: [RuneDialogAction(L10n.commonOk) { }])
    }
}

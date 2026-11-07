import SwiftUI
import UIKit

// ---------------------------------------------------------------------------
// ScreenshotProtection — covers the AUTOMATED capture paths and warns on a
// manual screenshot.
//
// What actually works (and what does NOT), so callers don't over-promise:
//   • Screen recording / AirPlay mirroring → an opaque black cover while
//     UIScreen.isCaptured (robust).
//   • App-switcher snapshot → an opaque cover added synchronously on
//     willResignActive (robust).
//   • A MANUAL hardware screenshot (power+volume) → iOS exposes NO API to
//     block it. The 1×1 isSecureTextEntry field below is a best-effort nudge
//     that only redacts content composited INTO the field's own layer — window
//     content is not, so it does NOT hide a still screenshot. We keep it
//     (harmless, may help on some future capture path) but do NOT rely on it,
//     and instead DETECT the screenshot and warn the user (the shared About
//     copy is worded accordingly — see AboutContent screenPrivacyBody).
//
// Usage: Call ScreenshotProtection.shared.enable() on app launch.
// ---------------------------------------------------------------------------

final class ScreenshotProtection {
    static let shared = ScreenshotProtection()

    private var secureField: UITextField?
    private var captureCover: UIView?
    private var snapshotCover: UIView?
    private var screenshotWarning: UIView?

    private init() {}

    func enable() {
        guard secureField == nil else { return }

        #if DEBUG
        // DEBUG-only escape hatch: a build launched with --disable-capture-protection
        // skips ALL capture defenses so the App Store review screencast can be
        // recorded on a device. The isSecureTextEntry trick AND the isCaptured
        // black cover otherwise render screen recordings entirely black. Compiled
        // out of Release and gated on an explicit launch arg, so it can never ship
        // or trigger for a real user (mirrors --test-wipe-on-launch). Pair with
        // --test-wipe-on-launch to record a fresh first run (EULA → PIN → …).
        if ProcessInfo.processInfo.arguments.contains("--disable-capture-protection") {
            return
        }
        #endif

        // Screen-recording / AirPlay defense: the
        // isSecureTextEntry trick is weaker than Android FLAG_SECURE and only
        // affects some capture paths. Explicitly observe active capture
        // (UIScreen.isCaptured) and cover the window opaquely while recording or
        // mirroring is active. Block-based observer so this class needn't be
        // an NSObject.
        NotificationCenter.default.addObserver(
            forName: UIScreen.capturedDidChangeNotification, object: nil, queue: .main
        ) { [weak self] _ in self?.updateCaptureCover() }

        // App-switcher snapshot defense: iOS
        // captures the task-switcher snapshot during the .inactive phase, which
        // precedes .background. Relying on a SwiftUI `scenePhase`-driven overlay
        // is timing-dependent and may not be composited into the captured frame.
        // The reliable, Apple-documented path is a UIKit window-level cover added
        // synchronously on willResignActive and removed on didBecomeActive — so
        // an opaque view is GUARANTEED to be in the hierarchy when the snapshot
        // is taken, blanking any unlocked content (conversation/contacts/etc.).
        NotificationCenter.default.addObserver(
            forName: UIApplication.willResignActiveNotification, object: nil, queue: .main
        ) { [weak self] _ in self?.showSnapshotCover() }
        NotificationCenter.default.addObserver(
            forName: UIApplication.didBecomeActiveNotification, object: nil, queue: .main
        ) { [weak self] _ in self?.hideSnapshotCover() }

        // capturedDidChange only fires on a
        // TRANSITION, and the one-shot evaluation at the bottom of enable() runs against
        // whatever window existed 0.1 s after launch. A process background-launched by a
        // silent push (or one whose key window arrives late) therefore never installed a
        // cover, for its entire lifetime, even with a screen recording already running.
        // willEnterForeground re-evaluates on every background→foreground transition,
        // INCLUDING "silently launched in the background, then the user taps the icon" —
        // once the process is already running from the push wake, the user opening it is
        // a genuine background→foreground transition, so this fires. It was originally
        // ALSO wired to didBecomeActive, but that fires on every foreground activation
        // including immediately after this one on the exact same transition (and,
        // separately, on a true cold launch — already covered by enable()'s own one-shot
        // evaluation) — so the cover was being torn down and rebuilt twice per foreground
        // for no additional coverage. willEnterForeground alone is both necessary (covers
        // the silent-push case) and sufficient (didBecomeActive never fires without a
        // preceding willEnterForeground for a background-launched process, since it never
        // reaches `.active` during the silent wake itself).
        NotificationCenter.default.addObserver(
            forName: UIApplication.willEnterForegroundNotification, object: nil, queue: .main
        ) { [weak self] _ in self?.updateCaptureCover() }

        // Manual-screenshot DETECTION: iOS can't block a hardware
        // screenshot, so warn the user that the captured image is unencrypted and
        // in Photos. Fires after the screenshot is already taken (the only signal
        // iOS provides); the honest About copy sets the expectation.
        NotificationCenter.default.addObserver(
            forName: UIApplication.userDidTakeScreenshotNotification, object: nil, queue: .main
        ) { [weak self] _ in self?.showScreenshotWarning() }

        DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) { [weak self] in
            guard let self else { return }
            if let scene = UIApplication.shared.connectedScenes.first as? UIWindowScene,
               let window = scene.windows.first {
                let field = UITextField()
                field.isSecureTextEntry = true
                field.isUserInteractionEnabled = false
                field.translatesAutoresizingMaskIntoConstraints = false

                window.addSubview(field)
                field.layer.zPosition = -1
                NSLayoutConstraint.activate([
                    field.widthAnchor.constraint(equalToConstant: 1),
                    field.heightAnchor.constraint(equalToConstant: 1),
                    field.centerXAnchor.constraint(equalTo: window.centerXAnchor),
                    field.centerYAnchor.constraint(equalTo: window.centerYAnchor),
                ])
                self.secureField = field
            }
            self.updateCaptureCover()
        }
    }

    private func keyWindow() -> UIWindow? {
        let scene = UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .first
        return scene?.windows.first { $0.isKeyWindow } ?? scene?.windows.first
    }

    /// Add an opaque cover synchronously so it is present in the task-switcher
    /// snapshot taken on resign-active. Idempotent.
    private func showSnapshotCover() {
        guard let window = keyWindow() else { return }
        if snapshotCover != nil { return }
        let cover = UIView(frame: window.bounds)
        cover.backgroundColor = .black
        cover.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        cover.isUserInteractionEnabled = false
        cover.layer.zPosition = .greatestFiniteMagnitude
        window.addSubview(cover)
        snapshotCover = cover
    }

    private func hideSnapshotCover() {
        snapshotCover?.removeFromSuperview()
        snapshotCover = nil
    }

    /// Transient banner shown after a manual screenshot: iOS gives no way to
    /// prevent it, so we tell the user the captured image is NOT encrypted.
    /// Auto-dismisses; idempotent (replaces any visible one).
    private func showScreenshotWarning() {
        guard let window = keyWindow() else { return }
        screenshotWarning?.removeFromSuperview()

        let banner = UIView()
        banner.translatesAutoresizingMaskIntoConstraints = false
        banner.backgroundColor = UIColor(red: 0.55, green: 0.06, blue: 0.06, alpha: 0.97)
        banner.layer.cornerRadius = 12
        banner.layer.zPosition = .greatestFiniteMagnitude
        banner.isUserInteractionEnabled = false

        let label = UILabel()
        label.translatesAutoresizingMaskIntoConstraints = false
        label.numberOfLines = 0
        label.textColor = .white
        label.font = .systemFont(ofSize: 13, weight: .semibold)
        label.text = L10n.conversationScreenshotWarningBanner
        banner.addSubview(label)
        window.addSubview(banner)
        screenshotWarning = banner

        NSLayoutConstraint.activate([
            banner.leadingAnchor.constraint(equalTo: window.leadingAnchor, constant: 16),
            banner.trailingAnchor.constraint(equalTo: window.trailingAnchor, constant: -16),
            banner.topAnchor.constraint(equalTo: window.safeAreaLayoutGuide.topAnchor, constant: 8),
            label.leadingAnchor.constraint(equalTo: banner.leadingAnchor, constant: 14),
            label.trailingAnchor.constraint(equalTo: banner.trailingAnchor, constant: -14),
            label.topAnchor.constraint(equalTo: banner.topAnchor, constant: 10),
            label.bottomAnchor.constraint(equalTo: banner.bottomAnchor, constant: -10),
        ])

        banner.alpha = 0
        UIView.animate(withDuration: 0.2) { banner.alpha = 1 }
        DispatchQueue.main.asyncAfter(deadline: .now() + 4.5) { [weak self, weak banner] in
            UIView.animate(withDuration: 0.3, animations: { banner?.alpha = 0 }) { _ in
                banner?.removeFromSuperview()
                if self?.screenshotWarning === banner { self?.screenshotWarning = nil }
            }
        }
    }

    private func updateCaptureCover() {
        // Use the resolved key window (not connectedScenes.first, which is not
        // guaranteed to be the foreground scene) and check the capture state of the
        // screen THAT WINDOW is on. UIScreen.isCaptured is set for both a local screen
        // recording and an AirPlay mirror of that content, so this covers the same
        // threat as the old all-screens scan — and more tightly (an unrelated external
        // display showing OTHER content shouldn't blank our window). UIScreen.screens
        // was deprecated in iOS 16; window.screen is the surface we're protecting.
        guard let window = keyWindow() else { return }
        let isCaptured = window.screen.isCaptured
        if isCaptured {
            if captureCover == nil {
                let cover = UIView(frame: window.bounds)
                cover.backgroundColor = .black
                cover.autoresizingMask = [.flexibleWidth, .flexibleHeight]
                cover.isUserInteractionEnabled = false
                cover.layer.zPosition = .greatestFiniteMagnitude
                window.addSubview(cover)
                captureCover = cover
            }
        } else {
            captureCover?.removeFromSuperview()
            captureCover = nil
        }
    }
}

// MARK: - SwiftUI privacy cover (moved from ContentView.swift)

/// Opaque cover shown whenever the scene is not active, so the iOS app-switcher
/// snapshot never captures unlocked content.
struct PrivacyCoverView: View {
    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()
            Image(systemName: "lock.shield.fill")
                .font(.system(size: 56))
                .foregroundColor(.white.opacity(0.85))
        }
    }
}

/// Applies the privacy cover whenever the scene is not active. Apply to the root
/// AND to every separately-presented sheet / fullScreenCover: those live in
/// their own presentation layer above the root, so the root's cover does not
/// reach them (IOS-SEC-2 — an app-switcher snapshot of an open AddContact code
/// or ChangePin keypad).
private struct PrivacyCoverModifier: ViewModifier {
    @Environment(\.scenePhase) private var scenePhase
    func body(content: Content) -> some View {
        content.overlay {
            if scenePhase != .active { PrivacyCoverView() }
        }
    }
}

extension View {
    func privacyCovered() -> some View { modifier(PrivacyCoverModifier()) }

    /// A sheet / fullScreenCover root that is privacy-covered and forced dark.
    /// Sheets don't reliably inherit the root's forced dark scheme, so it is
    /// re-asserted here or the sheet can render light. The modifier order does not
    /// matter: `preferredColorScheme` sets a preference the presenting host resolves
    /// for the whole presentation, an overlay forwards its content's preferences,
    /// and PrivacyCoverView uses only explicit colours.
    func coveredDarkSheet() -> some View {
        self
            .privacyCovered()
            .preferredColorScheme(.dark)
    }
}

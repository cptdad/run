import Foundation
import UIKit
import shared

// ---------------------------------------------------------------------------
// InactivityAutoLock — foreground inactivity monitor for the 2-minute
// auto-lock (Lever C).
//
// Backgrounding already locks immediately (ContentView's scenePhase handler);
// this bounds the remaining exposure: the app sitting OPEN and idle with the
// screen on. A non-recognizing catch-all gesture recognizer on every window
// timestamps the last user touch without interfering with normal hit-testing;
// ContentView polls it on a timer and calls AppState.lock() once the idle
// window (CredentialPolicy.AUTO_LOCK_TIMEOUT_MS) elapses while unlocked.
//
// Mirrors Android MainActivity.onUserInteraction + its Handler check loop.
// ---------------------------------------------------------------------------

final class InactivityAutoLock {

    static let shared = InactivityAutoLock()
    private init() {}

    /// Monotonic-enough idle clock. Uses ProcessInfo.systemUptime (not Date) so
    /// a wall-clock change can neither postpone nor force the auto-lock.
    private(set) var lastActivityUptime: TimeInterval = ProcessInfo.processInfo.systemUptime

    func touch() {
        lastActivityUptime = ProcessInfo.processInfo.systemUptime
    }

    var idleSeconds: TimeInterval {
        ProcessInfo.processInfo.systemUptime - lastActivityUptime
    }

    /// Installs the catch-all touch recognizer on every connected window that
    /// doesn't have one yet. Safe to call repeatedly (e.g. on every
    /// scenePhase-active transition, which also covers windows created later
    /// for sheets — though SwiftUI sheets share the key window).
    func installOnWindows() {
        for scene in UIApplication.shared.connectedScenes {
            guard let windowScene = scene as? UIWindowScene else { continue }
            for window in windowScene.windows {
                let alreadyInstalled = window.gestureRecognizers?.contains {
                    $0 is TouchObservingGestureRecognizer
                } ?? false
                if !alreadyInstalled {
                    let recognizer = TouchObservingGestureRecognizer(target: nil, action: nil)
                    recognizer.cancelsTouchesInView = false
                    recognizer.delaysTouchesBegan = false
                    recognizer.delaysTouchesEnded = false
                    window.addGestureRecognizer(recognizer)
                }
            }
        }
    }
}

/// Records every touch then immediately fails, so it never competes with the
/// app's real gestures — a pure observer.
private final class TouchObservingGestureRecognizer: UIGestureRecognizer {
    override func touchesBegan(_ touches: Set<UITouch>, with event: UIEvent) {
        InactivityAutoLock.shared.touch()
        state = .failed
    }
}

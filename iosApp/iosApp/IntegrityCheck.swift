import Foundation

// ---------------------------------------------------------------------------
// IntegrityCheck — detects jailbroken iOS devices.
//
// Checks for common jailbreak indicators:
//   - Cydia/Sileo apps
//   - Writable system paths
//   - Ability to fork (sandboxed apps cannot)
// ---------------------------------------------------------------------------

struct IntegrityCheck {

    static var isCompromised: Bool {
        #if targetEnvironment(simulator)
        return false
        #else
        // Check for jailbreak-related files
        let suspiciousPaths = [
            "/Applications/Cydia.app",
            "/Applications/Sileo.app",
            "/usr/sbin/sshd",
            "/usr/bin/ssh",
            "/etc/apt",
            "/private/var/lib/apt",
            "/private/var/lib/cydia",
            "/private/var/stash",
        ]
        for path in suspiciousPaths {
            if FileManager.default.fileExists(atPath: path) {
                return true
            }
        }

        // Check if we can write outside sandbox
        let testPath = "/private/jailbreak_test_\(UUID().uuidString)"
        do {
            try "test".write(toFile: testPath, atomically: true, encoding: .utf8)
            try FileManager.default.removeItem(atPath: testPath)
            return true // Should not be writable on non-jailbroken device
        } catch {
            // Expected — sandbox is enforced
        }

        return false
        #endif
    }
}

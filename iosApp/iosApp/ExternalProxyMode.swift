import Foundation
import Darwin
import shared

// ---------------------------------------------------------------------------
// ExternalProxyMode — the process-lifetime decision "embedded Tor, or the
// user's own SOCKS5 proxy" (docs/external-socks-proxy.md; commonMain
// ExternalTorProxy; persistence in iosMain IosExternalProxyStore).
//
// THE INVARIANT this file exists to make provable: while the user's setting
// is on, this process never starts the embedded Tor and never sends a relay
// byte anywhere but the configured host:port.
//
//  * The decision is made ONCE per process and then frozen (set-once below).
//    A setting changed in Settings applies at the NEXT LAUNCH; a wipe clears
//    the stored row but never flips a running process back to embedded Tor.
//  * TorManager.start() — the ONLY place tor_main / the control socket is
//    created — refuses unless `mayStartEmbeddedTor()` is true, which requires a
//    POSITIVE "no setting stored" read. An unreadable store is UNKNOWN and
//    refuses too (fail closed), without being cached, so a later start can
//    still resolve it once the keybag is readable.
//  * SwiftTorHttp — the ONLY relay SOCKS transport — asks `socksTarget(...)` on
//    every request: in external mode it ignores the caller's port and always
//    dials the configured endpoint; in the invalid / unknown states it refuses.
//
// Never logs the host or port — only "loopback"/"lan" and outcomes.
// ---------------------------------------------------------------------------

/// Connecting-UI status of external proxy mode (AppState.extProxyStatus).
enum ExtProxyStatus: Equatable {
    /// Embedded Tor is the transport (external mode not in effect).
    case off
    /// External mode: probing the proxy.
    case checking
    /// External mode: the proxy answered a SOCKS5 greeting (or the relay answered through it).
    case reachable
    /// External mode: the proxy did not answer — messaging unavailable, no fallback.
    case unreachable
    /// External mode: the stored setting is unusable (or the relay is not an
    /// onion) — messaging unavailable, no fallback.
    case invalid
    /// The setting could not be read — the embedded Tor is held back, messaging unavailable.
    case unreadable

    var isExternal: Bool { self != .off }
}

/// The user's proxy endpoint. `host` is an IP literal WITHOUT IPv6 brackets.
struct ExternalProxyEndpoint: Equatable, Sendable {
    let host: String
    let port: UInt16
    let isLan: Bool
    /// Log-safe class word — the ONLY thing about the endpoint that may be logged.
    var classWord: String { isLan ? "lan" : "loopback" }
}

final class ExternalProxyMode: @unchecked Sendable {

    enum Resolved: Equatable, Sendable {
        /// No setting stored: the embedded Tor is the transport.
        case embedded
        /// External proxy mode with a usable endpoint.
        case external(ExternalProxyEndpoint)
        /// A setting IS stored but does not parse: external mode, no transport.
        case invalid
    }

    static let shared = ExternalProxyMode()

    /// iOS ships WITHOUT the setting for now (2026-10-21): the
    /// Settings row is hidden, and a value stored by an earlier build is
    /// cleared at resolve so no iPhone is left in a mode it cannot leave.
    /// Android keeps the feature. Flip to true to bring the row back.
    static let settingsAvailable = false

    private let lock = NSLock()
    private var resolved: Resolved?

    private init() {}

    /// Resolves (once) and returns the mode, or nil when the store is
    /// unreadable right now. A nil is NOT cached.
    @discardableResult
    func resolve() -> Resolved? {
        lock.lock()
        if let r = resolved { lock.unlock(); return r }
        lock.unlock()
        // Store read outside the lock (Keychain I/O); first writer wins below.
        let read = IosExternalProxyStore.shared.read()
        let r: Resolved
        if !ExternalProxyMode.settingsAvailable && read.state != IosExternalProxyStore.shared.STATE_UNREADABLE {
            if read.state != IosExternalProxyStore.shared.STATE_OFF {
                // Fail closed: a clear that did not land keeps Tor held back (not cached).
                guard IosExternalProxyStore.shared.clear() else { return nil }
                LogBuffer.shared.append(level: "I", tag: "ExtProxy", message: "ext proxy: setting unavailable on iOS — stored value cleared")
            }
            r = .embedded
        } else {
            switch read.state {
            case IosExternalProxyStore.shared.STATE_OFF:
                r = .embedded
            case IosExternalProxyStore.shared.STATE_ON:
                if let host = read.host, read.port > 0, read.port <= 65535 {
                    r = .external(ExternalProxyEndpoint(host: ExternalProxyMode.stripBrackets(host),
                                                        port: UInt16(read.port), isLan: read.isLan))
                } else {
                    r = .invalid
                }
            case IosExternalProxyStore.shared.STATE_INVALID:
                r = .invalid
            default:
                LogBuffer.shared.append(level: "W", tag: "ExtProxy", message: "ext proxy: setting unreadable — embedded Tor held back")
                return nil
            }
        }
        lock.lock()
        if resolved == nil {
            resolved = r
            lock.unlock()
            switch r {
            case .embedded: break
            case .external(let ep):
                LogBuffer.shared.append(level: "I", tag: "ExtProxy", message: "ext proxy: \(ep.classWord) — embedded Tor disabled for this process")
            case .invalid:
                LogBuffer.shared.append(level: "W", tag: "ExtProxy", message: "ext proxy: setting invalid — embedded Tor disabled, messaging unavailable")
            }
            return r
        }
        let winner = resolved
        lock.unlock()
        return winner
    }

    /// The frozen decision, without triggering a read. nil = not resolved yet.
    var current: Resolved? {
        lock.lock(); defer { lock.unlock() }
        return resolved
    }

    /// True ONLY on a positive, frozen "no setting stored" decision.
    func mayStartEmbeddedTor() -> Bool {
        resolve() == .embedded
    }

    /// True when this process is (frozen) in external mode — valid or invalid.
    var isExternalThisProcess: Bool {
        switch current {
        case .external?, .invalid?: return true
        default: return false
        }
    }

    /// The configured endpoint when this process is in valid external mode.
    var endpoint: ExternalProxyEndpoint? {
        if case .external(let ep)? = current { return ep }
        return nil
    }

    /// Where a relay SOCKS5 request must connect. Called by SwiftTorHttp on
    /// every request.
    ///  - external: ALWAYS the configured endpoint (the caller's port is ignored).
    ///  - embedded: the embedded Tor's loopback listener on the caller's port.
    ///  - invalid / unresolved: nil — refuse. (The embedded Tor cannot have
    ///    started while unresolved, so there is no legitimate request to make.)
    func socksTarget(callerPort: Int) -> (host: String, port: UInt16)? {
        switch current {
        case .external(let ep)?:
            return (ep.host, ep.port)
        case .embedded?:
            guard callerPort > 0, callerPort <= 65535 else { return nil }
            return ("127.0.0.1", UInt16(callerPort))
        default:
            return nil
        }
    }

    static func stripBrackets(_ h: String) -> String {
        let t = h.trimmingCharacters(in: .whitespaces)
        if t.count >= 2, t.hasPrefix("["), t.hasSuffix("]") {
            return String(t.dropFirst().dropLast())
        }
        return t
    }

    // MARK: - Reachability probe

    /// Non-blocking TCP connect + SOCKS5 no-auth greeting (`05 01 00` → `05 00`)
    /// to the endpoint, on a background queue. Raw BSD sockets on an IP LITERAL
    /// parsed with inet_pton — no name resolution exists anywhere on this path.
    /// `completion` runs on an arbitrary queue.
    static func probe(_ ep: ExternalProxyEndpoint, timeoutMs: Int = 3000,
                      completion: @Sendable @escaping (Bool) -> Void) {
        DispatchQueue.global(qos: .userInitiated).async {
            completion(probeSync(ep, timeoutMs: timeoutMs))
        }
    }

    private static func probeSync(_ ep: ExternalProxyEndpoint, timeoutMs: Int) -> Bool {
        var storage = sockaddr_storage()
        var len: socklen_t = 0
        let family: Int32
        var v4 = in_addr()
        var v6 = in6_addr()
        if inet_pton(AF_INET, ep.host, &v4) == 1 {
            family = AF_INET
            var a = sockaddr_in()
            a.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            a.sin_family = sa_family_t(AF_INET)
            a.sin_port = in_port_t(ep.port).bigEndian
            a.sin_addr = v4
            withUnsafeMutableBytes(of: &storage) { dst in
                withUnsafeBytes(of: &a) { src in dst.copyMemory(from: src) }
            }
            len = socklen_t(MemoryLayout<sockaddr_in>.size)
        } else if inet_pton(AF_INET6, ep.host, &v6) == 1 {
            family = AF_INET6
            var a = sockaddr_in6()
            a.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
            a.sin6_family = sa_family_t(AF_INET6)
            a.sin6_port = in_port_t(ep.port).bigEndian
            a.sin6_addr = v6
            withUnsafeMutableBytes(of: &storage) { dst in
                withUnsafeBytes(of: &a) { src in dst.copyMemory(from: src) }
            }
            len = socklen_t(MemoryLayout<sockaddr_in6>.size)
        } else {
            return false   // not an IP literal — never resolved, never dialled
        }

        let fd = Darwin.socket(family, SOCK_STREAM, 0)
        guard fd >= 0 else { return false }
        defer { Darwin.close(fd) }
        var one: Int32 = 1
        _ = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
        let flags = fcntl(fd, F_GETFL, 0)
        _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)

        let connRes = withUnsafePointer(to: &storage) { ptr -> Int32 in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, len) }
        }
        if connRes != 0 {
            guard errno == EINPROGRESS else { return false }
            var pfd = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
            let pr = withUnsafeMutablePointer(to: &pfd) { Darwin.poll($0, 1, Int32(timeoutMs)) }
            guard pr > 0 else { return false }
            var soErr: Int32 = 0
            var soLen = socklen_t(MemoryLayout<Int32>.size)
            guard getsockopt(fd, SOL_SOCKET, SO_ERROR, &soErr, &soLen) == 0, soErr == 0 else { return false }
        }
        return Socks5Greeting.succeeds(fd: fd, timeoutMs: timeoutMs)
    }
}

/// The SOCKS5 no-auth method-selection round trip, shared by the external-proxy
/// probe above and AppState's embedded-Tor SOCKS liveness probe. A local listener
/// that merely `accept()`s fails it, so neither probe mistakes a port-squatter for
/// a live SOCKS server. Raw BSD send/recv bounded by poll() on an already-connected
/// non-blocking fd: no hostname, so DNS-leak-free and outside the network-API
/// allowlist. Touches only the fd and locals, so it is safe from any thread.
enum Socks5Greeting {
    static func succeeds(fd: Int32, timeoutMs: Int) -> Bool {
        func poll1(_ events: Int16) -> Bool {
            var pfd = pollfd(fd: fd, events: events, revents: 0)
            let r = withUnsafeMutablePointer(to: &pfd) { Darwin.poll($0, 1, Int32(timeoutMs)) }
            return r > 0 && (pfd.revents & events) != 0
        }
        // Write the greeting: VER=5, NMETHODS=1, METHOD=0x00 (no auth).
        let greeting: [UInt8] = [0x05, 0x01, 0x00]
        var sent = 0
        while sent < greeting.count {
            guard poll1(Int16(POLLOUT)) else { return false }
            let n = greeting.withUnsafeBytes { buf -> Int in
                guard let base = buf.baseAddress else { return 0 }
                return Darwin.send(fd, base.advanced(by: sent), greeting.count - sent, 0)
            }
            if n > 0 { sent += n }
            else if n < 0 && (errno == EAGAIN || errno == EINTR) { continue }
            else { return false }
        }
        // Read the 2-byte method-selection reply: expect VER=5, METHOD=0x00.
        var resp: [UInt8] = [0, 0]
        var got = 0
        while got < 2 {
            guard poll1(Int16(POLLIN)) else { return false }
            let n = resp.withUnsafeMutableBytes { buf -> Int in
                guard let base = buf.baseAddress else { return 0 }
                return Darwin.recv(fd, base.advanced(by: got), 2 - got, 0)
            }
            if n > 0 { got += n }
            else if n < 0 && (errno == EAGAIN || errno == EINTR) { continue }
            else { return false }   // n == 0 → peer closed
        }
        return resp[0] == 0x05 && resp[1] == 0x00
    }
}

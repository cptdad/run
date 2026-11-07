import Foundation
import Network
import shared

// ---------------------------------------------------------------------------
// SwiftTorHttp — HTTP client that tunnels through Tor's SOCKS5 proxy with
// manual SOCKS5 handshake for remote DNS (SOCKS5h).
//
// NSURLSession's SOCKS5 support resolves DNS locally, breaking .onion.
// Network.framework's ProxyConfiguration hangs on iOS simulator.
// This implementation connects a plain TCP NWConnection to Tor's SOCKS5
// port on 127.0.0.1 (or, in external proxy mode, to the user's own SOCKS5
// proxy at a configured IP literal — see ExternalProxyMode), manually
// performs the SOCKS5 handshake (sending the
// .onion hostname for remote resolution), then sends raw HTTP/1.1 over
// the tunneled connection.
//
// post(), put(), get() and delete() all BLOCK the calling Kotlin background
// thread on an NSCondition; every NWConnection callback runs on the per-request
// queue. Each call opens a fresh TCP connection.
//
// Privacy: no URLs, headers, or body content are logged.
// ---------------------------------------------------------------------------

final class SwiftTorHttp: NSObject, HttpBridge {

    // MARK: - NEWNYM abort (2026-10-08)
    //
    // Requests started with `cancelOnNewCircuit` (the health probe `GET /` and
    // the unread prime's batch `POST /peek` — read-only, idempotent) register
    // their NWConnection here, so `cancelNewCircuitSensitive()` — called right
    // after the app's `SIGNAL NEWNYM` was accepted — can cancel them: their
    // streams ride circuits Tor just retired, and the fresh circuits answer in
    // ~2–3 s. Cancelling drives the connection to `.cancelled`, which settles the
    // blocked caller with a transport failure (code -1) immediately; MessageManager
    // then re-probes at once and books the attempt as neither timeout nor success.
    // Android sibling: PlatformHttpClient.android.kt (OkHttp `Call.cancel()`).

    private final class InFlight {
        let connection: NWConnection
        var abortedForNewCircuit = false
        init(_ connection: NWConnection) { self.connection = connection }
    }

    /// First-byte state of ONE request; read and written only on that
    /// request's own serial queue.
    private final class FirstByteWatch {
        var seen = false
        var timedOut = false
        // Optimistic-stream timing (uptime ns; 0 = unset), for the one debug line.
        var connectSentAt: UInt64 = 0
        var replyAt: UInt64 = 0
    }

    private let inFlightLock = NSLock()
    private var newCircuitSensitive: [ObjectIdentifier: InFlight] = [:]

    func cancelNewCircuitSensitive() -> Int32 {
        inFlightLock.lock()
        let victims = Array(newCircuitSensitive.values)
        for v in victims { v.abortedForNewCircuit = true }
        inFlightLock.unlock()
        // Outside the lock: cancel() fires the state handler on the request's own
        // queue, which takes the lock to read the flag.
        for v in victims { v.connection.cancel() }
        return Int32(victims.count)
    }

    // MARK: - HttpBridge conformance

    func post(
        url: String,
        body: Data,
        contentType: String,
        headers: [String: String],
        socksPort: Int32,
        timeoutSeconds: Int32,
        suppressLog: Bool,
        cancelOnNewCircuit: Bool,
        socksAuth: String
    ) -> HttpBridgeResult {
        var allHeaders = headers
        allHeaders["Content-Type"] = contentType
        allHeaders["Content-Length"] = "\(body.count)"
        return execute(method: "POST", url: url, body: body,
                       headers: allHeaders, socksPort: Int(socksPort),
                       timeout: TimeInterval(timeoutSeconds),
                       suppressLog: suppressLog,
                       cancelOnNewCircuit: cancelOnNewCircuit,
                       socksAuth: socksAuth)
    }

    func put(
        url: String,
        body: Data,
        contentType: String,
        headers: [String: String],
        socksPort: Int32,
        timeoutSeconds: Int32,
        suppressLog: Bool,
        socksAuth: String
    ) -> HttpBridgeResult {
        var allHeaders = headers
        allHeaders["Content-Type"] = contentType
        allHeaders["Content-Length"] = "\(body.count)"
        return execute(method: "PUT", url: url, body: body,
                       headers: allHeaders, socksPort: Int(socksPort),
                       timeout: TimeInterval(timeoutSeconds),
                       suppressLog: suppressLog,
                       socksAuth: socksAuth)
    }

    func get(
        url: String,
        headers: [String: String],
        socksPort: Int32,
        timeoutSeconds: Int32,
        suppressLog: Bool,
        cancelOnNewCircuit: Bool,
        firstByteTimeoutSeconds: Int32,
        socksAuth: String
    ) -> HttpBridgeResult {
        return execute(method: "GET", url: url, body: nil,
                       headers: headers, socksPort: Int(socksPort),
                       timeout: TimeInterval(timeoutSeconds),
                       suppressLog: suppressLog,
                       cancelOnNewCircuit: cancelOnNewCircuit,
                       firstByteTimeout: TimeInterval(max(0, firstByteTimeoutSeconds)),
                       socksAuth: socksAuth)
    }

    // docs/RELAY_SPEC.md (push): DELETE /inbox/{id}/push (push opt-out / vault wipe).
    func delete(
        url: String,
        headers: [String: String],
        socksPort: Int32,
        timeoutSeconds: Int32,
        suppressLog: Bool,
        socksAuth: String
    ) -> HttpBridgeResult {
        return execute(method: "DELETE", url: url, body: nil,
                       headers: headers, socksPort: Int(socksPort),
                       timeout: TimeInterval(timeoutSeconds),
                       suppressLog: suppressLog,
                       socksAuth: socksAuth)
    }

    // MARK: - Result builders

    /// Update-nudge: every failure path returns `code: -1,
    /// isSuccess: false, appVersionHeader: nil`. Kotlin default args are NOT
    /// exported to Swift, so adding `appVersionHeader` to `HttpBridgeResult`
    /// turned the designated initializer into
    /// `init(code:body:isSuccess:appVersionHeader:)` and broke all 15
    /// failure-site call sites below (plus the 1 success site, handled
    /// separately in parseHttpResponse) — this factory restores a single
    /// terse call at each of them. `code` defaults to -1 (every failure site
    /// here uses it); pass `code:` explicitly for the rare non-default case.
    /// Log-safe class of a Network.framework error: the domain and numeric code
    /// only, never `localizedDescription` (free text that can carry an address).
    static func errorClass(_ error: NWError) -> String {
        switch error {
        case .posix(let code): return "posix(\(code.rawValue))"
        case .dns(let code): return "dns(\(code))"
        case .tls(let status): return "tls(\(status))"
        @unknown default: return String(describing: type(of: error))
        }
    }

    private func bridgeFail(_ body: String, code: Int32 = -1, firstByteTimeout: Bool = false) -> HttpBridgeResult {
        HttpBridgeResult(code: code, body: body, isSuccess: false, appVersionHeader: nil, firstByteTimeout: firstByteTimeout)
    }

    // MARK: - URL parsing

    private struct ParsedURL {
        let host: String
        let port: Int
        let pathAndQuery: String
        /// The percent-encoded PATH alone (no query), "/" when empty — what
        /// `isOptimisticEligible` compares (Android: OkHttp's `encodedPath`).
        let path: String
    }

    // MARK: - Optimistic data (2026-10-26)

    /// Which requests may write their HTTP bytes right behind the SOCKS5 CONNECT
    /// (Tor "optimistic data": one rendezvous-circuit round trip instead of two on
    /// a joined circuit): EXACTLY `GET /` (health probe + pre-unlock warm-up probe)
    /// and `POST /peek` (batch unread prime). Exact method, exact percent-encoded
    /// PATH — the query is not part of it, so `GET /?x=1` is the same read-only
    /// root GET and is eligible; `/peek/` is not.
    ///
    /// WHY so narrow: Tor RE-SENDS optimistic data when it retries a stream on
    /// another circuit, so the relay can receive the request TWICE. Harmless for
    /// these two read-only, idempotent requests; a send, a mint, a PUT/DELETE — and
    /// above all the `GET /inbox/{id}` drain (a leasing GET hides blobs for the lease; the move
    /// transfer inbox's plain GET deletes at request-handling time) — could execute twice. Everything else keeps the
    /// wait-for-reply order. Android sibling: `isOptimisticEligible` in
    /// PlatformHttpClient.android.kt (same rule; also not for an isolated
    /// (credentialed) stream, nor for the user's external proxy).
    static func isOptimisticEligible(method: String, path: String) -> Bool {
        (method == "GET" && path == "/") || (method == "POST" && path == "/peek")
    }

    private func parseURL(_ urlString: String) -> ParsedURL? {
        guard let url = URL(string: urlString),
              let scheme = url.scheme?.lowercased(),
              let host = url.host, !host.isEmpty else { return nil }

        // This transport speaks raw cleartext HTTP/1.1 over the Tor circuit —
        // the v3 .onion rendezvous handshake supplies the encryption + service
        // authentication, so there is no TLS layer here. An `https://` URL would
        // therefore be SILENTLY downgraded to cleartext; reject any non-`http`
        // scheme so a misconfigured relay URL fails closed instead of speaking
        // plaintext under an https-looking address.
        guard scheme == "http" else { return nil }

        let port = url.port ?? 80
        var pathAndQuery = url.path.isEmpty ? "/" : url.path
        if let query = url.query { pathAndQuery += "?\(query)" }
        // URL.path decodes and drops a trailing "/": take the raw encoded path for
        // the exact eligibility compare instead.
        let encodedPath = URLComponents(string: urlString)?.percentEncodedPath ?? ""
        return ParsedURL(host: host, port: port,
                         pathAndQuery: pathAndQuery,
                         path: encodedPath.isEmpty ? "/" : encodedPath)
    }

    // MARK: - Execute

    /// Everything `execute` decides BEFORE a connection is opened, in its original
    /// order: URL parse, SOCKS target, isolation credential, request bytes (header
    /// control-char reject), optimistic-data eligibility.
    private struct ValidatedRequest {
        let parsed: ParsedURL
        let proxyTarget: NWEndpoint
        let isolationUser: String?
        let requestData: Data
        let optimistic: Bool
    }

    private enum RequestValidation {
        case ready(ValidatedRequest)
        /// The early `bridgeFail` result, already logged where it always was.
        case failed(HttpBridgeResult)
    }

    /// The pre-connection validation of `execute` (every early `bridgeFail` return,
    /// same strings, same order, same log lines). No connection is opened here.
    private func validatedRequest(
        method: String,
        url: String,
        body: Data?,
        headers: [String: String],
        socksPort: Int,
        suppressLog: Bool,
        socksAuth: String
    ) -> RequestValidation {
        guard let parsed = parseURL(url) else {
            if !suppressLog {
                LogBuffer.shared.append(level: "E", tag: "TorHttp", message: "\(method) invalid URL")
            }
            return .failed(bridgeFail("Invalid URL"))
        }

        // FIX 2a (2026-09-16): NO per-request line here any more. This used to
        // write `<METHOD> <path> socksPort=NNNNN` on every request, duplicating
        // the `HttpClient` line PlatformHttpClient.ios.kt writes for the same
        // request and carrying a per-process-constant SOCKS port that says
        // nothing. Together with the response line below it made three log lines
        // per relay request on iOS against Android's one, and >90 % of a
        // debug-mode upload was that plumbing. The single surviving line is
        // `<METHOD> <path> → <code>`, written by the Kotlin actual after this
        // call returns (commonMain `httpLogLine`, byte-identical on Android).
        // The transport-level lines below (TCP failed / cancelled / waiting) are
        // NOT per-request narration and stay.

        // Connect to the SOCKS5 proxy — plain TCP, no NWProxyConfiguration
        // (which hangs on iOS simulator). The target is decided by
        // ExternalProxyMode for EVERY request: the embedded Tor's loopback
        // listener on the caller's port, or — in external proxy mode — ALWAYS
        // the user's configured IP literal and port (the caller's port is
        // ignored, so no stale/embedded port can ever be dialled). Invalid or
        // unresolved mode refuses: fail closed, never a fallback. Both are IP
        // literals, so no name is resolved here; the relay's .onion still goes
        // to the proxy unresolved in the CONNECT below (SOCKS5h). Never logged.
        guard let socksTarget = ExternalProxyMode.shared.socksTarget(callerPort: socksPort),
              let nwPort = NWEndpoint.Port(rawValue: socksTarget.port) else {
            if !suppressLog {
                LogBuffer.shared.append(level: "W", tag: "TorHttp", message: "\(method) refused — no SOCKS proxy available")
            }
            return .failed(bridgeFail("SOCKS proxy unavailable"))
        }
        // SOCKS ISOLATION (RendezvousHedge / SocksIsolation): a non-empty
        // credential = RFC 1929 username/password, so the embedded Tor puts this
        // stream in that isolation class. NEVER in external-proxy mode (the user's
        // proxy gets exactly the no-auth handshake it always got), and only a
        // credential of the shape SocksIsolation mints. The value is never logged.
        let isolationUser: String? = {
            guard !socksAuth.isEmpty,
                  !ExternalProxyMode.shared.isExternalThisProcess,
                  SocksIsolation.shared.isValidCredential(credential: socksAuth) else { return nil }
            return socksAuth
        }()
        // The request bytes are built BEFORE the SOCKS exchange (same bytes, same
        // sorted-header rule, same control-char backstop as always), so an eligible
        // request can follow the CONNECT without waiting for Tor's reply. A
        // rejected header now fails before any connection is opened.
        guard let requestData = buildHTTPRequest(method: method, parsed: parsed,
                                                 body: body, headers: headers) else {
            return .failed(bridgeFail("rejected: control char in header"))
        }
        // OPTIMISTIC DATA (see isOptimisticEligible): never for an isolated stream
        // (its own route, parity with Android) nor the user's external proxy (an
        // arbitrary SOCKS server; Android's external client keeps the classic order
        // too). The default no-auth handshake is unchanged, so the stream stays in
        // the same Tor isolation class — and on the same joined circuit — as every
        // other request.
        let optimistic = isolationUser == nil
            && !ExternalProxyMode.shared.isExternalThisProcess
            && SwiftTorHttp.isOptimisticEligible(method: method, path: parsed.path)
        let proxyTarget = NWEndpoint.hostPort(
            host: NWEndpoint.Host(socksTarget.host),
            port: nwPort
        )
        return .ready(ValidatedRequest(parsed: parsed, proxyTarget: proxyTarget,
                                       isolationUser: isolationUser, requestData: requestData,
                                       optimistic: optimistic))
    }

    private func execute(
        method: String,
        url: String,
        body: Data?,
        headers: [String: String],
        socksPort: Int,
        timeout: TimeInterval,
        suppressLog: Bool,
        cancelOnNewCircuit: Bool = false,
        firstByteTimeout: TimeInterval = 0,
        socksAuth: String = ""
    ) -> HttpBridgeResult {

        let validated: ValidatedRequest
        switch validatedRequest(method: method, url: url, body: body, headers: headers,
                                socksPort: socksPort, suppressLog: suppressLog, socksAuth: socksAuth) {
        case .failed(let fail): return fail
        case .ready(let v): validated = v
        }
        let parsed = validated.parsed
        let isolationUser = validated.isolationUser
        let requestData = validated.requestData
        let optimistic = validated.optimistic
        let proxyTarget = validated.proxyTarget
        let connection = NWConnection(to: proxyTarget, using: .tcp)
        // NEWNYM abort registry (see cancelNewCircuitSensitive). Registered BEFORE
        // start(), removed after the request settles below.
        let inFlight: InFlight? = cancelOnNewCircuit ? InFlight(connection) : nil
        if let inFlight {
            inFlightLock.lock()
            newCircuitSensitive[ObjectIdentifier(inFlight)] = inFlight
            inFlightLock.unlock()
        }

        let condition = NSCondition()
        var result = bridgeFail("Timeout")
        var done = false
        // First-byte budget: touched only on `queue` (the connection's state,
        // receive and timer callbacks all run there), so no lock is needed.
        let firstByte = FirstByteWatch()

        let queue = DispatchQueue(label: "com.vg.run.torhttp", qos: .userInitiated)

        connection.stateUpdateHandler = { state in
            switch state {
            case .ready:
                self.socks5Handshake(
                    connection: connection,
                    host: parsed.host,
                    port: parsed.port,
                    isolationUser: isolationUser,
                    optimisticPayload: optimistic ? requestData : nil,
                    onConnectSent: { firstByte.connectSentAt = DispatchTime.now().uptimeNanoseconds }
                ) { socksError in
                    if let err = socksError {
                        condition.lock()
                        result = self.bridgeFail("SOCKS5: \(err)")
                        done = true
                        condition.signal()
                        condition.unlock()
                        return
                    }
                    firstByte.replyAt = DispatchTime.now().uptimeNanoseconds
                    // The stream is CONNECTED through Tor — from here the relay's
                    // answer starts within ~1 s on a healthy circuit. No byte within
                    // the budget = a stalled circuit: cancel, and say why below.
                    if firstByteTimeout > 0 {
                        queue.asyncAfter(deadline: .now() + firstByteTimeout) {
                            if !firstByte.seen {
                                firstByte.timedOut = true
                                connection.cancel()
                            }
                        }
                    }
                    let onFirstByte: () -> Void = {
                        // ONE numbers-only debug line per optimistic stream (no
                        // host, no path, no identifier; LogBuffer is debug-mode
                        // gated). Times are from the CONNECT(+request) send.
                        if optimistic, !firstByte.seen, !suppressLog, firstByte.connectSentAt > 0 {
                            let now = DispatchTime.now().uptimeNanoseconds
                            let replyMs = (firstByte.replyAt &- firstByte.connectSentAt) / 1_000_000
                            let firstMs = (now &- firstByte.connectSentAt) / 1_000_000
                            LogBuffer.shared.append(level: "D", tag: "HttpClient",
                                                    message: "optimistic stream: socks reply +\(replyMs) ms, first byte +\(firstMs) ms")
                        }
                        firstByte.seen = true
                    }
                    let settle: (HttpBridgeResult) -> Void = { httpResult in
                        condition.lock()
                        result = httpResult
                        done = true
                        condition.signal()
                        condition.unlock()
                    }
                    if optimistic {
                        // The request already went out behind the CONNECT and the
                        // reply was consumed byte-exactly: what follows is HTTP.
                        self.receiveHTTP(connection: connection, accumulated: Data(),
                                         onFirstByte: onFirstByte, completion: settle)
                    } else {
                        // SOCKS5 tunnel established — send HTTP over it.
                        self.sendHTTP(connection: connection, requestData: requestData,
                                      onFirstByte: onFirstByte, completion: settle)
                    }
                }

            case .failed(let error):
                if !suppressLog {
                    LogBuffer.shared.append(level: "E", tag: "TorHttp", message: "TCP failed: \(SwiftTorHttp.errorClass(error))")
                }
                condition.lock()
                // Only settle if not already done — a relay that
                // sends a valid response then RSTs the socket would otherwise let this
                // late .failed clobber the good result into a false "TCP failed" +
                // forced retry (the .cancelled case already guards this way).
                if !done {
                    result = self.bridgeFail("TCP failed: \(SwiftTorHttp.errorClass(error))")
                    done = true
                    condition.signal()
                }
                condition.unlock()

            case .cancelled:
                condition.lock()
                if !done {
                    var aborted = false
                    if let inFlight {
                        self.inFlightLock.lock()
                        aborted = inFlight.abortedForNewCircuit
                        self.inFlightLock.unlock()
                    }
                    // A NEWNYM abort is not a timeout: say so (fixed phrase), so the
                    // line does not read "cancelled (Timeout)". Same for the C3
                    // first-byte budget.
                    let firstByteExpired = firstByte.timedOut && !aborted
                    let prev = aborted ? "new circuit" : (firstByteExpired ? "no first byte" : (result.body ?? ""))
                    if !suppressLog {
                        LogBuffer.shared.append(level: "W", tag: "TorHttp", message: "connection cancelled (\(prev.prefix(40)))")
                    }
                    result = self.bridgeFail("Cancelled(\(prev))", firstByteTimeout: firstByteExpired)
                    done = true
                    condition.signal()
                }
                condition.unlock()

            case .waiting(let error):
                if !suppressLog {
                    LogBuffer.shared.append(level: "W", tag: "TorHttp", message: "connection waiting: \(SwiftTorHttp.errorClass(error))")
                }

            default:
                break
            }
        }

        connection.start(queue: queue)

        queue.asyncAfter(deadline: .now() + timeout) {
            connection.cancel()
        }

        condition.lock()
        while !done { condition.wait() }
        condition.unlock()

        if let inFlight {
            inFlightLock.lock()
            newCircuitSensitive.removeValue(forKey: ObjectIdentifier(inFlight))
            inFlightLock.unlock()
        }
        connection.cancel()
        // FIX 2a: the `<METHOD> ← code=NNN` line that used to be written here is
        // gone too — the Kotlin actual writes ONE `<METHOD> <path> → <code>`
        // line for this same request the moment it gets this result back, with
        // the same WARN-only-on-transport-failure rule (code <= 0; a 4xx/5xx is
        // a valid HTTP response, and the relay's `GET /` 404 reachability probe
        // is not a fault). Duplicating it here is what made the status appear
        // twice per request in every upload.
        return result
    }

    // MARK: - SOCKS5 handshake (RFC 1928)

    /// Performs SOCKS5 greeting + CONNECT with domain-name addressing
    /// (type 0x03), so Tor resolves the hostname (SOCKS5h behavior).
    ///
    /// [isolationUser] non-nil (RendezvousHedge): offer ONLY username/password
    /// (method 0x02, RFC 1929) and authenticate as that user with
    /// `SocksIsolation.PASSWORD` — never also 0x00, since a server choosing "no
    /// auth" would silently drop the isolation. Same bytes as Android's
    /// `socks5UserPassHandshake` (commonMain `Socks5Wire`). Errors carry fixed
    /// text + reply bytes only: never the host, never the credential.
    ///
    /// [optimisticPayload] non-nil (see `isOptimisticEligible`): those bytes — the
    /// complete HTTP request — go out in the SAME send as the CONNECT, before the
    /// reply is read; completion(nil) then means "reply consumed, response next".
    private func socks5Handshake(
        connection: NWConnection,
        host: String,
        port: Int,
        isolationUser: String? = nil,
        optimisticPayload: Data? = nil,
        onConnectSent: (() -> Void)? = nil,
        completion: @escaping (String?) -> Void
    ) {
        // Step 1: Client greeting — version 5, 1 method: no-auth (0x00), or
        // username/password (0x02) for an isolated stream.
        let method: UInt8 = isolationUser == nil ? 0x00 : 0x02
        let greeting = Data([0x05, 0x01, method])
        connection.send(content: greeting, completion: .contentProcessed { error in
            if let error = error {
                completion("greeting send: \(SwiftTorHttp.errorClass(error))")
                return
            }
            // Step 2: Read server's method selection (2 bytes)
            connection.receive(minimumIncompleteLength: 2, maximumLength: 2) {
                content, _, _, error in
                guard let data = content, data.count == 2 else {
                    completion("greeting reply: \(error.map { SwiftTorHttp.errorClass($0) } ?? "short")")
                    return
                }
                guard data[0] == 0x05, data[1] == method else {
                    completion("auth method rejected: \(data[0]).\(data[1])")
                    return
                }
                guard let user = isolationUser else {
                    // Step 3: CONNECT request with domain name (type 0x03)
                    self.socks5Connect(connection: connection, host: host,
                                       port: port, optimisticPayload: optimisticPayload,
                                       onConnectSent: onConnectSent, completion: completion)
                    return
                }
                self.socks5UserPassAuth(connection: connection, user: user) { authError in
                    if let authError {
                        completion(authError)
                        return
                    }
                    self.socks5Connect(connection: connection, host: host,
                                       port: port, optimisticPayload: optimisticPayload,
                                       onConnectSent: onConnectSent, completion: completion)
                }
            }
        })
    }

    /// RFC 1929 sub-negotiation: `01 ULEN UNAME PLEN PASSWD` → expect `01 00`.
    private func socks5UserPassAuth(
        connection: NWConnection,
        user: String,
        completion: @escaping (String?) -> Void
    ) {
        let u = Array(user.utf8)
        let p = Array(SocksIsolation.shared.PASSWORD.utf8)
        guard (1...255).contains(u.count), (1...255).contains(p.count) else {
            completion("auth: credential length")
            return
        }
        var req = Data([0x01, UInt8(u.count)])
        req.append(contentsOf: u)
        req.append(UInt8(p.count))
        req.append(contentsOf: p)
        connection.send(content: req, completion: .contentProcessed { error in
            if let error = error {
                completion("auth send: \(SwiftTorHttp.errorClass(error))")
                return
            }
            connection.receive(minimumIncompleteLength: 2, maximumLength: 2) {
                content, _, _, error in
                guard let data = content, data.count == 2 else {
                    completion("auth reply: \(error.map { SwiftTorHttp.errorClass($0) } ?? "short")")
                    return
                }
                guard data[1] == 0x00 else {
                    completion("auth refused: \(data[1])")
                    return
                }
                completion(nil)
            }
        })
    }

    private func socks5Connect(
        connection: NWConnection,
        host: String,
        port: Int,
        optimisticPayload: Data? = nil,
        onConnectSent: (() -> Void)? = nil,
        completion: @escaping (String?) -> Void
    ) {
        let hostBytes = Array(host.utf8)
        guard hostBytes.count <= 255 else {
            completion("hostname too long")
            return
        }
        // VER CMD RSV ATYP(domain) LEN DOMAIN DST.PORT
        var req = Data([0x05, 0x01, 0x00, 0x03, UInt8(hostBytes.count)])
        req.append(Data(hostBytes))
        req.append(UInt8((port >> 8) & 0xFF))
        req.append(UInt8(port & 0xFF))
        // OPTIMISTIC DATA: the HTTP request rides in the same send, right behind
        // the CONNECT. Tor parses the SOCKS request off the front of its buffer and
        // keeps the rest, sending it as optimistic data on a joined rendezvous
        // circuit (else holding it until RELAY_CONNECTED). The reply below is still
        // read byte-exactly, so no HTTP byte of the response is swallowed.
        if let optimisticPayload {
            req.append(optimisticPayload)
        }

        onConnectSent?()
        connection.send(content: req, completion: .contentProcessed { error in
            if let error = error {
                completion("connect send: \(SwiftTorHttp.errorClass(error))")
                return
            }
            // Read the 4-byte fixed reply header: VER REP RSV ATYP. Read EXACTLY
            // 4 bytes (not "up to 256") so a coalesced TCP segment can never let
            // us swallow bytes past the SOCKS reply. The BND.ADDR/BND.PORT tail
            // length is ATYP-dependent and is drained precisely below, leaving the
            // HTTP response untouched in the stream for the next read.
            connection.receive(minimumIncompleteLength: 4, maximumLength: 4) {
                content, _, _, error in
                guard let head = content, head.count == 4 else {
                    completion("connect reply: \(error.map { SwiftTorHttp.errorClass($0) } ?? "short")")
                    return
                }
                let rep = head[1]
                if rep != 0x00 {
                    completion("connect rejected: rep=\(rep)")
                    return
                }
                // Drain exactly BND.ADDR + BND.PORT. addrLen by ATYP:
                // IPv4=4, IPv6=16, domain=1 length byte then that many bytes.
                let atyp = head[3]
                let drainTail: (Int) -> Void = { addrLen in
                    let remaining = addrLen + 2   // BND.ADDR + 2-byte BND.PORT
                    connection.receive(minimumIncompleteLength: remaining, maximumLength: remaining) {
                        _, _, _, drainErr in
                        // Reply fully consumed — the stream now carries only HTTP.
                        completion(drainErr.map { "connect drain: \(SwiftTorHttp.errorClass($0))" })
                    }
                }
                switch atyp {
                case 0x01: drainTail(4)     // IPv4
                case 0x04: drainTail(16)    // IPv6
                case 0x03:
                    // Domain: a length byte precedes the address. Read it, then
                    // drain exactly that many address bytes (+ the 2 port bytes).
                    connection.receive(minimumIncompleteLength: 1, maximumLength: 1) {
                        lenContent, _, _, lenErr in
                        guard let lenData = lenContent, lenData.count == 1 else {
                            completion("connect reply: \(lenErr.map { SwiftTorHttp.errorClass($0) } ?? "short atyp-domain")")
                            return
                        }
                        drainTail(Int(lenData[0]))
                    }
                default:
                    completion("connect: unexpected ATYP \(atyp)")
                }
            }
        })
    }

    // MARK: - HTTP/1.1 over the SOCKS5 tunnel

    /// The raw HTTP/1.1 request bytes, or nil if a header carries a control char
    /// (the caller fails with "rejected: control char in header"). Built before the
    /// SOCKS exchange so an optimistic request can ride behind the CONNECT.
    private func buildHTTPRequest(
        method: String,
        parsed: ParsedURL,
        body: Data?,
        headers: [String: String]
    ) -> Data? {
        // Structural backstop: never interpolate a header
        // key/value containing CR, LF, or other control chars into the raw
        // HTTP/1.1 request — that would be header/request injection. Callers
        // (MessageManager) already validate caps, but this closes the transport
        // boundary regardless of caller, matching OkHttp's behaviour on Android.
        for (key, value) in headers {
            let bad: (String) -> Bool = { s in
                s.unicodeScalars.contains { $0.value < 0x20 || $0.value == 0x7F }
            }
            if bad(key) || bad(value) {
                return nil
            }
        }
        var request = "\(method) \(parsed.pathAndQuery) HTTP/1.1\r\n"
        request += "Host: \(parsed.host)\r\n"
        request += "Connection: close\r\n"
        // Emit the app's headers in a fixed (key-sorted) order. A Swift
        // Dictionary has no stable iteration order, so an unsorted loop would
        // emit the capability/PoW headers in a per-run order — a client
        // fingerprint that distinguishes builds/devices to the relay. Sorting by
        // key (ASCII header names) makes the APP-header order deterministic and
        // matched with Android (toSortedMap). NOTE: only the app headers are
        // unified; the full request still differs by stack (here Host/Connection
        // are prepended and Content-* interleave into the sorted block, vs
        // OkHttp's own layout), so platform stays distinguishable overall.
        for (key, value) in headers.sorted(by: { $0.key < $1.key }) {
            request += "\(key): \(value)\r\n"
        }
        request += "\r\n"

        var requestData = Data(request.utf8)
        if let body = body {
            requestData.append(body)
        }
        return requestData
    }

    private func sendHTTP(
        connection: NWConnection,
        requestData: Data,
        onFirstByte: (() -> Void)? = nil,
        completion: @escaping (HttpBridgeResult) -> Void
    ) {
        connection.send(content: requestData, completion: .contentProcessed { error in
            if let error = error {
                completion(self.bridgeFail("HTTP send: \(SwiftTorHttp.errorClass(error))"))
                return
            }
            self.receiveHTTP(connection: connection, accumulated: Data(),
                             onFirstByte: onFirstByte,
                             completion: completion)
        })
    }

    // #15: cap the response we accumulate so a hostile relay can't OOM the
    // device by streaming an unbounded body. 16 MiB >> any legitimate inbox
    // drain (a max message blob is ~175 KB base64). Keep in sync with the
    // Kotlin clients' MAX_RESPONSE_BYTES.
    private static let maxResponseBytes = 16 * 1024 * 1024

    // Update-nudge: mirrors Kotlin's MAX_APP_VERSION_HEADER_CHARS
    // (PlatformHttpClient.kt) — the wire grammar is MAJOR.MINOR.PATCH, <= 14
    // chars total. Applied here so the full relay header set never transits
    // the bridge as an oversized string; PlatformHttpClient.ios.kt re-checks
    // it again on the Kotlin side (belt-and-braces).
    private static let maxAppVersionHeaderChars = 14

    private func receiveHTTP(
        connection: NWConnection,
        accumulated: Data,
        onFirstByte: (() -> Void)? = nil,
        completion: @escaping (HttpBridgeResult) -> Void
    ) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) {
            content, _, isComplete, error in

            var buffer = accumulated
            if let content = content, !content.isEmpty {
                buffer.append(content)
                onFirstByte?()
            }

            // #15: refuse an over-cap body instead of growing the buffer
            // unbounded toward OOM.
            if buffer.count > SwiftTorHttp.maxResponseBytes {
                completion(self.bridgeFail("Response too large"))
                return
            }

            // A graceful end-of-stream (Connection: close → isComplete) carries the
            // full body. A transport error BEFORE completion means a truncated
            // response — reject it rather than parse a partial body as if whole.
            if isComplete {
                completion(self.parseHttpResponse(buffer))
                return
            }
            if error != nil {
                completion(self.bridgeFail("Connection error before response complete"))
                return
            }
            self.receiveHTTP(connection: connection, accumulated: buffer,
                             onFirstByte: onFirstByte,
                             completion: completion)
        }
    }

    private func parseHttpResponse(_ data: Data) -> HttpBridgeResult {
        guard !data.isEmpty else {
            return bridgeFail("Empty response")
        }
        guard let raw = String(data: data, encoding: .utf8) else {
            return bridgeFail("Non-UTF8 response")
        }

        let separator = "\r\n\r\n"
        guard let separatorRange = raw.range(of: separator) else {
            return bridgeFail("Malformed: no header terminator in \(data.count) bytes")
        }

        let headerSection = raw[raw.startIndex..<separatorRange.lowerBound]
        var body = String(raw[separatorRange.upperBound...])

        let headerLines = headerSection.split(separator: "\r\n")
        let statusLine = headerLines.first ?? ""
        let parts = statusLine.split(separator: " ", maxSplits: 2)
        // Bound the status code to the valid HTTP range BEFORE it
        // reaches the trapping `Int32(code)` narrowing at the return below. A
        // hostile/MITM relay can answer `HTTP/1.1 2147483648 OK` — Int(parts[1])
        // accepts any 64-bit value, and Int32() then TRAPS (release is built -O,
        // which keeps overflow traps) → EXC_BAD_INSTRUCTION crash on EVERY response.
        // Same bug class as the M-A dechunk overflow, one function over. The range
        // check makes an out-of-range status a normal fail-closed -1, not a crash.
        guard parts.count >= 2, let code = Int(parts[1]), (100...599).contains(code) else {
            return bridgeFail("Bad status line (\(statusLine.count) chars)")
        }

        // Honor HTTP/1.1 framing. The controlled relay uses
        // identity encoding + Connection: close, so the common path is unchanged;
        // this adds robustness/parity if a relay or proxy ever responds chunked
        // (which would otherwise leave hex chunk sizes interleaved in the body and
        // silently break JSON parsing on iOS only) or sends a Content-Length.
        var headers: [String: String] = [:]
        for line in headerLines.dropFirst() {
            guard let colon = line.firstIndex(of: ":") else { continue }
            let name = line[line.startIndex..<colon].trimmingCharacters(in: .whitespaces).lowercased()
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            headers[name] = value
        }
        if headers["transfer-encoding"]?.lowercased().contains("chunked") == true {
            // FAIL CLOSED on malformed chunked framing — like
            // every other framing error here — instead of falling back to the raw
            // body with hex chunk-size lines still interleaved (which the old
            // `?? body` did, corrupting downstream JSON). De-chunk over BYTES, not
            // String characters, so a multi-byte-UTF-8 body can't mis-frame
            // (char count != byte count).
            guard let dechunked = SwiftTorHttp.dechunk(Array(body.utf8)) else {
                return bridgeFail("Malformed chunked framing")
            }
            body = String(decoding: dechunked, as: UTF8.self)
        } else if let cl = headers["content-length"].flatMap({ Int($0) }), cl >= 0 {
            // Enforce Content-Length: a body shorter than declared is truncated —
            // reject rather than accept a partial response.
            if body.utf8.count < cl {
                return bridgeFail("Truncated body (\(body.utf8.count) < Content-Length \(cl))")
            }
            body = String(decoding: Array(body.utf8.prefix(cl)), as: UTF8.self)
        }

        // Update-nudge: allowlisted here so the full relay header
        // set never transits the bridge — only this single, already
        // lowercased/trimmed value, and only if it fits the wire grammar's
        // length bound. Oversized/absent -> nil, same as every other
        // unrecognized header (dropped, not truncated).
        let versionHeader = headers["ios-version"].flatMap { $0.count <= SwiftTorHttp.maxAppVersionHeaderChars ? $0 : nil }

        return HttpBridgeResult(
            code: Int32(code),
            body: body.isEmpty ? nil : body,
            isSuccess: (200...299).contains(code),
            appVersionHeader: versionHeader,
            firstByteTimeout: false
        )
    }

    /// Byte-accurate de-chunking of an HTTP/1.1 chunked body. Chunk sizes are BYTE counts, so this walks a [UInt8] by byte index —
    /// a String/Character walk mis-frames a multi-byte-UTF-8 body. Returns nil on
    /// ANY malformed framing; the caller fails the response closed.
    private static func dechunk(_ bytes: [UInt8]) -> [UInt8]? {
        let CR: UInt8 = 0x0D, LF: UInt8 = 0x0A, SEMI: UInt8 = 0x3B
        var out = [UInt8]()
        var i = 0
        while true {
            // Size line: hex digits up to an optional ";ext", terminated by CRLF.
            guard let nl = indexOfCRLF(bytes, from: i) else { return nil }
            var end = i
            while end < nl && bytes[end] != SEMI { end += 1 }
            let hex = String(decoding: bytes[i..<end], as: UTF8.self)
                .trimmingCharacters(in: .whitespaces)
            guard let size = Int(hex, radix: 16), size >= 0 else { return nil }
            i = nl + 2                      // past the CRLF
            if size == 0 { break }          // last chunk
            // Bound WITHOUT the overflowing add. A hostile
            // relay can send a chunk size of `7fffffffffffffff` (Int.max) which
            // passes `size >= 0`; the old `i + size <= bytes.count` then overflows
            // Int, and release builds (-O) TRAP on overflow → EXC_BAD_INSTRUCTION
            // crash before this fail-closed `return nil` is reached (remote DoS,
            // reachable on the pre-pairing mint). `bytes.count - i` is always >= 0
            // here (i = nl+2 <= bytes.count), so this compare cannot overflow.
            guard size <= bytes.count - i else { return nil }
            out.append(contentsOf: bytes[i..<(i + size)])
            i += size
            // Trailing CRLF after the chunk data (required by the spec).
            guard i + 2 <= bytes.count, bytes[i] == CR, bytes[i + 1] == LF else { return nil }
            i += 2
        }
        return out
    }

    /// First index of the CRLF byte pair at or after [from], or nil.
    private static func indexOfCRLF(_ bytes: [UInt8], from: Int) -> Int? {
        guard from >= 0, bytes.count >= 2 else { return nil }
        var i = from
        while i + 1 < bytes.count {
            if bytes[i] == 0x0D, bytes[i + 1] == 0x0A { return i }
            i += 1
        }
        return nil
    }
}

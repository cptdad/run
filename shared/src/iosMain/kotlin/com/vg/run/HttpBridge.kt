package com.vg.run

import platform.Foundation.NSData

// ---------------------------------------------------------------------------
// HttpBridge — interface fulfilled by the Swift layer using NWConnection.
//
// NSURLSession's SOCKS5 proxy support does NOT tunnel DNS queries through
// the proxy (no SOCKS5h support). This means .onion addresses cannot be
// resolved and all hidden-service requests fail with NSURLErrorBadURL.
//
// Network.framework's NWConnection with nw_proxy_config_create_socksv5
// properly sends the target hostname through the SOCKS5 CONNECT command,
// achieving remote DNS (SOCKS5h). This bridge lets the Kotlin shared
// module use that Swift/NWConnection transport for Tor-routed HTTP.
//
// The bridge is registered by `AppState.registerBridges()` (called from `RunApp.init()`, then again at the
// top of `AppState.init()`),
// before `IosAppController()` is constructed and so before any network call.
// ---------------------------------------------------------------------------

data class HttpBridgeResult(
    val code: Int,
    val body: String?,
    val isSuccess: Boolean,
    /**
     * Update-nudge: the relay's `ios-version` response header,
     * already lowercased/trimmed and length-capped on the Swift side
     * (parseHttpResponse) — a single nullable string, NOT a map, to keep the
     * ObjC/Swift surface trivial. Null on every failure path and whenever the
     * header is absent or oversized. See [HttpResult.headers] for the
     * allowlist this feeds into on the Kotlin side.
     */
    val appVersionHeader: String? = null,
    /**
     * The SOCKS5 CONNECT succeeded but no response byte arrived
     * within the request's first-byte budget, so SwiftTorHttp cancelled it.
     * Always false when no budget was passed. See [HttpResult.firstByteTimeout].
     */
    val firstByteTimeout: Boolean = false,
)

interface HttpBridge {
    fun post(
        url: String,
        body: NSData,
        contentType: String,
        headers: Map<String, String>,
        socksPort: Int,
        timeoutSeconds: Int,
        // When true, the bridge must NOT call LogBuffer.append/platformLog
        // for this request — a general per-request opt-out for callers that
        // must not generate log lines for their own traffic. True for exactly
        // one caller: DebugLogUploader's own `POST /debuglog` (threaded from
        // RelayHttp.post's six-argument overload through
        // PlatformHttpClient.post), whose log line would otherwise be new
        // since the uploader's cursor and get shipped by the next tick —
        // a 1 Hz self-feeding loop. False everywhere else.
        suppressLog: Boolean,
        // NEWNYM ABORT (RelayHttp): register this request so
        // [cancelNewCircuitSensitive] can cancel its NWConnection.
        cancelOnNewCircuit: Boolean,
        // SOCKS ISOLATION (RendezvousHedge / SocksIsolation): non-empty = do the
        // SOCKS5 handshake with username/password (RFC 1929, method 0x02 ONLY),
        // username = this value, password = [SocksIsolation.PASSWORD], so Tor puts
        // the stream in that isolation class. "" = today's no-auth handshake. The
        // bridge MUST ignore it in external-proxy mode and must never log it.
        socksAuth: String
    ): HttpBridgeResult

    fun put(
        url: String,
        body: NSData,
        contentType: String,
        headers: Map<String, String>,
        socksPort: Int,
        timeoutSeconds: Int,
        suppressLog: Boolean,
        // See [post].
        socksAuth: String
    ): HttpBridgeResult

    fun get(
        url: String,
        headers: Map<String, String>,
        socksPort: Int,
        timeoutSeconds: Int,
        suppressLog: Boolean,
        cancelOnNewCircuit: Boolean,
        // > 0 = once the SOCKS5 CONNECT succeeded, cancel the request if no
        // response byte arrives within this many seconds and report it as
        // [HttpBridgeResult.firstByteTimeout]. 0 = no such budget.
        firstByteTimeoutSeconds: Int,
        // See [post].
        socksAuth: String
    ): HttpBridgeResult

    // docs/RELAY_SPEC.md (push): DELETE /inbox/{id}/push (push opt-out / vault wipe).
    fun delete(
        url: String,
        headers: Map<String, String>,
        socksPort: Int,
        timeoutSeconds: Int,
        suppressLog: Boolean,
        // See [post].
        socksAuth: String
    ): HttpBridgeResult

    /**
     * Cancels every in-flight request started with `cancelOnNewCircuit = true`
     * (NWConnection.cancel(); the blocked caller returns a transport failure at
     * once). Non-blocking. Returns how many were cancelled.
     */
    fun cancelNewCircuitSensitive(): Int
}

object HttpBridgeHolder {
    var bridge: HttpBridge? = null
}

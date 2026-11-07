package com.vg.run

/**
 * SOCKS LISTENER MOVE AFTER A GUARD-CHANNEL KICK (2026-10-09, connect ladder C4).
 *
 * The kick (`SETCONF DisableNetwork=1` then `=0`, see [HsCircuitWatchdog]'s
 * channel-kick decision) closes EVERY listener, and the re-enable re-binds
 * `SocksPort auto` on a NEW port. Before this, both platforms handed the SOCKS
 * port out exactly once per Tor process (Android `Connected(port)`, iOS
 * `socksPort` + the transport sink), so a kick after bootstrap would have
 * stranded every transport on a closed port. That is why the bootstrap-stall
 * kick refuses once the port is handed out.
 *
 * Instead of rebuilding transports (the restart path, which tears down the
 * session's loops and managers), every Tor-proxied client resolves its port
 * through this table AT EACH CONNECTION:
 *  - Android: `PlatformHttpClient.torProxy` uses a ProxySelector that asks
 *    [resolve] per connection (never `Proxy.NO_PROXY` — always exactly one
 *    SOCKS proxy on 127.0.0.1).
 *  - iOS: `PlatformHttpClient.ios.kt` passes [resolve]'s port to SwiftTorHttp on
 *    every request.
 * So one [completeMove] re-points every existing client — the session's
 * MessageManager, the push/telemetry/bug-report one-shots — and nothing is rebuilt.
 *
 * NEVER A FIXED PORT, NEVER A SQUATTABLE GAP. Between [beginMove] and
 * [completeMove] the old port is closed and a co-installed app could in theory
 * bind it (the L8 threat that made the port `auto` in the first place). For that
 * window [resolve] returns [BLOCKED_PORT] (1): a privileged port no app can listen
 * on, so a request in the gap fails FAST (connection refused) instead of reaching
 * a squatter. A move whose readback fails stays blocked (fail closed); a new Tor
 * process calls [reset].
 *
 * The new port is only ever one Tor reported on its authenticated control channel
 * (`GETINFO net/listeners/socks`, parsed by [parseGetinfoSocksPort]), and only a
 * 127.0.0.1 listener is accepted. Ports are not identifiers and are never on the
 * wire, but the panel line still carries none ([HsCircuitWatchdog.SOCKS_MOVED_PHRASE]).
 */
object SocksPortRedirect {

    /** Connection target while a move is unconfirmed: nothing can listen there. */
    const val BLOCKED_PORT = 1

    private val lock = SyncLock()
    /** old port → new port, chained if a port ever moves twice. */
    private val moved = HashMap<Int, Int>()
    /** Ports whose listener is gone and whose replacement is not known yet. */
    private val blocked = HashSet<Int>()

    /** The port a client created for [port] must connect to NOW. */
    fun resolve(port: Int): Int = lock.withLock {
        var p = port
        var hops = 0
        while (hops < 8) {
            if (p in blocked) return@withLock BLOCKED_PORT
            val next = moved[p] ?: return@withLock p
            p = next
            hops++
        }
        BLOCKED_PORT   // a cycle cannot be built through the API; fail closed anyway
    }

    /** The kick is about to close [oldPort]'s listener: block it until [completeMove]. */
    fun beginMove(oldPort: Int) {
        if (oldPort <= 0) return
        lock.withLock { blocked += oldPort }
    }

    /** Tor re-bound the listener on [newPort]: re-point [oldPort] (and everything
     *  that resolved to it) there. [newPort] == [oldPort] = Tor confirmed the SAME
     *  port (or the kick never closed it): just unblock. Refuses a non-port or a
     *  privileged port — the old port then stays blocked (fail closed). */
    fun completeMove(oldPort: Int, newPort: Int): Boolean {
        if (oldPort <= 0 || newPort !in MIN_LISTENER_PORT..65535) return false
        if (newPort == oldPort) {
            lock.withLock { blocked -= oldPort }
            return true
        }
        lock.withLock {
            blocked -= newPort
            moved.remove(newPort)
            moved[oldPort] = newPort
            blocked -= oldPort
        }
        return true
    }

    /** A fresh Tor process (Android restart / corrupt-state retry) owns its own
     *  ports: forget every move and block. */
    fun reset() {
        lock.withLock {
            moved.clear()
            blocked.clear()
        }
    }

    /** Lowest port `SocksPort auto` can hand out to an app process. */
    internal const val MIN_LISTENER_PORT = 1024

    /**
     * The SOCKS port from a `GETINFO net/listeners/socks` reply, or null.
     *
     * Reply shape: `250-net/listeners/socks="127.0.0.1:41234"` followed by
     * `250 OK` (a single-listener reply may also arrive as one
     * `250 net/listeners/socks=…` line). Only a quoted or bare `127.0.0.1:<port>`
     * entry is accepted; any other address — or none — is null (fail closed).
     * Pure, so the readback both platforms run is unit-tested once.
     */
    fun parseGetinfoSocksPort(replyLines: List<String>): Int? {
        for (raw in replyLines) {
            val line = raw.trimEnd('\r', '\n')
            if (!line.startsWith("250")) continue
            val key = line.indexOf("net/listeners/socks=")
            if (key < 0) continue
            val value = line.substring(key + "net/listeners/socks=".length)
            for (entry in value.split(' ')) {
                val e = entry.trim().removeSurrounding("\"")
                if (!e.startsWith("127.0.0.1:")) continue
                val port = e.removePrefix("127.0.0.1:").toIntOrNull() ?: continue
                if (port in MIN_LISTENER_PORT..65535) return port
            }
        }
        return null
    }
}

package com.vg.run

// ---------------------------------------------------------------------------
// IosExternalProxyStore — iOS persistence + validation for the EXTERNAL SOCKS
// PROXY MODE (commonMain ExternalTorProxy, docs/external-socks-proxy.md).
//
// The setting lives in the PRE-UNLOCK store: the platform KeyValueStore
// (Keychain, KeychainHelper.kvPut's strict this-device-only class), the same
// store DebugMode's startup read uses — it must be readable before the vault
// opens because the embedded Tor starts speculatively on the PIN screen and
// this setting decides whether it may start AT ALL. It is a KeyValueStore row,
// so every wipe path's KeychainBridge.kvDeleteAll() sweep clears it with the
// rest (IosAppController.emergencyWipe, RunApp's DEBUG test wipe); AppState
// additionally removes it explicitly as a belt (clearWipeResidue) and on the
// reinstall-over-surviving-Keychain launch branch.
//
// Every validation decision is the SHARED one (ExternalTorProxy.classify /
// parse / encode) — Swift never re-implements the IP-literal rules. The Swift
// surface here deliberately uses only primitives (Int state codes, String,
// Int, Boolean) so the commonMain types never have to cross the ObjC boundary.
//
// Never logs the host or port: only the class ("loopback"/"lan") and outcomes.
// Nothing here throws across the bridge (a Kotlin exception reaching Swift
// terminates the process): every store call is wrapped.
// ---------------------------------------------------------------------------

/** Result of [IosExternalProxyStore.read]. [host]/[port] are set only for [IosExternalProxyStore.STATE_ON]. */
class IosExternalProxyRead(
    val state: Int,
    val host: String?,
    val port: Int,
    /** True when [host] classifies as LAN (non-loopback) — drives the unencrypted-on-your-network warning. */
    val isLan: Boolean,
)

object IosExternalProxyStore {
    /** No value stored — the embedded Tor is the transport. */
    const val STATE_OFF = 0
    /** A valid host:port is stored — external proxy mode. */
    const val STATE_ON = 1
    /** A value IS stored but does not parse — still external mode, fail closed (no transport). */
    const val STATE_INVALID = 2
    /** The store could not be read right now (locked keybag / securityd glitch) — UNKNOWN. */
    const val STATE_UNREADABLE = -1

    /** [validate] verdicts. */
    const val VALID_LOOPBACK = 0
    const val VALID_LAN = 1
    const val INVALID_HOST = -1
    const val INVALID_PORT = -2

    /**
     * Tri-state read. A transient Keychain failure is UNREADABLE, never OFF —
     * reading it as OFF would let the embedded Tor start for a user who chose
     * to forbid it.
     */
    fun read(): IosExternalProxyRead {
        val raw = try {
            KeyValueStore().getString(ExternalTorProxy.PREF_KEY)
        } catch (_: Throwable) {
            return IosExternalProxyRead(STATE_UNREADABLE, null, 0, false)
        } ?: return IosExternalProxyRead(STATE_OFF, null, 0, false)
        val cfg = try { ExternalTorProxy.parse(raw) } catch (_: Throwable) { null }
            ?: return IosExternalProxyRead(STATE_INVALID, null, 0, false)
        val cls = try { ExternalTorProxy.classify(cfg.host) } catch (_: Throwable) { HostClass.INVALID }
        if (cls == HostClass.INVALID) return IosExternalProxyRead(STATE_INVALID, null, 0, false)
        return IosExternalProxyRead(STATE_ON, cfg.host, cfg.port, cls == HostClass.LAN)
    }

    /**
     * Validates user input with the shared rules. Accepts an IPv6 literal with or
     * without brackets. Returns [VALID_LOOPBACK], [VALID_LAN], [INVALID_HOST] or
     * [INVALID_PORT].
     */
    fun validate(host: String, port: Int): Int = try {
        val h = normalizeHost(host)
        when {
            ExternalTorProxy.classify(h) == HostClass.INVALID -> INVALID_HOST
            port !in 1..65535 -> INVALID_PORT
            else -> {
                // Round-trip through the shared encoder + parser: what we would
                // store must be exactly what the next launch will accept.
                val parsed = ExternalTorProxy.parse(ExternalTorProxy.encode(ExternalTorProxyConfig(h, port)))
                when {
                    parsed == null -> INVALID_HOST
                    ExternalTorProxy.classify(parsed.host) == HostClass.LAN -> VALID_LAN
                    else -> VALID_LOOPBACK
                }
            }
        }
    } catch (_: Throwable) {
        INVALID_HOST
    }

    /**
     * Persists a validated host:port. Returns true only when the value READS
     * BACK identically (kvPut fails silently on a locked keybag).
     */
    fun save(host: String, port: Int): Boolean = try {
        if (validate(host, port) < 0) {
            false
        } else {
            val encoded = ExternalTorProxy.encode(ExternalTorProxyConfig(normalizeHost(host), port))
            val store = KeyValueStore()
            store.putStringSync(ExternalTorProxy.PREF_KEY, encoded)
            store.getString(ExternalTorProxy.PREF_KEY) == encoded
        }
    } catch (_: Throwable) {
        false
    }

    /** Removes the setting. Returns whether it is CONFIRMED gone. */
    fun clear(): Boolean = try {
        KeyValueStore().remove(ExternalTorProxy.PREF_KEY)
    } catch (_: Throwable) {
        false
    }

    private fun normalizeHost(host: String): String {
        val t = host.trim()
        return if (t.length >= 2 && t.startsWith("[") && t.endsWith("]")) t.substring(1, t.length - 1) else t
    }
}

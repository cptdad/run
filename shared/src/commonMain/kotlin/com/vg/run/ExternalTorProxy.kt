package com.vg.run

// ---------------------------------------------------------------------------
// EXTERNAL SOCKS PROXY MODE (2026-10-19) — the pure, shared half.
//
// A user who runs their own SOCKS5 proxy (Orbot, a tor daemon on a LAN box, a
// logging SOCKS proxy in front of Tor) can point ALL relay traffic at it and
// thereby SEE every request Rún makes — and verify that the embedded Tor is
// never used. Read once per launch from the platform's PRE-UNLOCK store
// (Android: its own SharedPreferences file, iOS: the pre-unlock store the
// speculative Tor start reads), so a change takes effect at the NEXT launch.
// While a config is present the embedded Tor is never constructed, and the
// relay client is a SOCKS5h client (remote DNS — the onion goes to the proxy
// unresolved) pointed at the configured address. FAIL CLOSED: an unreachable
// proxy leaves messaging unavailable; there is no fallback to the embedded Tor
// or to direct HTTP.
//
// WHY ONLY IP LITERALS. A hostname would have to be resolved by THIS device
// before the first byte goes to the proxy — a DNS query that is both a leak
// (it names the proxy host to the resolver) and an attack surface (a resolver
// that answers with a public address silently turns "my LAN box" into "the
// internet"). An IP literal needs no resolution at all, and limiting it to
// loopback / RFC 1918 / link-local means the proxy hop can never leave the
// local network segment. Everything else is INVALID.
//
// Stored form: "a.b.c.d:port" or "[::1]:port". Parsing is strict on purpose
// (no whitespace, no leading zeros, no sign, ASCII digits only, octets <= 255,
// port 1..65535): a lenient parser is where "0127.0.0.1" (octal on some
// stacks) or a full-width digit sneaks a different address past the class
// check than the one the socket layer finally dials.
//
// Nothing here ever logs the host or the port — the connection-log phrases
// below are the ONLY lines either platform writes about this mode.
// ---------------------------------------------------------------------------

/** A validated external SOCKS5 proxy address: an IP literal + a port. */
data class ExternalTorProxyConfig(val host: String, val port: Int)

/** What kind of address an external-proxy host is. */
enum class HostClass {
    /** 127.0.0.0/8 or `::1` — the proxy runs on this device (e.g. Orbot). */
    LOOPBACK,

    /**
     * 10/8, 172.16/12, 192.168/16 or 169.254/16 — the proxy runs elsewhere on
     * the local network. Allowed, but the UI warns: the hop between this phone
     * and the proxy is unencrypted on that network.
     */
    LAN,

    /** Anything else, including every hostname. Never accepted. */
    INVALID,
}

object ExternalTorProxy {

    /**
     * Pre-unlock store key. Android: in its own prefs file
     * (`RunViewModel.EXT_TOR_PROXY_PREFS_NAME`, deleted by every wipe path),
     * device-key SEALED — see [readStored].
     * iOS: the same literal in its pre-unlock store, on every wipe path's
     * purge list.
     */
    const val PREF_KEY: String = "ext_tor_proxy"

    /** The only IPv6 literal accepted (loopback). */
    const val IPV6_LOOPBACK: String = "::1"

    /** Upper bound on a stored/entered value; anything longer is rejected unread. */
    private const val MAX_STORED_CHARS = 32

    /**
     * Parses the stored form. Null on absent, empty, malformed or non-local
     * input. A null here is NOT "mode off" for the launch path: presence of a
     * stored value decides the mode ([readStored] / [isConfiguredButInvalid]),
     * so a corrupt value fails closed instead of re-enabling the embedded Tor.
     */
    fun parse(stored: String?): ExternalTorProxyConfig? {
        if (stored.isNullOrEmpty() || stored.length > MAX_STORED_CHARS) return null
        val host: String
        val portText: String
        if (stored.startsWith("[")) {
            val close = stored.indexOf(']')
            if (close < 0 || close + 1 >= stored.length || stored[close + 1] != ':') return null
            host = stored.substring(1, close)
            // Only the bracketed form may carry an IPv6 literal, and only ::1.
            if (host != IPV6_LOOPBACK) return null
            portText = stored.substring(close + 2)
        } else {
            val colon = stored.lastIndexOf(':')
            if (colon <= 0) return null
            host = stored.substring(0, colon)
            // An unbracketed host must be IPv4 — a stray colon means an
            // unbracketed IPv6 literal, which is ambiguous with the port.
            if (host.contains(':')) return null
            portText = stored.substring(colon + 1)
        }
        val port = parsePort(portText) ?: return null
        if (classify(host) == HostClass.INVALID) return null
        return ExternalTorProxyConfig(host, port)
    }

    /**
     * The stored form of [c]. Formatting only — it does NOT validate; build
     * configs through [fromInput] or [parse], and [parse] remains the gate on
     * the way back in.
     */
    fun encode(c: ExternalTorProxyConfig): String =
        if (c.host.contains(':')) "[${c.host}]:${c.port}" else "${c.host}:${c.port}"

    /**
     * Classifies a BARE host (no brackets, no port). Strict: only canonical
     * dotted-quad IPv4 or exactly `::1`; never a hostname, never resolves.
     */
    fun classify(host: String): HostClass {
        if (host == IPV6_LOOPBACK) return HostClass.LOOPBACK
        val o = ipv4Octets(host) ?: return HostClass.INVALID
        return when {
            o[0] == 127 -> HostClass.LOOPBACK
            o[0] == 10 -> HostClass.LAN
            o[0] == 172 && o[1] in 16..31 -> HostClass.LAN
            o[0] == 192 && o[1] == 168 -> HostClass.LAN
            o[0] == 169 && o[1] == 254 -> HostClass.LAN
            else -> HostClass.INVALID
        }
    }

    // -----------------------------------------------------------------------
    // Settings-screen helpers (shared so both platforms validate identically)
    // -----------------------------------------------------------------------

    /** Inline validation outcome for the settings form. */
    enum class InputError { NONE, HOST, PORT }

    /**
     * Validates the settings form's two fields EXACTLY as typed (no trimming —
     * the strict rule applies to input as much as to storage). [hostText] may
     * be `::1` or `[::1]`.
     */
    fun validateInput(hostText: String, portText: String): InputError {
        if (classify(unbracket(hostText)) == HostClass.INVALID) return InputError.HOST
        if (parsePort(portText) == null) return InputError.PORT
        return InputError.NONE
    }

    /** The config for a valid form, or null — see [validateInput]. */
    fun fromInput(hostText: String, portText: String): ExternalTorProxyConfig? {
        if (validateInput(hostText, portText) != InputError.NONE) return null
        return ExternalTorProxyConfig(unbracket(hostText), parsePort(portText)!!)
    }

    /** True when the host is on the LAN (the UI shows the unencrypted-hop warning). */
    fun isLan(hostText: String): Boolean = classify(unbracket(hostText)) == HostClass.LAN

    /**
     * A value IS stored under [PREF_KEY] but does not parse. The launch path
     * must treat this as "external mode, misconfigured" — fail CLOSED (no
     * embedded Tor, no relay) — never as "mode off": a corrupted/planted value
     * must not silently re-enable the embedded Tor for a user who asked for
     * it never to run.
     */
    fun isConfiguredButInvalid(stored: String?): Boolean =
        stored != null && parse(stored) == null

    // -----------------------------------------------------------------------
    // Connection-log phrases — the ONLY lines either platform writes about this
    // mode, word for word identical on iOS, none carrying a ConnectionLog.Code.
    // No host, no port: the class and the outcome are the whole diagnostic.
    // -----------------------------------------------------------------------

    /** `ext proxy: loopback in use, embedded Tor disabled` — at connect start. */
    fun inUseLogLine(hostClass: HostClass): String =
        "ext proxy: ${hostClass.name.lowercase()} in use, embedded Tor disabled"

    /** `ext proxy: loopback reachable` / `ext proxy: lan unreachable`. */
    fun statusLogLine(hostClass: HostClass, reachable: Boolean): String =
        "ext proxy: ${hostClass.name.lowercase()} ${if (reachable) "reachable" else "unreachable"}"

    /** A stored value exists but does not parse / does not authenticate (fail closed). */
    const val PHRASE_INVALID_CONFIG: String = "ext proxy: setting invalid - messaging unavailable"

    /** The stored value could not be read at all (device key / keychain outage; fail closed). */
    const val PHRASE_UNREADABLE_CONFIG: String = "ext proxy: setting unreadable - messaging unavailable"

    /** External mode with a non-onion relay URL: the SOCKS path only carries onions (fail closed). */
    const val PHRASE_RELAY_NOT_ONION: String = "ext proxy: relay is not an onion - messaging unavailable"

    // -----------------------------------------------------------------------
    // Sealed persistence (Android; usable by any platform with a CryptoProvider)
    //
    // The value is DEVICE-KEY SEALED ([SealedPref], slot [SEALED_SLOT]) rather
    // than stored as plaintext, same rule as the Debug-mode flag: a
    // planted plaintext "192.168.x.y:port" in the app's prefs would otherwise
    // route every relay request — capability headers included, which the proxy
    // sees as the Tor client — through an attacker's box. A planted or tampered
    // value is UNAUTHENTICATED and reads as [StoredState.INVALID]: external mode
    // stays ON and fails closed (no relay, no embedded Tor), so planting can
    // neither redirect traffic nor silently switch the mode off.
    // -----------------------------------------------------------------------

    /** AEAD context binding the sealed value to this one slot. */
    internal const val SEALED_SLOT: String = "ext-tor-proxy:v1"

    /** What the pre-unlock store holds for this launch. */
    enum class StoredState {
        /** Nothing stored — external mode is off. */
        OFF,

        /** An authenticated value that parses — [StoredRead.config] is set. */
        VALID,

        /** Something is stored but it does not authenticate or parse. Mode ON, fail closed. */
        INVALID,

        /** Something is stored but the device key could not open it now. Mode ON, fail closed. */
        UNREADABLE,
    }

    class StoredRead(val state: StoredState, val config: ExternalTorProxyConfig?) {
        /** External mode is ON for this launch (whatever the state of the value). */
        val modeOn: Boolean get() = state != StoredState.OFF
    }

    /** Reads + authenticates + parses the stored setting. Never throws. */
    fun readStored(store: KeyValueStore, crypto: CryptoProvider): StoredRead =
        readStoredIn(store.asDebugModeStore(), crypto.asDeviceKeyCipher())

    /**
     * Seals and persists [config] (or removes the setting when null), then
     * reads it back through the same path the next launch uses. True only
     * when the stored state verifiably matches the request.
     */
    fun writeStored(store: KeyValueStore, crypto: CryptoProvider, config: ExternalTorProxyConfig?): Boolean =
        writeStoredIn(store.asDebugModeStore(), crypto.asDeviceKeyCipher(), config)

    internal fun readStoredIn(store: DebugModeStore, cipher: DeviceKeyCipher): StoredRead {
        val raw = try {
            store.get(PREF_KEY)
        } catch (_: Exception) {
            return StoredRead(StoredState.UNREADABLE, null)
        } ?: return StoredRead(StoredState.OFF, null)
        val read = SealedPref.open(cipher, SEALED_SLOT, raw)
        return when (read.state) {
            SealedPrefState.ABSENT -> StoredRead(StoredState.OFF, null)
            SealedPrefState.UNREADABLE -> StoredRead(StoredState.UNREADABLE, null)
            SealedPrefState.UNAUTHENTICATED -> StoredRead(StoredState.INVALID, null)
            SealedPrefState.PROVEN -> {
                val cfg = parse(read.value)
                if (cfg != null) StoredRead(StoredState.VALID, cfg) else StoredRead(StoredState.INVALID, null)
            }
        }
    }

    internal fun writeStoredIn(store: DebugModeStore, cipher: DeviceKeyCipher, config: ExternalTorProxyConfig?): Boolean =
        try {
            if (config == null) {
                store.remove(PREF_KEY) && readStoredIn(store, cipher).state == StoredState.OFF
            } else {
                val encoded = encode(config)
                // Only a value that parses back is ever written.
                if (parse(encoded) != config) return false
                store.putSync(PREF_KEY, SealedPref.seal(cipher, SEALED_SLOT, encoded))
                readStoredIn(store, cipher).config == config
            }
        } catch (_: Exception) {
            false
        }

    // -----------------------------------------------------------------------
    // Internals
    // -----------------------------------------------------------------------

    /**
     * Raw address bytes of a VALID host (4 for IPv4, 16 for `::1`), for the
     * socket layer to build its address WITHOUT any name lookup
     * (`InetAddress.getByAddress`). Null for anything [classify] rejects.
     */
    fun addressBytes(host: String): ByteArray? {
        if (classify(host) == HostClass.INVALID) return null
        if (host == IPV6_LOOPBACK) return ByteArray(16).also { it[15] = 1 }
        val o = ipv4Octets(host) ?: return null
        return ByteArray(4) { o[it].toByte() }
    }

    private fun unbracket(h: String): String =
        if (h.length >= 2 && h.startsWith("[") && h.endsWith("]")) h.substring(1, h.length - 1) else h

    private fun isAsciiDigits(s: String): Boolean = s.isNotEmpty() && s.all { it in '0'..'9' }

    /** Canonical decimal 1..65535: ASCII digits, no sign, no leading zero, ≤ 5 chars. */
    internal fun parsePort(s: String): Int? {
        if (!isAsciiDigits(s) || s.length > 5 || s[0] == '0') return null
        val v = s.toInt()
        return if (v in 1..65535) v else null
    }

    /** Canonical dotted quad: 4 parts, ASCII digits, 1–3 chars, no leading zero, ≤ 255. */
    private fun ipv4Octets(host: String): IntArray? {
        if (host.length > 15) return null
        val parts = host.split('.')
        if (parts.size != 4) return null
        val out = IntArray(4)
        for (i in 0 until 4) {
            val p = parts[i]
            if (!isAsciiDigits(p) || p.length > 3) return null
            if (p.length > 1 && p[0] == '0') return null
            val v = p.toInt()
            if (v > 255) return null
            out[i] = v
        }
        return out
    }
}

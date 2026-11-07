package com.vg.run

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Regression guard: the Android torrc must set SafeSocks and
 * SafeLogging (the iOS side already did), so the embedded Tor rejects
 * pre-resolved-IP SOCKS requests and scrubs addresses from its on-disk log.
 */
class TorrcConfigTest {

    private val torrc = buildTorrc("/data/tor/data", "/cache/tor", "/data/tor/data/tor.log")

    @Test
    fun torrc_sets_safe_socks() {
        assertTrue(
            torrc.lineSequence().any { it.trim() == "SafeSocks 1" },
            "Android torrc must set 'SafeSocks 1':\n$torrc",
        )
    }

    @Test
    fun torrc_sets_safe_logging() {
        assertTrue(
            torrc.lineSequence().any { it.trim() == "SafeLogging 1" },
            "Android torrc must set 'SafeLogging 1':\n$torrc",
        )
    }

    @Test
    fun torrc_embeds_the_supplied_paths() {
        assertTrue(torrc.contains("DataDirectory /data/tor/data"))
        assertTrue(torrc.contains("Log notice file /data/tor/data/tor.log"))
    }

    /**
     * Mobile-reliability parity with iOS (TorManager.swift): a FIXED
     * circuit-build timeout instead of the adaptive default that prematurely
     * kills slower-but-valid .onion circuits, plus extra entry guards. Regression
     * guard so a future torrc edit can't silently drop back to Tor defaults.
     *
     * The value moved 90 -> 45 (lever 3, 2026-09-11): a dead intro/rendezvous
     * path is what the connect-time tail is made of, and the app's stream-level
     * budget cannot abandon a CIRCUIT. Keep it in lockstep with iOS, and never
     * below ~30 s — below that, genuinely slow mobile builds start being killed,
     * which is the failure adaptive CBT was disabled for.
     */
    @Test
    fun torrc_pins_mobile_circuit_settings() {
        assertTrue(
            torrc.lineSequence().any { it.trim() == "LearnCircuitBuildTimeout 0" },
            "Android torrc must disable adaptive CBT (parity with iOS):\n$torrc",
        )
        assertTrue(
            torrc.lineSequence().any { it.trim() == "CircuitBuildTimeout 45" },
            "Android torrc must pin CircuitBuildTimeout 45 (lever 3; keep in lockstep with iOS):\n$torrc",
        )
        // NumEntryGuards 8 is a KNOWING reliability decision
        // (see buildTorrc kdoc) — pinned present, in lockstep with iOS.
        assertTrue(
            torrc.lineSequence().any { it.trim() == "NumEntryGuards 8" },
            "Android torrc must set NumEntryGuards 8 (parity with iOS):\n$torrc",
        )
    }

    /**
     * Guideline 2.1: "Add Contact" loaded
     * indefinitely because Tor never finished bootstrapping on Apple's
     * IPv6-only NAT64 review-lab Wi-Fi, where IPv4-literal dials (Tor's
     * default) cannot be translated. Regression guard so a future torrc edit
     * can't silently drop these (parity with iOS TorManager.swift).
     */
    @Test
    fun torrc_enables_ipv6_client_support() {
        assertTrue(
            torrc.lineSequence().any { it.trim() == "ClientUseIPv6 1" },
            "Android torrc must set 'ClientUseIPv6 1' (Guideline 2.1 IPv6-only NAT64 fix):\n$torrc",
        )
        assertTrue(
            torrc.lineSequence().any { it.trim() == "ClientPreferIPv6ORPort auto" },
            "Android torrc must set 'ClientPreferIPv6ORPort auto' (Guideline 2.1 IPv6-only NAT64 fix):\n$torrc",
        )
    }

    /**
     * The NEWNYM self-heal control channel (Android parity with iOS
     * config.controlSocket + cookieAuthentication). It MUST be a UNIX-domain
     * ControlSocket inside the app-private Tor data dir, cookie-authenticated, and
     * derived from the SAME data dir path passed to [buildTorrc] (never hardcoded).
     */
    @Test
    fun torrc_sets_a_cookie_authenticated_unix_control_socket() {
        assertTrue(
            torrc.lineSequence().any { it.trim() == "ControlSocket /data/tor/data/cp" },
            "Android torrc must set a UNIX-domain 'ControlSocket <dataDir>/cp' for NEWNYM self-heal:\n$torrc",
        )
        assertTrue(
            torrc.lineSequence().any { it.trim() == "CookieAuthentication 1" },
            "Android torrc must set 'CookieAuthentication 1' for the control socket:\n$torrc",
        )
        assertTrue(
            torrc.contains("ControlSocket /data/tor/data/$TOR_CONTROL_SOCKET_NAME"),
            "the control socket path must be derived from the supplied dataDir + " +
                "TOR_CONTROL_SOCKET_NAME, never hardcoded:\n$torrc",
        )
    }

    /**
     * HARD SECURITY CONSTRAINT: NEVER a TCP `ControlPort`. A
     * localhost TCP control listener is discoverable/bindable by any co-installed
     * app. The control channel is UNIX-domain only. This guard fails loudly if a
     * future edit ever reintroduces a TCP control listener.
     */
    @Test
    fun torrc_never_opens_a_tcp_control_port() {
        assertFalse(
            torrc.lineSequence().any { it.trim().startsWith("ControlPort") },
            "Android torrc must NEVER open a TCP ControlPort — a localhost control listener is " +
                "bindable by any co-installed app (L8 regression):\n$torrc",
        )
    }
}

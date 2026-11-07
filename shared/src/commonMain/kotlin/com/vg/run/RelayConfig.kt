package com.vg.run

// ---------------------------------------------------------------------------
// RelayConfig — central configuration for the relay server URL.
//
// The relay server is the blind intermediary that stores and forwards
// encrypted message blobs between devices. It never sees plaintext.
//
// The URL is set via the gitignored relay.properties file at the repo root
// (key: relayOnionUrl). It is compiled into the shared module by the
// generateRelayUrl Gradle task and shared by both Android and iOS.
//
// Debug-only overrides (all gated compile-time on BuildConfig.DEBUG /
// Platform.isDebugBinary inside the platform actuals):
//   • Android emulator → "http://10.0.2.2:8080" (host machine loopback).
//   • iOS simulator     → "http://localhost:8080".
//   • Physical device + debug build → the dev/test relay (relayDevOnionUrl /
//     RELAY_DEV_ONION_URL) when configured (a release build never carries it).
// A release build always uses the production URL from relay.properties; the
// generateRelayUrl task additionally fails the build if the dev URL ever
// equals the production URL.
// ---------------------------------------------------------------------------

// SEVERAL ONION ADDRESSES: a relay may be configured under up to
// three onion addresses of the SAME backend (comma-separated relayOnionUrl /
// relayDevOnionUrl — see shared/build.gradle.kts). [CANDIDATE_URLS] is that
// ordered list for the running binary (release-first gating, slot 1 first);
// [BASE_URL] is the address the SESSION uses: slot 1 until the descriptor race
// ([RelayAddressRace]) has a winner, then the winner. With one address the race
// never runs and [BASE_URL] is slot 1, exactly as before.
// ---------------------------------------------------------------------------

expect object RelayConfig {
    /**
     * Every configured address of the relay this binary talks to, slot 1 first
     * (empty = no relay configured). Release builds are pinned to the production
     * list; the dev list and the emulator/simulator loopback are debug-only.
     */
    val CANDIDATE_URLS: List<String>

    /**
     * Base URL of the relay server (no trailing slash): the session's selected
     * address — slot 1 of [CANDIDATE_URLS] until [RelayAddressRace] decides a
     * faster one. Read it at USE time; do not cache it across a connect.
     */
    val BASE_URL: String

    /**
     * True when slot 1 of [CANDIDATE_URLS] targets a Tor hidden service (.onion)
     * (every extra address is an onion of the same relay by construction).
     * When true, all relay traffic is routed through an embedded Tor
     * SOCKS5 proxy. When false, direct HTTP is used in debug/emulator builds only;
     * a release build refuses a non-onion relay and disables messaging (fail-closed).
     */
    val isTorRequired: Boolean
}

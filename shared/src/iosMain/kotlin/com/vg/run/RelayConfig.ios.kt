package com.vg.run

import platform.posix.getenv
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.toKString
import kotlin.native.Platform

// ---------------------------------------------------------------------------
// RelayConfig — iOS actual with simulator detection.
//
// Devices use the relay URL compiled into the shared module from the
// gitignored relay.properties at the repo root (see shared/build.gradle.kts
// generateRelayUrl task); DEBUG binaries on physical devices prefer the
// dev-relay list when one is configured (see CANDIDATE_URLS below). The same
// lists are used by the Android actual, so relay.properties is the single source
// of truth across platforms.
//
// The simulator uses direct HTTP to the host machine because Tor cannot
// run inside the iOS simulator. Detected via the SIMULATOR_DEVICE_NAME env
// var that Xcode sets for simulator processes.
// ---------------------------------------------------------------------------

@OptIn(ExperimentalForeignApi::class, kotlin.experimental.ExperimentalNativeApi::class)
actual object RelayConfig {

    private val isSimulator: Boolean =
        getenv("SIMULATOR_DEVICE_NAME")?.toKString().isNullOrEmpty().not()

    actual val CANDIDATE_URLS: List<String> =
        // Compile-gate the simulator clearnet override on a DEBUG
        // binary, mirroring Android's BuildConfig.DEBUG gate. The release
        // XCFramework is built optimized (Platform.isDebugBinary == false), so
        // the list can never resolve to the localhost cleartext host in a shipped
        // build even if SIMULATOR_DEVICE_NAME were somehow set. (The clearnet path
        // is already #if DEBUG-gated + fail-closed in AppState.startTorOrDirect;
        // this closes the parity gap at the config source.)
        // Dev-relay addition (2026-07-17): debug binaries on PHYSICAL devices use
        // the dev/test relay (relayDevOnionUrl*) when configured, keeping test
        // traffic off the production relay. Release stays structurally pinned to
        // RELAY_URLS_FROM_PROPERTIES — the first branch wins before any override.
        when {
            !Platform.isDebugBinary -> RELAY_URLS_FROM_PROPERTIES
            isSimulator -> listOf("http://localhost:8080")
            RELAY_DEV_URLS_FROM_PROPERTIES.isNotEmpty() -> RELAY_DEV_URLS_FROM_PROPERTIES
            else -> RELAY_URLS_FROM_PROPERTIES
        }

    /** The session's address: slot 1 until the descriptor race picks a faster one. */
    actual val BASE_URL: String
        get() = RelayEndpoints.race.currentBaseUrl()

    /**
     * True when the session relay (slot 1 of [CANDIDATE_URLS]) is a `.onion`.
     * In a RELEASE build a non-onion list makes this false, and false there means
     * messaging is DISABLED, never clearnet: AppState.startTorOrDirect fails closed (its direct path is `#if DEBUG`-only).
     * Direct HTTP is reachable only from debug/emulator builds.
     */
    actual val isTorRequired: Boolean
        get() = hostIsOnion(CANDIDATE_URLS.firstOrNull() ?: "")
}

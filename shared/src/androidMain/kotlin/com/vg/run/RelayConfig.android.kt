package com.vg.run

import android.os.Build
import com.vg.run.shared.BuildConfig

// ---------------------------------------------------------------------------
// RelayConfig — Android actual with emulator detection.
//
// Physical devices use the relay URL(s) compiled into the shared module from
// the gitignored relay.properties at the repo root (see shared/build.gradle.kts
// generateRelayUrl task); DEBUG builds on physical devices prefer the dev-relay
// list when one is configured (see CANDIDATE_URLS below). The same lists are
// used by the iOS actual, so relay.properties is the single source of truth
// across platforms.
//
// The emulator uses direct HTTP to the host machine because the Tor binary
// (guardianproject libtor.so) segfaults under ARM translation on emulated devices.
// ---------------------------------------------------------------------------

actual object RelayConfig {

    private val isEmulator: Boolean = Build.FINGERPRINT.contains("generic")
            || Build.FINGERPRINT.contains("emulator")
            || Build.MODEL.contains("Emulator")
            || Build.MODEL.contains("Android SDK")
            || Build.MANUFACTURER.contains("Genymotion")
            || Build.PRODUCT.contains("sdk")
            || Build.PRODUCT.contains("emulator")

    actual val CANDIDATE_URLS: List<String> =
        // The emulator cleartext-loopback override is gated on BuildConfig.DEBUG
        // (compile-time), so a RELEASE build always uses RELAY_URLS_FROM_PROPERTIES
        // even on an OEM device whose Build.* fields match the emulator heuristic.
        // Debug (incl. the e2e emulator suites) keeps the 10.0.2.2 host route.
        // Dev-relay addition (2026-07-17): debug builds on PHYSICAL devices use the
        // dev/test relay (relayDevOnionUrl*) when configured, keeping test traffic
        // off the production relay. Release stays structurally pinned to
        // RELAY_URLS_FROM_PROPERTIES — the first branch wins before any override.
        when {
            !BuildConfig.DEBUG -> RELAY_URLS_FROM_PROPERTIES
            isEmulator -> listOf("http://10.0.2.2:8080")
            RELAY_DEV_URLS_FROM_PROPERTIES.isNotEmpty() -> RELAY_DEV_URLS_FROM_PROPERTIES
            else -> RELAY_URLS_FROM_PROPERTIES
        }

    /** The session's address: slot 1 until the descriptor race picks a faster one. */
    actual val BASE_URL: String
        get() = RelayEndpoints.race.currentBaseUrl()

    /**
     * True when the session relay (slot 1 of [CANDIDATE_URLS]) is a `.onion`.
     * In a RELEASE build a non-onion list makes this false, and false there means
     * messaging is DISABLED, never clearnet: RunViewModel fails closed ("clearnet relay refused in release build").
     * Direct HTTP is reachable only from debug/emulator builds.
     */
    actual val isTorRequired: Boolean
        get() = hostIsOnion(CANDIDATE_URLS.firstOrNull() ?: "")
}

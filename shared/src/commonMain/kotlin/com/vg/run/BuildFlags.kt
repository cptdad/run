package com.vg.run

/**
 * True in a DEBUGGABLE / test build (Android `BuildConfig.DEBUG`, iOS
 * `Platform.isDebugBinary`); false in the optimized release binaries.
 *
 * Debug-only TestHook uses, and ONLY these:
 *  - Lowering the Argon2id KDF cost in test builds — see [VaultSelector]. On a
 *    debuggable APK/XCFramework ART won't AOT-compile the pure-Java/interpreted
 *    Argon2, so the release-strength cost is far too slow on an interpreted debug build,
 *    which would make the e2e suite and the dev inner loop unusable. Release is UNAFFECTED.
 *  - [ProcessWipeLatch.resetForTest] (androidMain) — an instrumented-test-only
 *    reset of the post-wipe regeneration guard; a hard no-op in release.
 *  - [ReauthPolicy.setTestIntervalOverrideMs] / [ReauthPolicy.isEnabled] — the
 *    periodic random re-auth at MAXIMUM (docs/periodic-reauth-design.md) is OFF
 *    by default in a debuggable build (the device e2e suites run iOS seats on
 *    MAXIMUM for multi-minute Tor waits, and the timer is touch-independent so
 *    KeepAwake cannot defeat it) and turns on only once a test arms a fixed
 *    override. A release build has no such escape path and is always on at
 *    MAXIMUM regardless of this flag.
 *  - [DescriptorHedge.setNoHedgeControl] — the physical-phone A/B's no-hedge control arm
 *    for the descriptor hedge (a connect-time optimisation, not a security
 *    decision). Refused in release, so a shipped app always hedges.
 *
 * Do NOT gate any OTHER security decision on this.
 */
internal expect val isDebugBuild: Boolean

/**
 * A RELEASE app must never link the DEBUG shared framework. That would
 * run Argon2id at the 1 MiB / 1-pass DEBUG cost (see [isDebugBuild]) and silently +
 * PERMANENTLY provision every vault forensically-weak — the cost is pinned into the
 * credential blob and read back on every unlock, and commonMain alone can't tell a
 * mis-built release from a genuine debug build (the framework reports debug either way).
 *
 * So the APP passes its OWN build type here at startup: if it is a release app but the
 * linked framework reports debug, fail LOUD immediately rather than ship weak vaults.
 * No-op for a genuine debug/test build (appIsReleaseBuild = false). Call once on launch.
 */
fun assertKdfBuildIntegrity(appIsReleaseBuild: Boolean) {
    check(!(appIsReleaseBuild && isDebugBuild)) {
        "BUILD INTEGRITY: a release app linked a DEBUG shared framework — Argon2id KDF " +
            "would be debug-weak (1 MiB / 1 pass). Rebuild against the release framework."
    }
}

/**
 * Public mirror of [isDebugBuild] for callers OUTSIDE this Kotlin module —
 * `androidApp` (a separate Gradle module) and Swift (which can only see
 * `public` commonMain symbols through the generated framework header) cannot
 * see an `internal` commonMain declaration directly.
 *
 * Exists so platform layers gating the in-app store-review nudge
 * ([ReviewPromptPolicy]) read the SAME debug signal [VaultSelector] already
 * uses to pick the Argon2id KDF cost, instead of each platform inventing its
 * own (Android `BuildConfig.DEBUG` from a DIFFERENT module's generated
 * class, iOS `#if DEBUG`) that could in principle drift from it — exactly the class of drift this
 * whole file exists to prevent. Called directly from Swift as `BuildFlagsKt.isDebugBuildPublic()`,
 * same idiom as [assertKdfBuildIntegrity] (RunApp.swift).
 */
fun isDebugBuildPublic(): Boolean = isDebugBuild

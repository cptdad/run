package com.vg.run

import java.io.File

// ---------------------------------------------------------------------------
// Tor working-dir layout + torrc (split out of TorManager.kt): the directory
// and file names, the per-session ephemera purge, the stale-dir policy and the
// torrc text. Pure top-level declarations, so the policy is unit-testable
// without an Application or the Tor binary (TorrcConfigTest,
// TorWorkingDirPolicyTest). TorManager owns the paths and calls these.
// ---------------------------------------------------------------------------

/** Root of both Tor working-dir trees, under `filesDir` and under `cacheDir`. */
internal const val TOR_ROOT_DIR_NAME = "tor_direct"

/** The retained DataDirectory child of `filesDir/tor_direct` (guard state). */
internal const val TOR_DATA_DIR_NAME = "data"

/** The retained CacheDirectory child of `cacheDir/tor_direct` (consensus cache). */
internal const val TOR_CACHE_DIR_NAME = "cache"

/**
 * Our AF_UNIX control socket inside the DataDirectory (never a TCP ControlPort —
 * a localhost TCP control listener is bindable by any co-installed app; the
 * hardening moved to SocksPort auto + control-socket readback for exactly that
 * reason). Mirrors iOS's `config.controlSocket` named `cp`.
 */
internal const val TOR_CONTROL_SOCKET_NAME = "cp"

/**
 * Tor's cookie-auth file, written into the DataDirectory when
 * `CookieAuthentication 1` is set (we don't set `CookieAuthFile`, so it defaults
 * here). Read + AUTHENTICATEd with by [TorManager]; per-session auth material.
 */
internal const val TOR_CONTROL_COOKIE_NAME = "control_auth_cookie"

/**
 * The ONLY files inside the preserved DataDirectory that must not survive a
 * restart.
 *
 * `tor.log` is load-bearing, not hygiene: [TorManager.start] tails the notice log
 * from offset 0 to learn the SOCKS port, so a log left by a session that died
 * before its post-bootstrap delete would hand the new session the PREVIOUS run's
 * `Socks listener listening on 127.0.0.1:NNNN` — a port this process does not own
 * and that any local app may have re-bound. That is the deanonymisation hazard
 * [TorNoticeLog.parseSocksListenerPort] exists to bound, arriving by a different
 * route. `torrc` is rewritten from [buildTorrc] on every start; deleting it first
 * means a stale config can never be what Tor reads.
 *
 * [TOR_CONTROL_COOKIE_NAME] + [TOR_CONTROL_SOCKET_NAME] join them (parity with
 * iOS `purgeSessionEphemera`, which clears the same `control_auth_cookie` + `cp`):
 * a stale 32-byte cookie left by a previous run would pass the length guard and
 * be AUTHENTICATEd — against the FRESH daemon's newly-minted cookie — so it must
 * be cleared before start; a leftover socket file with no listener would only
 * cost connect retries, but is auth-adjacent state worth not inheriting. Both are
 * re-created by the fresh daemon on every start.
 *
 * Everything else in the directory (`state` = entry guards, `cached-*`,
 * `lock`, `diff-cache/`) is exactly what we now keep. A stale `lock` is safe:
 * Tor's lock is an advisory `flock` released by the kernel when its holder dies.
 */
internal val TOR_SESSION_EPHEMERAL_FILES =
    listOf("torrc", "tor.log", TOR_CONTROL_SOCKET_NAME, TOR_CONTROL_COOKIE_NAME)

/**
 * Readies a PRESERVED Tor DataDirectory for a new session: removes
 * [TOR_SESSION_EPHEMERAL_FILES] and nothing else.
 *
 * Top-level and taking the directory as a parameter so the preserve-vs-discard
 * policy is unit-testable without an Application or the Tor binary (the same
 * reason [buildTorrc] lives out here).
 */
internal fun purgeSessionEphemera(dataDir: File) {
    for (name in TOR_SESSION_EPHEMERAL_FILES) {
        try {
            File(dataDir, name).delete()
        } catch (_: Exception) { /* best-effort — the fresh daemon / start() recreates each */ }
    }
}

/**
 * The `tor_direct` children to delete on start, given the directory listing and
 * the one name to [keep]. Pure so the "never purge the retained dir" property is
 * unit-testable.
 */
internal fun staleTorDirsToPurge(children: List<String>, keep: String): List<String> =
    children.filter { it != keep }

/**
 * Builds the Tor configuration written to torrc. Extracted as a pure function
 * so the privacy directives (SafeSocks/SafeLogging) can be asserted
 * in a unit test without spawning a Tor process. SafeSocks rejects SOCKS
 * requests carrying a pre-resolved IP (forcing hostname/SOCKS5h), and
 * SafeLogging scrubs addresses from the on-disk notice log.
 *
 * `NumEntryGuards 8` — a KNOWING reliability-over-anonymity trade-off. In Tor 0.4.9 the option
 * feeds `guard-n-primary-guards-to-use` (entrynodes.c), i.e. how many of the
 * primary guards circuits are spread across concurrently; the primary LIST stays
 * at the consensus default of 3 (`NumPrimaryGuards` unset), so the effect is
 * "circuits through all 3 primaries at random" instead of Tor's default 1. Cost:
 * ~3× adversarial-guard exposure and a mildly non-stock connection shape. It was
 * removed once and reinstated after cross:multi3 failed 4/4 with
 * the exact slow-guard signature it was added for (relay probes through the
 * SOCKS proxy failing for minutes right after "CONNECTED" — a SLOW primary is
 * not an UNREACHABLE one, so Tor does not fall past it at to_use=1). Keep in
 * lockstep with iOS. Revisit only with a measured alternative (e.g. 2).
 *
 * `ControlSocket` / `CookieAuthentication` — the NEWNYM self-heal channel
 * (parity with iOS config.controlSocket + cookieAuthentication). A
 * UNIX-DOMAIN control socket at `$dataDir/cp` (derived from [dataDirPath], the
 * same dir TorManager passes), cookie-authenticated, inside app-private
 * FBE storage. DELIBERATELY NOT a TCP control port: a localhost TCP control
 * listener is discoverable/bindable by any co-installed app and would regress
 * that hardening. See TorManager.requestNewCircuit.
 *
 * `CircuitBuildTimeout 45` / `LearnCircuitBuildTimeout 0` — mobile reliability,
 * parity with iOS (TorManager.swift). The ADAPTIVE circuit-build timeout (Tor's
 * default) learns from fast circuits on a variable mobile network, then
 * prematurely KILLS slower-but-valid .onion circuits — the circuit-level cousin
 * of the blind-mint hang that the MessageManager warm-gate addresses app-side.
 * Pin a fixed CBT instead, and keep more entry guards so a slow guard has live
 * fallbacks. (Android previously ran Tor defaults: adaptive CBT + a single guard.)
 * WHY 45, not the original 90 (lever 3, 2026-09-11): CBT bounds how long Tor
 * holds a circuit that is never going to finish — and on the onion path that
 * is exactly the failure the connect-time tail is made of (a dead intro
 * point, an unreachable rendezvous point). The app's own 20 s health budget
 * cannot rescue it: rotating the STREAM does not abandon the CIRCUIT, and a
 * stream pending on a rendezvous inherits the circuit's fate, so a dead path
 * used to cost the full 90 s before Tor would try another one. 45 s halves
 * that tail while staying far above a normal 3-hop build (single-digit
 * seconds) and above the slow-but-valid mobile builds that made adaptive CBT
 * unusable here — so it must never go below ~30 s, which is where genuine
 * builds start being killed. Path selection is unchanged and adaptive CBT
 * stays OFF; this is purely how long a doomed attempt is given.
 *
 * `ClientUseIPv6` / `ClientPreferIPv6ORPort` — Guideline 2.1 fix, parity with
 * iOS (TorManager.swift): see the full rationale comment above the torrc
 * string there (IPv6-only NAT64 review-lab / enterprise Wi-Fi networks
 * can't translate Tor's default IPv4-literal dials, stalling bootstrap
 * forever).
 *
 * Directory bootstrap is deliberately STOCK on both platforms: no
 * `UseDefaultFallbackDirs`, no `FallbackDir` lines, so Tor uses its own
 * compiled-in fallback list (200 entries in 0.4.9.11) alongside the
 * directory authorities. Android has always done this; iOS matched it on
 * 2026-09-15 (C3) when the 18-entry curated override was removed — the
 * static-link symbol collision it worked around had been fixed months
 * earlier by the dynamic Tor.framework. The reasoning lives in the comment
 * above `torrcOptions(authPath:)` in TorManager.swift; keep the two in lockstep.
 */
internal fun buildTorrc(dataDirPath: String, cacheDirPath: String, logFilePath: String): String =
    """
    SocksPort auto
    DataDirectory $dataDirPath
    CacheDirectory $cacheDirPath
    ControlSocket $dataDirPath/$TOR_CONTROL_SOCKET_NAME
    CookieAuthentication 1
    DisableNetwork 0
    RunAsDaemon 0
    Log notice file $logFilePath
    AvoidDiskWrites 1
    SafeSocks 1
    SafeLogging 1
    LearnCircuitBuildTimeout 0
    CircuitBuildTimeout 45
    NumEntryGuards 8
    ClientUseIPv6 1
    ClientPreferIPv6ORPort auto
    """.trimIndent()

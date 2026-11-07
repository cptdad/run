#!/usr/bin/env bash
#
# CI source guard — DNS-leak defense-in-depth.
#
# Fails the build if a DNS-capable networking API is used OUTSIDE the
# approved transport files. The risk: a future module that talks
# to the network directly bypasses PlatformHttpClient and therefore its
# .onion/SOCKS DNS-leak guard (hostIsOnion), silently re-opening the leak
# even though PlatformHttpClient itself is hardened. This catches that at
# build time, on both platforms, regardless of which module added it.
#
# Bash 3.2 compatible (macOS default shell).
#
# Exit 0 = clean. Exit 1 = a disallowed networking call site was found.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# The ONLY files allowed to use raw networking APIs. Each of these must
# itself enforce the .onion/SOCKS host guard (or route through one that
# does). Add a new file here ONLY together with that guard.
ALLOW="
shared/src/commonMain/kotlin/com/vg/run/PlatformHttpClient.kt
shared/src/androidMain/kotlin/com/vg/run/PlatformHttpClient.android.kt
shared/src/androidMain/kotlin/com/vg/run/Socks5Sockets.kt
shared/src/iosMain/kotlin/com/vg/run/PlatformHttpClient.ios.kt
shared/src/iosMain/kotlin/com/vg/run/HttpBridge.kt
iosApp/iosApp/SwiftTorHttp.swift
"

# DNS-capable networking entry points (each resolves a hostname locally, or
# is the SOCKS transport that must apply the guard).
PATTERN='NSURLSession|URLSession|NWConnection|OkHttpClient|HttpURLConnection|getaddrinfo|CFHostStartInfoResolution|java\.net\.Socket|URLConnection|InetAddress\.(getByName|getAllByName)'

viol="$(mktemp)"
srcs="$(mktemp)"
trap 'rm -f "$viol" "$srcs"' EXIT

# Enumerate main-source .kt/.swift/.m/.h files. Prefer git (respects the index
# and ignores), but fall back to `find` so the guard STILL RUNS in an extracted
# source archive or CI export that has no .git. Without the fallback, git
# ls-files prints "fatal: not a git repository" to stderr, yields nothing on
# stdout, and the scan silently passes over ZERO files — a false pass that
# reads as "no leaks" (external review 2026-07 #1).
#
# .m/.h added: mirrors the widening
# scripts/check-logging-gated.sh got — the guard was Kotlin+Swift
# only, so a raw NSURLSession/NWConnection/getaddrinfo call site in vendored
# Objective-C (iosApp/Tor, iosApp/Argon2 — see the path filter below) shipped
# into the App Store binary with this guard reporting green regardless.
list_sources() {
    if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        git ls-files '*.kt' '*.swift' '*.m' '*.h'
    else
        find shared/src/commonMain shared/src/androidMain shared/src/iosMain \
             androidApp/src iosApp/iosApp iosApp/Tor iosApp/Argon2 \
             -type f \( -name '*.kt' -o -name '*.swift' -o -name '*.m' -o -name '*.h' \) 2>/dev/null
    fi
}

# androidApp/src/<name> source sets to include: every directory EXCEPT the
# JVM unit-test and instrumented-test roots (those legitimately use
# OkHttp/MockWebServer). Discovered at scan time rather than hardcoded to
# "main" — a newly added product flavor or build-type source set is exactly
# where variant-specific network code would live (RunFcmService and VendorPush
# lived under androidApp/src/google before the 2026-08-04 flavor collapse
# moved them to main) and is covered automatically, with no edit to this
# script required for the next source set.
android_app_src_dirs() {
    # `|| true` guards against `find` exiting non-zero when androidApp/src is
    # absent (a stripped export). Without it, `set -eo pipefail` propagates
    # that non-zero status through the `android_dirs_alt=$(...)` assignment
    # below and kills the script THERE — silently, with no error message,
    # before the zero-files diagnostic ever runs. Fail loud, not blank.
    find androidApp/src -mindepth 1 -maxdepth 1 -type d 2>/dev/null \
      | grep -vE '/(test|androidTest)$' \
      | sed 's#^androidApp/src/##' || true
}

android_dirs_alt="$(android_app_src_dirs | paste -sd'|' -)"
if [ -z "$android_dirs_alt" ]; then
    # androidApp/src is missing or contains only test dirs (e.g. a stripped
    # export) — fall back to "main" so the regex below stays well-formed;
    # the zero-files guard further down still fires if nothing is found at
    # all.
    android_dirs_alt="main"
fi

# Scan main + flavor/build-type sources only — excludes build/ output and
# every test source set (tests legitimately use OkHttp/MockWebServer).
#
# iosApp/Tor + iosApp/Argon2 added:
# iosApp/iosApp.xcodeproj/project.pbxproj declares both as
# PBXFileSystemSynchronizedRootGroups, so every file under them is
# auto-compiled into the shipped app with no pbxproj edit — same reason
# scripts/check-logging-gated.sh's SWIFT_DIRS covers iosApp/Argon2 (and its
# Objective-C block covers iosApp/Tor). iosApp/RunCryptoTests is a
# test target (never shipped) and stays out of scope, same as before.
list_sources \
  | grep -E "^(\./)?(shared/src/(commonMain|androidMain|iosMain)|androidApp/src/(${android_dirs_alt})|iosApp/iosApp|iosApp/Tor|iosApp/Argon2)/" \
  | { grep -vE '^(\./)?(shared/src/(commonTest|androidUnitTest|iosTest|jvmTest|[a-z][A-Za-z0-9]*Test)|androidApp/src/(test|androidTest)[A-Za-z0-9]*|iosApp/[^/]+Tests?)/' || [ $? -eq 1 ]; } \
  > "$srcs" || [ $? -eq 1 ]

# A guard that scanned nothing is not a pass — fail closed rather than
# false-pass on an empty file set (no git AND no source tree found).
if [ ! -s "$srcs" ]; then
    echo "ERROR: network-api guard found ZERO source files to scan." >&2
    echo "Not inside a git checkout and the main source dirs are absent — refusing" >&2
    echo "to report OK. Run this from the repo root (or a source tree that contains" >&2
    echo "shared/src, androidApp/src, iosApp/iosApp)." >&2
    exit 2
fi

while IFS= read -r f; do
    f="${f#./}"   # normalise the find-fallback's leading ./ to match the allowlist
    # Exact whole-line match against the allowlist (not a substring): a scanned
    # path must EQUAL an allowlisted entry. The old `*"$f"*` substring test would
    # skip any file whose path is a substring of an allowlisted line, silently
    # widening the guard as the allowlist grows.
    if printf '%s\n' "$ALLOW" | grep -qxF "$f"; then continue; fi
    rc=0
    hits="$(grep -nE "$PATTERN" "$f" 2>&1)" || rc=$?
    if [ "$rc" -gt 1 ]; then
        echo "ERROR: grep failed on $f (rc=$rc): $hits" >&2
        exit 2
    fi
    [ "$rc" -eq 0 ] || hits=""
    if [ -n "$hits" ]; then
        echo "  $f" >> "$viol"
        printf '%s\n' "$hits" | sed 's/^/      /' >> "$viol"
    fi
done < "$srcs"

if [ -s "$viol" ]; then
    echo "ERROR: disallowed networking API outside approved files (DNS-leak guard):"
    cat "$viol"
    echo ""
    echo "All networking must go through PlatformHttpClient, which enforces the"
    echo ".onion (direct) / non-.onion (SOCKS) host guard. If a new networking"
    echo "file is genuinely required, add the SAME host guard to it and then"
    echo "allowlist it in scripts/check-network-api-usage.sh."
    exit 1
fi

echo "network-api guard: OK — no disallowed networking APIs outside approved files"

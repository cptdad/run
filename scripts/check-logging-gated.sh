#!/usr/bin/env bash
#
# Release-logging source guard.
#
# INVARIANT: a production build must emit NOTHING to any log sink the OS keeps —
# logcat, the iOS unified log, stdout/stderr. Today that holds because every call
# site routes through the debug-gated helpers (platformLog* / LogBuffer, both
# no-ops unless a DEBUG-only flag is set) and the few direct sinks sit inside
# `if (BuildConfig.DEBUG)` / `#if DEBUG`. Nothing STRUCTURAL enforced it, so one
# ungated Log.d in a future change would silently ship device metadata to a sink
# that is on-disk, outside the app sandbox on iOS, and survives the panic wipe.
#
# This guard fails the push when a raw logging API appears outside a gate.
# It scans SOURCE ONLY (no build dirs) and is deliberately narrow: it flags the
# sinks, not the app's own helpers, so the fix is always "route it through
# platformLog / LogBuffer, or gate it".
#
# Escape hatch: put the call inside `if (BuildConfig.DEBUG)` on the SAME line, or
# inside a `#if DEBUG` block on Swift. Anything else must use the helpers.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
fail=0

# --- scan-set discovery --------------------------------------------
# This guard used to scan only androidApp/src/main + shared/src/androidMain and
# iosApp/iosApp — so it missed code that ships: qualified source sets (e.g. the
# pre-collapse androidApp/src/google/, which held RunFcmService.kt /
# VendorPush.kt) and the non-iosApp/iosApp Swift/ObjC compiled into the
# app (iosApp/Argon2, iosApp/Tor). Source sets are DISCOVERED at scan time, the
# same approach as the sibling scripts/check-network-api-usage.sh, so the next
# product flavor or build-type source set is covered with no edit here.
#
# Every dir EXCEPT the test source-set roots is in scope. Excluded shapes:
# exact test/androidTest, their flavor/build-type-qualified variants (testFoss,
# androidTestGoogleDebug — a camelCase qualifier is REQUIRED, so a production
# dir like src/testing or src/tester is still scanned), and KMP-style *Test
# sets (commonTest, iosArm64Test) in case discovery ever meets them.
# Debug-only source sets (src/debug, src/googleDebug) ARE scanned: their contents
# never reach a release build, so the gate is stricter than strictly necessary
# there, and the fix for a legitimate hit is a trivial `if (BuildConfig.DEBUG)`.
android_app_src_dirs() {
    # A missing androidApp/src yields no dirs here; the zero-sources guard below
    # then fails loud. `grep -v` exits 1 when it filters everything out: that is
    # "no dirs", not an error (only rc >= 2 is).
    find "$ROOT/androidApp/src" -mindepth 1 -maxdepth 1 -type d 2>/dev/null \
      | { grep -vE '/((test|androidTest)([A-Z][A-Za-z0-9]*)?|[a-z][A-Za-z0-9]*Test)$' || [ $? -eq 1 ]; }
}

# scan <grep args...>: prints the hits; a grep ERROR (rc >= 2: unreadable file,
# bad regex) aborts the script with rc 2 instead of reading as "no match".
# Call as `hits="$(scan ...)" || exit 2` (an `exit` inside <(...) would only
# end the subshell).
scan() {
    local out rc=0
    out="$(grep "$@" 2>&1)" || rc=$?
    if [ "$rc" -gt 1 ]; then echo "ERROR: grep failed (rc=$rc): $out" >&2; exit 2; fi
    if [ "$rc" -eq 0 ]; then printf '%s\n' "$out"; fi
    return 0
}
# Drop lines matching a pattern; "nothing left" (rc 1) is fine.
drop() { grep -v "$@" || [ $? -eq 1 ]; }

# Arrays (not space-joined strings): a checkout path with a space must not make
# the guard silently scan a SUBSET while still printing green.
KOTLIN_DIRS=()
SWIFT_DIRS=()
while IFS= read -r d; do
    [ -n "$d" ] && [ -d "$d" ] && KOTLIN_DIRS+=("$d")
done < <(android_app_src_dirs)
for d in "$ROOT/shared/src/androidMain" "$ROOT/shared/src/commonMain" "$ROOT/shared/src/iosMain"; do
    [ -d "$d" ] && KOTLIN_DIRS+=("$d")
done

# iosApp/RunCryptoTests is a test target (never shipped) and is excluded; the
# rest of iosApp's Swift is compiled into the app.
for d in "$ROOT/iosApp/iosApp" "$ROOT/iosApp/Argon2"; do
    [ -d "$d" ] && SWIFT_DIRS+=("$d")
done

# A guard that scanned nothing is not a pass. Without this, a moved/renamed
# source tree turns every grep below into a no-op and the script prints its
# green summary — a false "production logs nothing".
kt_count=0; sw_count=0
if [ "${#KOTLIN_DIRS[@]}" -gt 0 ]; then
    kt_count=$(find "${KOTLIN_DIRS[@]}" -type f -name '*.kt' | wc -l | tr -d ' ') \
        || { echo "ERROR: find failed while counting Kotlin sources" >&2; exit 2; }
fi
if [ "${#SWIFT_DIRS[@]}" -gt 0 ]; then
    sw_count=$(find "${SWIFT_DIRS[@]}" -type f -name '*.swift' | wc -l | tr -d ' ') \
        || { echo "ERROR: find failed while counting Swift sources" >&2; exit 2; }
fi
if [ "$kt_count" -eq 0 ] || [ "$sw_count" -eq 0 ]; then
    echo "ERROR: release-logging guard found ZERO sources to scan" >&2
    echo "       (kotlin=$kt_count swift=$sw_count). Refusing to report OK — run this" >&2
    echo "       from a checkout containing androidApp/src, shared/src and iosApp/." >&2
    exit 2
fi

# --- Kotlin: android.util.Log.* outside a same-line BuildConfig.DEBUG gate -----
# Platform.android.kt is the sanctioned sink (it gates on IS_DEBUG internally).
hits="$(scan -rn --include='*.kt' -E '\bLog\.(d|w|e|i|v)\(' "${KOTLIN_DIRS[@]}" \
         | drop 'Platform.android.kt' | drop 'BuildConfig.DEBUG')" || exit 2
while IFS= read -r hit; do
    [ -z "$hit" ] && continue
    echo "  $hit"
    fail=1
done <<< "$hits"

# --- Swift: os_log / Logger / NSLog / print outside a #if DEBUG block ---------
# Per-file check: a file may declare a Logger only if it also has #if DEBUG, and
# the known-gated helpers (torLog, wipeDiag) live behind one. Bare print() is
# never allowed — Kotlin/Native's println is already IS_DEBUG-gated upstream.
hits="$(scan -rn --include='*.swift' -E '^\s*(print\(|NSLog\()' "${SWIFT_DIRS[@]}")" || exit 2
while IFS= read -r hit; do
    [ -z "$hit" ] && continue
    echo "  $hit"
    fail=1
done <<< "$hits"

files="$(scan -rl --include='*.swift' -E 'os_log|Logger\(' "${SWIFT_DIRS[@]}")" || exit 2
while IFS= read -r f; do
    [ -z "$f" ] && continue
    if ! grep -q '#if DEBUG' "$f"; then
        echo "  $f: declares a Logger/os_log sink with no #if DEBUG gate in the file"
        fail=1
    fi
done <<< "$files"

# --- Objective-C: iosApp/Tor (vendored iCepa Tor wrapper, compiled into the app)
# TORLogging.m legitimately CONTAINS os_log plumbing — it is upstream code — but
# that plumbing is dead unless somebody arms it by calling TORInstallEventLogging
# / TORInstallTorLogging (or their *Callback variants). Nothing in the app does,
# and this keeps it that way: arming them pipes Tor's own event log (circuits,
# bootstrap, errors) into the iOS unified log, which is on-disk, outside the app
# sandbox, and survives the panic wipe. A bare NSLog in the vendored tree would
# log unconditionally, so that is flagged directly.
if [ -d "$ROOT/iosApp/Tor" ]; then
    objc_count=$(find "$ROOT/iosApp/Tor" -type f \( -name '*.m' -o -name '*.h' \) | wc -l | tr -d ' ')
    if [ "$objc_count" -eq 0 ]; then
        echo "ERROR: release-logging guard found ZERO Objective-C sources under iosApp/Tor." >&2
        exit 2
    fi
    hits="$(scan -rn --include='*.m' --include='*.h' -E '(^|[^A-Za-z_])NSLog\(' \
                "$ROOT/iosApp/Tor")" || exit 2
    while IFS= read -r hit; do
        [ -z "$hit" ] && continue
        echo "  $hit"
        fail=1
    done <<< "$hits"

    # The arming call, searched in the APP sources (the definitions and their
    # internal cross-calls live in iosApp/Tor itself and are not the violation).
    hits="$(scan -rn --include='*.swift' --include='*.kt' --include='*.m' \
                -E 'TORInstall(Event|Tor)Logging(Callback)?[[:space:]]*\(' \
                "${SWIFT_DIRS[@]}" "$ROOT/shared/src/iosMain")" || exit 2
    while IFS= read -r hit; do
        [ -z "$hit" ] && continue
        echo "  $hit: arms the vendored Tor os_log sink (TORInstall*Logging)"
        fail=1
    done <<< "$hits"
fi

if [ "$fail" -ne 0 ]; then
    echo ""
    echo "✖ release-logging guard: ungated logging sink(s) above."
    echo "  Route it through platformLog/platformLogWarn/platformLogError (system"
    echo "  log gated on debug, LogBuffer no-op in release), or gate the call with"
    echo "  if (BuildConfig.DEBUG) / #if DEBUG. Production must log nothing."
    exit 1
fi

echo "release-logging guard: no ungated logging sinks."

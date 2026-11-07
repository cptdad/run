#!/usr/bin/env bash
# Canary self-test for the three SOURCE gates (check-logging-gated.sh,
# check-network-api-usage.sh, verify-release-clean.sh).
#
# Each gate is copied into a throw-away fixture tree whose path CONTAINS A SPACE
# (the original word-splitting bug), run once on the clean fixture (must pass),
# then once per planted violation (must fail with the expected exit code).
# A gate that stays green on a planted canary is a broken gate.
#
#   usage: scripts/test-source-gates.sh        (bash 3.2 compatible, no Gradle)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
BASE="$(mktemp -d)"
trap 'chmod -R u+rwx "$BASE" 2>/dev/null; rm -rf "$BASE"' EXIT
total=0; bad=0

check() {   # check <label> <want_rc> <got_rc> [log]
    total=$((total + 1))
    if [ "$2" = "$3" ]; then echo "  ok   $1 (rc=$3)"
    else echo "  FAIL $1: want rc=$2, got rc=$3" >&2; [ -n "${4:-}" ] && sed 's/^/        /' "$4" >&2; bad=$((bad + 1)); fi
}

new_fixture() {   # echoes a fresh fixture root (path with a space)
    local n; n="$(mktemp -d "$BASE/fx.XXXXXX")/with space"
    mkdir -p "$n/scripts"; echo "$n"
}

run_gate() {   # run_gate <root> <gate-basename>  -> rc, log in $BASE/last.log
    ( cd "$1" && bash "$1/scripts/$2" ) >"$BASE/last.log" 2>&1
}

# ---------------------------------------------------------------- logging gate
logging_fx() {
    local r; r="$(new_fixture)"
    cp "$HERE/check-logging-gated.sh" "$r/scripts/"
    mkdir -p "$r/shared/src/androidMain" "$r/shared/src/commonMain" "$r/shared/src/iosMain" \
             "$r/androidApp/src/main" "$r/iosApp/iosApp" "$r/iosApp/Argon2"
    for d in shared/src/androidMain shared/src/commonMain shared/src/iosMain androidApp/src/main; do
        printf 'package x\nfun ok() = 1\n' > "$r/$d/Ok.kt"
    done
    printf 'import Foundation\nlet ok = 1\n' > "$r/iosApp/iosApp/Ok.swift"
    printf 'import Foundation\nlet ok = 1\n' > "$r/iosApp/Argon2/Ok.swift"
    echo "$r"
}
lcase() {   # lcase <label> <want_rc> <relpath> <content>
    local r; r="$(logging_fx)"
    mkdir -p "$(dirname "$r/$3")"; printf '%s\n' "$4" > "$r/$3"
    run_gate "$r" check-logging-gated.sh; check "logging $1" "$2" $? "$BASE/last.log"
}
echo "== check-logging-gated.sh"
r="$(logging_fx)"; run_gate "$r" check-logging-gated.sh; check "C0 clean fixture" 0 $? "$BASE/last.log"
lcase "C1 ungated Log.d" 1 androidApp/src/main/Leak.kt 'fun f() { Log.d("t", "m") }'
lcase "C1b gated Log.d" 0 androidApp/src/main/Gated.kt 'fun f() { if (BuildConfig.DEBUG) Log.d("t", "m") }'
lcase "C2 Swift print" 1 iosApp/iosApp/Leak.swift 'print("x")'
lcase "C3 Logger without #if DEBUG" 1 iosApp/iosApp/Lg.swift 'let l = Logger(subsystem: "a", category: "b")'
mkdir -p "$BASE/none"
r="$(logging_fx)"; mkdir -p "$r/iosApp/Tor"; printf 'void f(void){ NSLog(@"x"); }\n' > "$r/iosApp/Tor/x.m"
run_gate "$r" check-logging-gated.sh; check "logging C4 NSLog in iosApp/Tor" 1 $? "$BASE/last.log"
r="$(logging_fx)"; mkdir -p "$r/iosApp/Tor"; printf 'void f(void){}\n' > "$r/iosApp/Tor/x.m"
printf 'func g() { TORInstallEventLogging(nil) }\n' > "$r/iosApp/iosApp/Arm.swift"
run_gate "$r" check-logging-gated.sh; check "logging C5 TORInstallEventLogging" 1 $? "$BASE/last.log"
lcase "C6 canary in a dir with a space" 1 "androidApp/src/main/my dir/Leak.kt" 'fun f() { Log.e("t", "m") }'
r="$(new_fixture)"; cp "$HERE/check-logging-gated.sh" "$r/scripts/"
run_gate "$r" check-logging-gated.sh; check "logging C7 empty tree" 2 $? "$BASE/last.log"
if [ "$(id -u)" -ne 0 ]; then
    r="$(logging_fx)"; mkdir -p "$r/androidApp/src/main/locked"; printf 'x\n' > "$r/androidApp/src/main/locked/L.kt"
    chmod 000 "$r/androidApp/src/main/locked"
    run_gate "$r" check-logging-gated.sh; check "logging C8 unreadable dir" 2 $? "$BASE/last.log"
    chmod 755 "$r/androidApp/src/main/locked"
fi

# ------------------------------------------------------------ network-api gate
net_fx() {
    local r; r="$(new_fixture)"
    cp "$HERE/check-network-api-usage.sh" "$r/scripts/"
    mkdir -p "$r/shared/src/commonMain/kotlin/com/vg/run" "$r/androidApp/src/main" "$r/iosApp/iosApp"
    printf 'package x\nfun ok() = 1\n' > "$r/shared/src/commonMain/kotlin/com/vg/run/Ok.kt"
    echo "$r"
}
ncase() {   # ncase <label> <want_rc> <relpath> <content>
    local r; r="$(net_fx)"
    mkdir -p "$(dirname "$r/$3")"; printf '%s\n' "$4" > "$r/$3"
    run_gate "$r" check-network-api-usage.sh; check "network $1" "$2" $? "$BASE/last.log"
}
echo "== check-network-api-usage.sh"
r="$(net_fx)"; run_gate "$r" check-network-api-usage.sh; check "N0 clean fixture" 0 $? "$BASE/last.log"
ncase "N1 OkHttpClient in commonMain" 1 shared/src/commonMain/kotlin/com/vg/run/Leak.kt 'val c = OkHttpClient()'
ncase "N1b same text in allowlisted file" 0 shared/src/commonMain/kotlin/com/vg/run/PlatformHttpClient.kt 'val c = OkHttpClient()'
ncase "N2 URLSession in iosApp" 1 iosApp/iosApp/Leak.swift 'let s = URLSession.shared'
ncase "N3 InetAddress.getByName" 1 androidApp/src/main/Leak.kt 'val a = java.net.InetAddress.getByName("x")'
ncase "N3b URLConnection" 1 androidApp/src/main/Leak2.kt 'val c = url.openConnection() as URLConnection'
ncase "N4 main package named test/" 1 shared/src/commonMain/kotlin/com/vg/run/test/Leak.kt 'val c = OkHttpClient()'
ncase "N4b test source set is skipped" 0 androidApp/src/test/Leak.kt 'val c = OkHttpClient()'
r="$(new_fixture)"; cp "$HERE/check-network-api-usage.sh" "$r/scripts/"; rm -rf "$r/shared"
run_gate "$r" check-network-api-usage.sh; check "network N5 empty tree" 2 $? "$BASE/last.log"

# --------------------------------------------------------- release-clean gate
R_FILES="androidApp/src/main/java/com/vg/run/AddContactScreen.kt
androidApp/src/main/java/com/vg/run/MainActivity.kt
shared/src/commonMain/kotlin/com/vg/run/LoggingState.kt
shared/src/androidMain/kotlin/com/vg/run/RelayConfig.android.kt
shared/src/iosMain/kotlin/com/vg/run/RelayConfig.ios.kt
shared/src/commonMain/kotlin/com/vg/run/VaultKdf.kt
iosApp/iosApp/AppState.swift"
rel_fx() {
    local r f; r="$(new_fixture)"
    cp "$HERE/verify-release-clean.sh" "$r/scripts/"
    while IFS= read -r f; do mkdir -p "$r/$(dirname "$f")"; cp "$REPO/$f" "$r/$f"; done <<< "$R_FILES"
    for f in "$REPO"/iosApp/iosApp/*.swift; do cp "$f" "$r/iosApp/iosApp/"; done
    echo "$r"
}
rcase() {   # rcase <label> <want_rc> <file> <perl -pi expression | APPEND:text | RM>
    local r; r="$(rel_fx)"
    case "$4" in
        APPEND:*) printf '\n%s\n' "${4#APPEND:}" >> "$r/$3" ;;
        RM) rm -rf "$r/$3" ;;
        *) perl -pi -e "$4" "$r/$3" ;;
    esac
    run_gate "$r" verify-release-clean.sh; check "release $1" "$2" $? "$BASE/last.log"
    LAST_R="$r"
}
echo "== verify-release-clean.sh"
r="$(rel_fx)"; run_gate "$r" verify-release-clean.sh; check "R0 unmutated copy" 0 $? "$BASE/last.log"
A=androidApp/src/main/java/com/vg/run
rcase "R1 testTagsAsResourceId hardcoded" 1 $A/MainActivity.kt 'APPEND:val z = Modifier.semantics { testTagsAsResourceId = true }'
rcase "R2 logging defaults on" 1 shared/src/commonMain/kotlin/com/vg/run/LoggingState.kt 's/var enabled: Boolean = false/var enabled: Boolean = true/'
rcase "R3 paste reveal ungated" 1 $A/AddContactScreen.kt 's/onRevealPaste = \{ if \(BuildConfig\.DEBUG\)/onRevealPaste = { if (true)/'
rcase "R4 Argon2 cost lowered" 1 shared/src/commonMain/kotlin/com/vg/run/VaultKdf.kt 's/ARGON2_MEMORY_KIB = 65_536/ARGON2_MEMORY_KIB = 1_024/'
rcase "R5 FLAG_SECURE gate inverted" 1 $A/MainActivity.kt 's/if \(!BuildConfig\.DEBUG\) \{(\s*)$/if (BuildConfig.DEBUG) {$1/ if /setFlags|^\s*if \(!BuildConfig\.DEBUG\) \{\s*$/'
# The Swift preprocessor walk: plant the read in a fresh file.
sw() { local r; r="$(rel_fx)"; printf '%s\n' "$2" > "$r/iosApp/iosApp/ZzCanary.swift"
       run_gate "$r" verify-release-clean.sh; check "release $1" "$3" $? "$BASE/last.log"; }
sw "R6 launch-arg read outside any #if" 'let a = ProcessInfo.processInfo.arguments' 1
sw "R6b read in #else of #if DEBUG" '#if DEBUG
#else
let a = ProcessInfo.processInfo.arguments
#endif' 1
sw "R6c read inside #if DEBUG" '#if DEBUG
let a = ProcessInfo.processInfo.arguments
#endif' 0
rcase "R7 source dir missing" 1 androidApp/src/main/java/com/vg/run RM
grep -q 'check 1' "$BASE/last.log" && check "R7 message names check 1" 0 0 || check "R7 message names check 1" 0 1 "$BASE/last.log"

echo
if [ "$bad" -ne 0 ]; then echo "test-source-gates: $bad of $total case(s) FAILED" >&2; exit 1; fi
echo "test-source-gates: all $total cases passed"

#!/usr/bin/env bash
# Debug-hook gating regression guard (external security review 2026-07, #9).
#
# Rún gates its debug-only surface at RUNTIME via BuildConfig.DEBUG (not via a
# separate source set), so those testTag / paste-code / log-viewer strings
# legitimately remain in the release binary but are INERT:
#   • Compose testTags are only exposed as automation resource-ids when
#     `testTagsAsResourceId = BuildConfig.DEBUG` (false in release), and
#   • the no-camera paste-code wizard's reveal action is `if (BuildConfig.DEBUG)`.
# So "no debug strings in the artifact" is neither achievable nor meaningful here.
# The reliable check for this model is a SOURCE-level assertion that the gating
# stays intact, so a future edit can't silently un-gate a debug hook into release.
#
#   usage: scripts/verify-release-clean.sh
set -uo pipefail
cd "$(dirname "$0")/.."
SRC="androidApp/src/main/java/com/vg/run"
fail=0

# 1) testTagsAsResourceId must ALWAYS be gated on BuildConfig.DEBUG — never a
#    hardcoded true/false (true would expose every debug testTag as an automation
#    hook in a release build).
#    The flavour source sets (src/google, src/foss) are scanned too when present; they are
#    added only if they exist, because a missing path makes grep exit 2 even on a match,
#    which would turn a real hit into a silent pass (the canary test fixture has no flavours).
SRC_DIRS=("$SRC")
for d in androidApp/src/google/kotlin androidApp/src/foss/kotlin; do
  [ -d "$d" ] && SRC_DIRS+=("$d")
done
if [ ! -d "$SRC" ]; then
  echo "FAIL: check 1: $SRC missing — refusing to report OK." >&2
  fail=1
elif grep -rnE "testTagsAsResourceId[[:space:]]*=[[:space:]]*(true|false)\b" "${SRC_DIRS[@]}" 2>/dev/null; then
  echo "FAIL: testTagsAsResourceId is hardcoded above — must be '= BuildConfig.DEBUG'." >&2
  fail=1
fi

# 2) The in-app logging kill-switch must ship OFF (no telemetry / log buffer in
#    a production build unless explicitly toggled).
if ! grep -qE "var enabled: Boolean = false" shared/src/commonMain/kotlin/com/vg/run/LoggingState.kt 2>/dev/null; then
  echo "FAIL: LoggingState.enabled must default to false." >&2
  fail=1
fi

# 3) The no-camera paste-code reveal action must stay BuildConfig.DEBUG-gated
#    (an un-gated reveal put the contact bundle on the clipboard
#    via an undocumented gesture in release).
if ! grep -qE "onRevealPaste = \{ if \(BuildConfig\.DEBUG\)" "$SRC/AddContactScreen.kt" 2>/dev/null; then
  echo "FAIL: the paste-code reveal action is not BuildConfig.DEBUG-gated." >&2
  fail=1
fi

# 4) The clearnet / Tor-BYPASS override is the HIGHEST-impact
#    debug gate — dropping a condition would ship a RELEASE that routes cleartext
#    HTTP to a host-derived LAN address with NO Tor, deanonymizing users to the
#    relay/network. It was the only debug gate with no source-level regression
#    guard. Assert all three legs stay compile-gated:
RELAY_A="shared/src/androidMain/kotlin/com/vg/run/RelayConfig.android.kt"
RELAY_I="shared/src/iosMain/kotlin/com/vg/run/RelayConfig.ios.kt"
APPSTATE="iosApp/iosApp/AppState.swift"
# Since the dev-relay slot (2026-07-17) the gate is a release-FIRST when{}:
# the first branch pins !DEBUG / !isDebugBinary to RELAY_URLS_FROM_PROPERTIES
# (the ordered address list since 2026-10-23 — several onions, one relay),
# so the emulator/simulator clearnet override AND the dev-relay slot are both
# structurally unreachable in a release build. Assert that exact shape: a when
# whose FIRST branch is the release pin, with the clearnet literal after it.
if ! perl -0777 -ne 'exit 1 unless /CANDIDATE_URLS[^=]*=[^{]*when\s*\{\s*!BuildConfig\.DEBUG\s*->\s*RELAY_URLS_FROM_PROPERTIES\b.*?10\.0\.2\.2/s' "$RELAY_A" 2>/dev/null; then
  echo "FAIL: Android BASE_URL is not a release-first when{} (!BuildConfig.DEBUG -> RELAY_URLS_FROM_PROPERTIES before the 10.0.2.2 override)." >&2
  fail=1
fi
if ! perl -0777 -ne 'exit 1 unless /CANDIDATE_URLS[^=]*=[^{]*when\s*\{\s*!Platform\.isDebugBinary\s*->\s*RELAY_URLS_FROM_PROPERTIES\b.*?localhost:8080/s' "$RELAY_I" 2>/dev/null; then
  echo "FAIL: iOS BASE_URL is not a release-first when{} (!Platform.isDebugBinary -> RELAY_URLS_FROM_PROPERTIES before the localhost override)." >&2
  fail=1
fi
# iOS direct (clearnet) connect must sit inside a #if DEBUG…#else block so a
# release fails CLOSED (torState=.disconnected) instead of routing direct.
if ! perl -0777 -ne 'exit 1 unless /#if DEBUG.*?connectDirect\(\).*?#else/s' "$APPSTATE" 2>/dev/null; then
  echo "FAIL: iOS connectDirect() (clearnet) is not inside a #if DEBUG block in AppState.swift." >&2
  fail=1
fi

# 5) The Argon2id KDF cost is lowered ONLY in debug (test-build speed). Assert the
#    release path stays memory-hard: the const is >= 64 MiB and the runtime cost
#    falls back to that const in release (the else-branch of the isDebugBuild gate).
#    The KDF block moved out of VaultSelector.kt into VaultKdf.kt (2026-11 readability
#    pass); a missing file makes every grep below FAIL loudly, never pass silently.
VAULTSEL="shared/src/commonMain/kotlin/com/vg/run/VaultKdf.kt"
if ! grep -qE "const val ARGON2_MEMORY_KIB = 65_536" "$VAULTSEL" 2>/dev/null; then
  echo "FAIL: ARGON2_MEMORY_KIB release constant is not 65_536 (64 MiB)." >&2
  fail=1
fi
if ! grep -qE "if \(isDebugBuild\).*else ARGON2_MEMORY_KIB" "$VAULTSEL" 2>/dev/null; then
  echo "FAIL: runtime Argon2 memory is not 'if (isDebugBuild) … else ARGON2_MEMORY_KIB' — release must use the full cost." >&2
  fail=1
fi
if ! grep -qE "if \(isDebugBuild\).*else ARGON2_ITERATIONS" "$VAULTSEL" 2>/dev/null; then
  echo "FAIL: runtime Argon2 iterations is not gated to fall back to ARGON2_ITERATIONS in release." >&2
  fail=1
fi

# 6) FLAG_SECURE (screenshot/screen-record protection) and the
#    inactivity auto-lock are RELEASE protections that are skipped ONLY in DEBUG
#    (FLAG_SECURE is dropped in debug so the e2e suites can screen-record; the
#    auto-lock is skipped so accessibility-driven tests don't get locked out).
#    Both are gated the OPPOSITE way from the debug-only hooks above —
#    `if (!BuildConfig.DEBUG)` — so a future edit that inverts or drops the gate
#    would ship a RELEASE with no screenshot protection or no auto-lock, uncaught.
#    Assert both stay inside `if (!BuildConfig.DEBUG)` (multiline: the block spans
#    several lines). Mirrors the clearnet-override guard (#4).
MAIN="$SRC/MainActivity.kt"
if ! perl -0777 -ne 'exit 1 unless /if\s*\(!BuildConfig\.DEBUG\)\s*\{\s*window\.setFlags\(\s*WindowManager\.LayoutParams\.FLAG_SECURE/s' "$MAIN" 2>/dev/null; then
  echo "FAIL: FLAG_SECURE is not applied inside 'if (!BuildConfig.DEBUG)' in MainActivity.kt — a release could ship without screenshot protection." >&2
  fail=1
fi
# Since the periodic re-auth (docs/periodic-reauth-design.md, 2026-08-21) ONE
# watchdog Runnable drives both Lever C and the re-auth deadline, so it is posted
# in EVERY build from onResume (the re-auth branch must tick in debug for the
# TEST_REAUTH_INTERVAL_MS e2e hook). The release-only gate therefore moved INSIDE
# the Runnable: the Lever-C idle computation must sit in
# `if (!BuildConfig.DEBUG && vm.vault != null) { … leverCRemainingMs = timeoutMs - idleMs }`.
# Assert BOTH halves: (a) the watchdog still runs from onResume (immediate run() since 2026-11-06, or posted), and (b) the
# Lever-C branch is still release-gated — dropping or inverting either would ship
# a release with no idle auto-lock. (PeriodicReauthLockSourceTest locks the same
# structure from the JVM side.)
if ! perl -0777 -ne 'exit 1 unless /override fun onResume\(\)\s*\{.*?(?:autoLockHandler\.postDelayed\(autoLockCheck,|autoLockCheck\.run\(\))/s' "$MAIN" 2>/dev/null; then
  echo "FAIL: the auto-lock watchdog is not posted from onResume in MainActivity.kt — a release could ship without auto-lock." >&2
  fail=1
fi
if ! perl -0777 -ne 'exit 1 unless /if\s*\(!BuildConfig\.DEBUG\s*&&\s*vm\.vault\s*!=\s*null\)\s*\{[^}]*leverCRemainingMs\s*=\s*timeoutMs\s*-\s*idleMs/s' "$MAIN" 2>/dev/null; then
  echo "FAIL: the Lever-C idle auto-lock branch is not gated on '!BuildConfig.DEBUG && vm.vault != null' inside the watchdog in MainActivity.kt — a release could ship without auto-lock." >&2
  fail=1
fi

# 7) Every ProcessInfo.processInfo.arguments
#    read in iosApp/iosApp/*.swift drives test-only behavior — up to and
#    including a full crypto-erase vault wipe (--test-wipe-on-launch) — and must
#    be lexically inside an ACTIVE `#if DEBUG` branch, never the #else/#elseif
#    side and never unconditional. Release Xcode configurations define neither
#    SWIFT_ACTIVE_COMPILATION_CONDITIONS=DEBUG nor GCC_PREPROCESSOR_DEFINITIONS
#    DEBUG=1 (verified by reading project.pbxproj), so anything actually gated
#    this way is compiled OUT of the shipped binary.
#
#    A per-file "does this file contain #if DEBUG anywhere" test would pass even
#    if the read sat in the file's #else branch or entirely outside the #if —
#    the exact weakness check-logging-gated.sh:97-102 has for Swift Logger
#    declarations. So this does a real preprocessor-depth walk per file instead:
#    a stack tracks each enclosing #if/#elseif's condition and current branch,
#    and a hit only counts as gated if some enclosing entry is CURRENTLY on a
#    branch whose condition is literally `DEBUG` (#else always clears that
#    entry's flag, since the #else branch of `#if DEBUG` is release code).
PI_FILES=()
while IFS= read -r f; do
  [ -n "$f" ] && PI_FILES+=("$f")
done < <(grep -l 'ProcessInfo\.processInfo\.arguments' iosApp/iosApp/*.swift 2>/dev/null)
if [ "${#PI_FILES[@]}" -eq 0 ]; then
  echo "FAIL: found no iosApp/iosApp/*.swift files to scan for ProcessInfo.processInfo.arguments — refusing to report OK." >&2
  fail=1
else
  pi_hits="$(perl -ne '
      if (/^\s*#if\s+(.*?)\s*(?:\/\/.*)?$/) {
          push @stack, ($1 eq "DEBUG") ? 1 : 0;
      } elsif (/^\s*#elseif\s+(.*?)\s*(?:\/\/.*)?$/) {
          $stack[-1] = ($1 eq "DEBUG") ? 1 : 0 if @stack;
      } elsif (/^\s*#else\b/) {
          $stack[-1] = 0 if @stack;
      } elsif (/^\s*#endif\b/) {
          pop @stack;
      } elsif (/ProcessInfo\.processInfo\.arguments/) {
          my $gated = 0;
          $gated ||= $_ for @stack;
          print "$ARGV:$.: $_" unless $gated;
      }
      close(ARGV) if eof;
  ' "${PI_FILES[@]}" 2>&1)"
  if [ -n "$pi_hits" ]; then
    echo "$pi_hits" >&2
    echo "FAIL: ProcessInfo.processInfo.arguments read outside an active '#if DEBUG' branch (lines above) — must be compiled out of Release." >&2
    fail=1
  fi
fi

if [ "$fail" -ne 0 ]; then
  echo "✗ Debug-hook gating regression detected." >&2
  exit 1
fi
echo "✓ Debug-hook gating intact: testTagsAsResourceId=BuildConfig.DEBUG, logging off, paste reveal gated, clearnet override DEBUG-gated (Android+iOS+AppState), Argon2 release cost memory-hard, FLAG_SECURE + auto-lock release-gated, iOS launch-arg reads #if DEBUG-gated."

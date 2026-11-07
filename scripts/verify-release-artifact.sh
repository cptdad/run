#!/usr/bin/env bash
# Release-ARTIFACT security verification (external review 2026-07, #5).
#
# Complements the source-level gate (verify-release-clean.sh) by inspecting a
# BUILT release artifact: validly + expected-key signed, no INJECTED unsigned
# entries, and a hardened compiled manifest (not debuggable, backup disabled,
# a network-security-config present, only MainActivity exported). Run against
# the assembleRelease (.apk, F-Droid/direct) or bundleRelease (.aab,
# Play Store) output before distributing.
#   usage: scripts/verify-release-artifact.sh <release .apk|.aab>
#
# .apk  → apksigner (whole-artifact v2/v3) + aapt2 manifest checks.
# .aab  → jarsigner signature + MANIFEST.MF coverage (detects post-signing
#         injected entries — jarsigner -verify -strict is NOT usable
#         here because a legit .aab trips its benign "signed in JarFile but not in
#         JarInputStream" warning on every entry) + bundletool manifest checks.
set -uo pipefail
APK="${1:-}"
[ -n "$APK" ] && [ -f "$APK" ] || { echo "usage: verify-release-artifact.sh <release .apk|.aab>" >&2; exit 2; }
case "$APK" in
  *.apk) KIND=apk ;;
  *.aab) KIND=aab ;;
  *) echo "unsupported artifact (need .apk or .aab): $APK" >&2; exit 2 ;;
esac
SDK_BT="${ANDROID_HOME:-$HOME/Library/Android/sdk}/build-tools"
fail=0

# --- belt-and-braces relay-scrub check --------------------------
# shared/build.gradle.kts's generateRelayUrl task scrubs the dev/test relay
# .onion to an empty constant for any release compilation it can DETECT from the
# invocation (assembleRelease, bundleRelease, linkReleaseFramework*, a bare
# `build`/`assemble`, CONFIGURATION=Release, STRIP_DEV_RELAY=1) — but that
# detection is necessarily heuristic (Gradle camel-case abbreviations like `aR`
# resolve only against the full task graph, which is not safely introspectable
# there — see the comment above releaseArtifactIntent in that file). This check
# is unconditional: it inspects the ACTUAL BUILT ARTIFACT, so it closes the gap
# regardless of how the artifact was produced. Read the dev onion the SAME way
# the build does — RELAY_DEV_ONION_URL env var first, else the gitignored
# repo-root relay.properties `relayDevOnionUrl` key — and NEVER print it.
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# The dev value is a COMMA-SEPARATED list since 2026-10-23 (several onion
# addresses of one relay): split it like the build does — entries trimmed,
# empty items ignored; a non-empty env var wins over relay.properties for the
# WHOLE list — and check EVERY entry. Never print one.
dev_raw="${RELAY_DEV_ONION_URL:-}"
if [ -z "$(printf '%s' "$dev_raw" | tr -d ', \t')" ] && [ -f "$REPO_ROOT/relay.properties" ]; then
  # Parse like java.util.Properties (what Gradle uses): `key=value`, `key = value`
  # or `key:value`, with `\:` escapes in the value.
  dev_raw="$(sed -nE 's/^[[:space:]]*relayDevOnionUrl[[:space:]]*[=:][[:space:]]*//p' "$REPO_ROOT/relay.properties" | tail -1 | sed 's/\\:/:/g' | tr -d '\r\n')"
fi
# `strings` output goes to a temp FILE that is grepped afterwards. Do NOT pipe it
# into `grep -q`: under `pipefail`, grep -q exits at the first match, strings/unzip
# die with SIGPIPE (141), the pipeline status is non-zero, and the `if` silently
# takes the "no leak" branch (verified fail-open with GNU strings).
dev_strings="$(mktemp)"
trap 'rm -f "$dev_strings"' EXIT
unzip -p "$APK" 2>/dev/null | strings > "$dev_strings"
dev_checked=0
dev_leaked=0
IFS=',' read -r -a dev_entries <<< "$dev_raw"
for dev_onion in "${dev_entries[@]}"; do
  dev_onion="$(printf '%s' "$dev_onion" | tr -d ' \t')"
  [ -n "$dev_onion" ] || continue
  dev_checked=$((dev_checked+1))
  if grep -qF -- "$dev_onion" "$dev_strings"; then
    echo "✗ configured dev/test relay .onion entry #$dev_checked is present as a string in $(basename "$APK") — release scrub bypassed" >&2
    dev_leaked=1
    fail=1
  fi
done
if [ "$dev_checked" -gt 0 ]; then
  [ "$dev_leaked" -ne 0 ] || echo "✓ none of the $dev_checked configured dev/test relay .onion address(es) is present in the artifact"
else
  echo "✓ no dev/test relay configured (RELAY_DEV_ONION_URL / relay.properties relayDevOnionUrl) — nothing to check"
fi

# --- post-signing injected-entry detection against the SIGNED file ---
# jarsigner -verify (v1 JAR signing) WITHOUT -strict exits 0 even when extra
# UNSIGNED entries are appended after signing — the tamper this catches. -strict
# can't be used (it also fails a legit .aab, exit 4, on a benign streaming-verify
# quirk on every entry).
#
# An earlier version tried a coverage check against META-INF/MANIFEST.MF — WRONG: MANIFEST.MF
# is NOT the cryptographically protected file. META-INF/*.SF is (and *.RSA signs
# the .SF). An attacker who injects a file AND adds its `Name:` line to MANIFEST.MF
# passed that check; they CANNOT add to the .SF without the private key.
#
# So use TWO INDEPENDENT signals — a check that shares one blind spot manufactures
# false confidence — and require BOTH:
#   (a) every content entry appears in the SIGNED .SF (attacker-uneditable); and
#   (b) `jarsigner -verify` does not report "unsigned entries".
# Validated (scratchpad) on a real signed .aab: clean passes both; a co-edited copy
# (evil.dex + a MANIFEST.MF Name line, .SF untouched) fails BOTH.
signed_entry_names() {
  # The .SF (e.g. META-INF/RUN.SF) carries a Name:+digest per SIGNED entry, in the
  # same wrapped-line format as MANIFEST.MF. Reads whichever *.SF is present.
  local aab="$1" sfname
  sfname="$(unzip -Z1 "$aab" 2>/dev/null | grep -E '^META-INF/.*\.SF$' | head -1)"
  [ -n "$sfname" ] || return 1
  unzip -p "$aab" "$sfname" 2>/dev/null | tr -d '\r' | awk '
    /^Name: /     { if (n!="") print n; n=substr($0,7); inname=1; next }
    inname && /^ /{ n=n substr($0,2); next }
                  { if (n!="") { print n; n=""; inname=0 } }
    END           { if (n!="") print n }'
}
assert_no_injected_entries() {
  local aab="$1" sf uncovered=0 e total=0
  sf="$(signed_entry_names "$aab")" || { echo "✗ .aab has no readable META-INF/*.SF (unsigned?)" >&2; return 1; }
  [ -n "$sf" ] || { echo "✗ .aab .SF lists no signed entries (unsigned/tampered?)" >&2; return 1; }
  # (a) every content entry must be in the SIGNED .SF.
  while read -r e; do
    total=$((total+1))
    case "$e" in
      ""|*/) continue ;;                                              # dirs
      META-INF/MANIFEST.MF|META-INF/*.SF|META-INF/*.RSA|META-INF/*.DSA|META-INF/*.EC) continue ;;  # signature files
    esac
    printf '%s\n' "$sf" | grep -qxF "$e" || { echo "  ✗ entry NOT in the signed .SF (post-signing injection): $e" >&2; uncovered=$((uncovered+1)); }
  done < <(unzip -Z1 "$aab" 2>/dev/null)
  # Fail CLOSED if the archive enumeration was empty — a broken unzip must not
  # pass a signature-coverage gate by vacuously covering zero entries.
  [ "$total" -gt 0 ] || { echo "✗ could not enumerate archive entries (empty listing) — failing closed" >&2; return 1; }
  # Reject DUPLICATE archive names outright (Android "Master Key" /
  # Bug-8219321 class). A duplicate central-directory record for an ALREADY-SIGNED
  # name defeats both signals above — (a) it IS a signed name so the .SF coverage
  # check passes, and (b) jarsigner emits a "SHA-256 digest error", NOT an "unsigned
  # entries" line — so the detector would false-green (the overall gate still fails
  # closed via the whole-jar `jarsigner -verify` at the caller, but the detector's
  # standalone guarantee would be violable). Fail closed here so a future refactor
  # trusting the detector alone can't be bypassed.
  local dups
  dups="$(unzip -Z1 "$aab" 2>/dev/null | sort | uniq -d)"
  if [ -n "$dups" ]; then
    echo "  ✗ archive contains DUPLICATE entry names (Master-Key-class tamper):" >&2
    printf '    %s\n' $dups >&2
    uncovered=$((uncovered+1))
  fi
  # (b) independent signal: jarsigner's own unsigned-entry report.
  if jarsigner -verify "$aab" 2>/dev/null | grep -qi 'unsigned entries'; then
    echo "  ✗ jarsigner reports UNSIGNED entries (post-signing injection)" >&2
    uncovered=$((uncovered+1))
  fi
  if [ "$uncovered" -ne 0 ]; then
    echo "✗ archive contains entries NOT covered by the signature (post-signing tampering)" >&2
    return 1
  fi
  echo "✓ every archive entry is in the signed .SF and jarsigner reports no unsigned entries"
  return 0
}

# Signer verification (FAIL-CLOSED). The release signing config fails
# OPEN to UNSIGNED when no keystore is present (androidApp/build.gradle.kts), so
# a manifest-only gate would happily pass an UNSIGNED artifact. Assert the
# artifact is validly signed — and, when RUN_EXPECTED_SIGNER_SHA256 is set, that
# it is signed by the EXPECTED key (paste the signer's SHA-256 cert digest).
signer_sha=""
if [ "$KIND" = apk ]; then
  APKSIGNER="$(ls "$SDK_BT"/*/apksigner 2>/dev/null | sort -V | tail -1)"
  [ -n "$APKSIGNER" ] || { echo "apksigner not found in Android SDK build-tools" >&2; exit 2; }
  if sig_out="$("$APKSIGNER" verify --print-certs "$APK" 2>/dev/null)"; then
    signer_sha="$(printf '%s' "$sig_out" | grep -aiE 'certificate SHA-256 digest:' | head -1 | grep -aoiE '[0-9a-f]{64}' | tr 'A-F' 'a-f')"
    echo "✓ APK is validly signed${signer_sha:+ (signer SHA-256 $signer_sha)}"
  else
    echo "✗ APK is NOT validly signed — release signing may have fallen back to UNSIGNED" >&2; fail=1
  fi
else
  if jarsigner -verify "$APK" 2>/dev/null | grep -q 'jar verified'; then
    # Strip the "SHA256:" label BEFORE removing colons — otherwise the 'A' in
    # "SHA256" is valid hex and shifts the 64-char grab off the real digest.
    signer_sha="$(unzip -p "$APK" 'META-INF/*.RSA' 'META-INF/*.DSA' 'META-INF/*.EC' 2>/dev/null | keytool -printcert 2>/dev/null | grep -aiE 'SHA256:' | head -1 | sed -E 's/.*[Ss][Hh][Aa]256:[[:space:]]*//' | tr -d ' :' | grep -aoiE '^[0-9a-f]{64}' | tr 'A-F' 'a-f')"
    echo "✓ AAB is validly signed${signer_sha:+ (signer SHA-256 $signer_sha)}"
  else
    echo "✗ AAB is NOT validly signed — release signing may have fallen back to UNSIGNED" >&2; fail=1
  fi
  # Catch post-signing injected entries against the SIGNED .SF (+
  # jarsigner's own unsigned-entry report) — jarsigner -verify alone misses them.
  assert_no_injected_entries "$APK" || fail=1
fi
# Verify the signer IDENTITY by DEFAULT, not just signature presence.
# The expected release-signer SHA-256 cert digest is baked in below (it is NOT a
# secret — it is embedded in every shipped APK), so a wrong-key but validly-signed
# artifact — e.g. a debug key, or an attacker-swapped keystore in ~/.run-signing/
# outside the repo/gitleaks scope — FAILS even when RUN_EXPECTED_SIGNER_SHA256 is
# unset. The env var overrides the default (e.g. to verify a rotated key). Update
# EXPECTED_SIGNER_SHA256 here whenever the release signing key is rotated.
EXPECTED_SIGNER_SHA256="29b4d5195bbc4ffd9be87c2547ee33371c7edff46f14ba8f93eadd7e2d2d2422"
want="$(printf '%s' "${RUN_EXPECTED_SIGNER_SHA256:-$EXPECTED_SIGNER_SHA256}" | tr -d ' :' | tr 'A-F' 'a-f')"
if [ -n "$signer_sha" ] && [ "$signer_sha" = "$want" ]; then
  echo "✓ signer matches the expected release key"
else
  echo "✗ signer '$signer_sha' != expected '$want' (wrong key or unsigned)" >&2; fail=1
fi

# --- Manifest hardening checks ---
# aapt2 reads the APK's binary manifest; the .aab manifest is protobuf, read via
# bundletool. Both are checked directly on the shipped artifact (the
# .aab manifest is not skipped). Checks (both formats): NOT debuggable,
# allowBackup=false, networkSecurityConfig present, only $PKG.MainActivity exported.
if [ "$KIND" = aab ]; then
  BUNDLETOOL="$(command -v bundletool 2>/dev/null)"
  if [ -z "$BUNDLETOOL" ]; then
    # FAIL CLOSED. A release-integrity gate silently skipping part of
    # itself is worse than requiring the tool — the earlier warn-skip let an environment
    # without bundletool downgrade coverage of the shipped .aab's manifest. bundletool is
    # a standard Android tool; install it (e.g. `brew install bundletool` or via the SDK
    # cmdline-tools) to cut a release. (Source gate + release-APK check remain, but this
    # gate must verify the ACTUAL shipped .aab.)
    echo "✗ bundletool not found — REQUIRED for .aab manifest verification" >&2
    fail=1
  else
    MAN="$("$BUNDLETOOL" dump manifest --bundle="$APK" 2>/dev/null)"
    [ -n "$MAN" ] || { echo "✗ could not read .aab manifest via bundletool" >&2; fail=1; }
    PKG="$(printf '%s' "$MAN" | grep -aoE 'package="[^"]+"' | head -1 | sed -E 's/.*"([^"]+)".*/\1/')"

    if printf '%s' "$MAN" | grep -qiE 'android:debuggable="true"'; then
      echo "✗ release is DEBUGGABLE" >&2; fail=1
    else echo "✓ not debuggable"; fi

    if printf '%s' "$MAN" | grep -qiE 'android:allowBackup="false"'; then
      echo "✓ allowBackup=false"
    else echo "✗ allowBackup is not explicitly false" >&2; fail=1; fi

    if printf '%s' "$MAN" | grep -qiE 'android:networkSecurityConfig='; then
      echo "✓ networkSecurityConfig set"
    else echo "✗ no networkSecurityConfig — release must define a cleartext policy" >&2; fail=1; fi

    # Our OWN ($PKG.*) code must export nothing but the launcher MainActivity.
    # bundletool emits each component's opening tag (with its attributes) on ONE
    # line, so a per-line test is sufficient (third-party library exports like
    # ProfileInstallReceiver are permission-gated and out of $PKG.* scope).
    if [ -z "$PKG" ]; then
      echo "✗ could not determine app package from the .aab — cannot verify exported components" >&2; fail=1
    else
      own_extra="$(printf '%s' "$MAN" \
        | grep -aE '<(activity|activity-alias|service|receiver|provider) ' \
        | grep -a 'android:exported="true"' \
        | grep -aF "android:name=\"$PKG." \
        | grep -avF "android:name=\"$PKG.MainActivity\"" | grep -c .)"
      exp_total="$(printf '%s' "$MAN" | grep -ac 'android:exported="true"')"
      if [ "$own_extra" -ne 0 ]; then
        echo "✗ $own_extra $PKG.* component(s) other than MainActivity are exported" >&2; fail=1
      else
        echo "✓ only MainActivity exported from $PKG.* ($exp_total exported total incl. library components)"
      fi
    fi
  fi
  if [ "$fail" -ne 0 ]; then
    echo "✗ Release artifact FAILED security checks: $APK" >&2; exit 1
  fi
  echo "✓ Release artifact checks passed: $(basename "$APK")"
  exit 0
fi

# --- .apk manifest checks (aapt2) ---
AAPT2="$(ls "$SDK_BT"/*/aapt2 2>/dev/null | sort -V | tail -1)"
[ -n "$AAPT2" ] || { echo "aapt2 not found in Android SDK build-tools" >&2; exit 2; }

XML="$("$AAPT2" dump xmltree --file AndroidManifest.xml "$APK" 2>/dev/null)"
[ -n "$XML" ] || { echo "could not read manifest from $APK (extraction failed)" >&2; exit 3; }

# App package/namespace — DERIVED from the artifact, not hardcoded, so this gate
# stays correct if the app is renamed or built under a variant namespace
# (external review 2026-07 #4). aapt2 already expands relative component names
# (".Foo") to fully-qualified in the COMPILED manifest, but we normalise anyway
# (belt-and-braces) in case the script is ever pointed at a merged/source
# manifest. If BOTH derivation paths fail we do NOT silently assume a package —
# a privacy release gate must prefer "could not determine package" over guessing,
# else the exported-component assertion (below) would be scoped to the wrong
# namespace and quietly pass (external review 2026-07 secfix4 follow-up).
PKG="$("$AAPT2" dump packagename "$APK" 2>/dev/null | head -1 | tr -d '[:space:]')"
[ -n "$PKG" ] || PKG="$(printf '%s' "$XML" | grep -aoE 'A: package="[^"]+"' | head -1 | sed -E 's/.*"([^"]+)".*/\1/')"

# 1) NOT debuggable (a shipped debug build / BuildConfig.DEBUG leak).
if printf '%s' "$XML" | grep -qiE "android:debuggable\(0x[0-9a-f]+\)=true"; then
  echo "✗ release is DEBUGGABLE" >&2; fail=1
else
  echo "✓ not debuggable"
fi

# 2) backup / data-extraction disabled (no off-device copy of the encrypted vault).
if printf '%s' "$XML" | grep -qiE "android:allowBackup\(0x[0-9a-f]+\)=false"; then
  echo "✓ allowBackup=false"
else
  echo "✗ allowBackup is not explicitly false" >&2; fail=1
fi

# 3) network-security-config present (constrains cleartext; Tor is the only
#    transport). FAIL CLOSED — for a privacy app an absent cleartext policy is a
#    release defect, not a warning (external review 2026-07 #2).
if printf '%s' "$XML" | grep -qiE "android:networkSecurityConfig"; then
  echo "✓ networkSecurityConfig set"
else
  echo "✗ no networkSecurityConfig — release must define a cleartext policy" >&2; fail=1
fi

# 4) exported components: our OWN code ($PKG.*) must export nothing but the
#    launcher MainActivity. Third-party library exports (e.g. AndroidX
#    ProfileInstallReceiver, Play Billing) are permission-gated and out of scope,
#    so we scope the assertion to our package rather than a raw count that would
#    false-fail on them (external review 2026-07 #2).
#
#    Block-aware parse: aapt2 emits a component's own attributes right after its
#    "E: <component>" line and BEFORE any nested "E: intent-filter"/action, so the
#    component name is the FIRST android:name in the block and exported=true (if
#    present) is at the same level. This survives attribute reordering — a plain
#    grep -B1 would miss a violation whenever android:theme/launchMode sit between
#    name and exported.
#
#    norm(): relative (".Foo") and bare ("Foo") component names are resolved
#    against $PKG before the ownership test, so a future ".BadReceiver" declared
#    exported is still caught even if it reaches this parser un-expanded
#    (external review 2026-07 #4).
own_extra=$(printf '%s' "$XML" | awk -v pkg="$PKG" '
  function norm(n) {
    if (n ~ /^\./)    return pkg n
    if (n !~ /\./)    return pkg "." n
    return n
  }
  function flush(  n) {
    if (!incomp) return
    n = norm(cname)
    if (cexp && n == pkg "." "MainActivity") return          # the launcher: allowed
    if (cexp && index(n, pkg ".") == 1)      bad++           # any other app-owned export
  }
  /E: (activity|activity-alias|service|receiver|provider) \(/ { flush(); incomp=1; cname=""; cexp=0; next }
  incomp && cname=="" && match($0, /android:name\([^)]*\)="[^"]*"/) {
    s=substr($0,RSTART,RLENGTH); sub(/.*="/,"",s); sub(/"$/,"",s); cname=s; next
  }
  incomp && /android:exported\([^)]*\)=true/ { cexp=1 }
  END { flush(); print bad+0 }
')
exp_total=$(printf '%s' "$XML" | grep -ciE "android:exported\(0x[0-9a-f]+\)=true")
if [ -z "$PKG" ]; then
  echo "✗ could not determine app package from the APK — cannot verify exported components" >&2; fail=1
elif [ "$own_extra" -ne 0 ]; then
  echo "✗ $own_extra $PKG.* component(s) other than MainActivity are exported" >&2; fail=1
else
  echo "✓ only MainActivity exported from $PKG.* ($exp_total exported total incl. library components)"
fi

if [ "$fail" -ne 0 ]; then
  echo "✗ Release artifact FAILED security checks: $APK" >&2; exit 1
fi
echo "✓ Release artifact checks passed: $(basename "$APK")"

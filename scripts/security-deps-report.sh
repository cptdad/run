#!/usr/bin/env bash
# Security-critical dependency freshness GATE (external review 2026-07, #1).
#
# Reports the pinned anonymity-transport / crypto dependencies AND FAILS when one
# is behind its approved-minimum version past a time-boxed exception window. A
# temporary exception (expiry date + rationale) lets a TRACKED upgrade defer
# without silently accepting staleness — once the expiry passes, this blocks.
# Wired into .githooks/pre-push (enforcing) AND mirrored in CI (release-gates.yml)
# because a hook alone is bypassable.
set -uo pipefail
cd "$(dirname "$0")/.."
today="$(date +%Y-%m-%d)"
fail=0

# The "approved-min" is a TEMPORARY floor that unblocks a tracked upgrade — NOT
# a claim that it is the newest release. It is the minimum we will ship past
# the exception window, nothing more (external review 2026-07 #3).
# label | pinned | temp-approved-min | exception-expiry (YYYY-MM-DD, "" = none) | rationale
gate() {
  local label="$1" pinned="$2" approved="$3" expiry="$4" why="$5"
  if [ -z "$pinned" ]; then echo "  ? $label: version not found" >&2; fail=1; return; fi
  local lower; lower="$(printf '%s\n%s\n' "$pinned" "$approved" | sort -V | head -1)"
  if [ "$pinned" = "$approved" ] || [ "$lower" != "$pinned" ]; then
    echo "  ✓ $label: $pinned (>= temp-approved min $approved)"
  elif [ -n "$expiry" ] && [[ "$today" < "$expiry" ]]; then
    echo "  ⚠ $label: $pinned < temp-approved min $approved — EXCEPTION until $expiry ($why)"
  else
    echo "  ✗ $label: $pinned < temp-approved min $approved — exception ${expiry:-none} EXPIRED/absent ($why)" >&2
    fail=1
  fi
}

echo "Security-critical dependency freshness gate:"
tor="$(grep -oE 'tor-android:[0-9.]+'       shared/build.gradle.kts | head -1 | cut -d: -f2)"
sqlc="$(grep -oE 'sqlcipher-android:[0-9.]+' shared/build.gradle.kts | head -1 | cut -d: -f2)"
# Extend coverage beyond Tor/SQLCipher to the rest of the
# transport/crypto surface, so an accidental downgrade of any of these is caught
# and they stay visible in the report. Floors sit at the current pins (no active
# exception); raise a floor above the pin with an expiry+rationale to time-box a
# deferred upgrade.
okhttp="$(grep -oE 'okhttp:[0-9.]+'          shared/build.gradle.kts | head -1 | cut -d: -f2)"
tink="$(grep -oE 'tink-android:[0-9.]+'      shared/build.gradle.kts | head -1 | cut -d: -f2)"
bc="$(grep -oE 'bcprov-jdk18on:[0-9.]+'      shared/build.gradle.kts | head -1 | cut -d: -f2)"
camerax="$(grep -oE 'camera-camera2:[0-9.]+' androidApp/build.gradle.kts | head -1 | cut -d: -f2)"
# The UnifiedPush connector performs the RFC 8291 WebPush DECRYPTION of every
# push wake on non-Play devices, so it belongs on this list too — and it is the
# artifact the Tink pin is COUPLED to (its POM requires com.google.crypto.tink:
# tink at an exact version, which :androidApp excludes in favour of the
# tink-android pin above). Pinned in the version catalog, not a module file.
upconn="$(grep -oE '^unifiedpush = "[0-9.]+"' gradle/libs.versions.toml | head -1 | grep -oE '[0-9.]+')"

# Floors match the shipped pins since the 2026-07 maintenance pass (Tor
# 0.4.9.11), the 2026-09 BouncyCastle bump to 1.86, the 2026-09 SQLCipher
# core bump to 4.19.0, and the 2026-09-16 transport/crypto pass (OkHttp 5.5.0,
# Tink 1.23.0, UnifiedPush connector 3.3.5); no active exceptions. When a floor
# is next raised ahead of the pin, add a time-boxed exception (expiry +
# rationale).
#
# OkHttp 5.x note: `com.squareup.okhttp3:okhttp` is a Kotlin-Multiplatform
# module from 5.0.0 on, so the coordinate in shared/build.gradle.kts is a
# metadata redirect and Gradle resolves the real Android artifact as
# `okhttp-android`. The grep above still reads the declared `okhttp:<version>`
# pin, which is the number that matters here. The bump was gated on
# re-verifying the SOCKS remote-DNS invariant against the 5.5.0 sources
# (RouteSelector still returns an UNRESOLVED address for Proxy.Type.SOCKS,
# never reaching the Dns lookup) — see PlatformHttpClientSocksDnsTest.
#
# SQLCipher core 4.19.0 on BOTH platforms as of 2026-09-16 (the older note here
# claimed no swift-sqlcipher release wrapped core 4.18.0 — true when written,
# stale since 2026-08-29). skiptools/swift-sqlcipher 1.12.0 wraps core 4.18.0
# and 1.13.0 wraps core 4.19.0, so the iOS pin below is 1.13.0 = the same core
# as net.zetetic:sqlcipher-android 4.19.0. The two wrappers version
# independently; what must stay in lockstep is the CORE, so check the
# swift-sqlcipher release notes for the core version before moving either pin.
#
# Do NOT let this floor pull the project onto SQLCipher 5.x. 5.0.0-beta
# (2026-09-15) switches to AES-256-GCM AEAD, 512K KDF iterations and 8192-byte
# default pages, i.e. it changes how an EXISTING vault file is read. That is a
# per-vault migration (cipher_compatibility / cipher_migrate) with a brick
# hazard, not a version bump — it needs its own design pass on both platforms.
gate "Tor (guardianproject:tor-android)" "$tor"  "0.4.9.13" "" \
     "keep in lockstep with the iOS tor.xcframework rebuild (same TOR_VERSION)"
gate "SQLCipher (net.zetetic)"           "$sqlc" "4.19.0"   "" \
     "keep in lockstep with iOS swift-sqlcipher (same SQLCipher core)"
gate "OkHttp (com.squareup.okhttp3)"     "$okhttp" "5.5.0"  "" \
     "SOCKS/Tor transport on Android; 5.x since 2026-09-16 (remote DNS re-verified)"
gate "Tink (com.google.crypto.tink)"     "$tink"   "1.23.0" "" \
     "AEAD + Android Keystore master key; COUPLED to the UnifiedPush connector pin"
gate "BouncyCastle (org.bouncycastle)"   "$bc"     "1.86"   "" \
     "Argon2id vault KDF (v3)"
gate "CameraX (androidx.camera)"         "$camerax" "1.3.4" "" \
     "QR pairing scanner; pulls transitive appcompat/fragment (pinned up)"
gate "UnifiedPush connector"             "$upconn" "3.3.5"  "" \
     "RFC 8291 WebPush decryption; COUPLED to the Tink pin (see androidApp/build.gradle.kts)"

# The freshness floor was Android-only. The iOS transport/crypto
# pins ARE SHA/revision-pinned, but a downgrade wasn't caught here — gate them too.
# iOS Tor = TOR_VERSION in the framework build script (kept in lockstep with the
# Android tor-android pin); iOS SQLCipher = swift-sqlcipher (skiptools SPM wrapper)
# from Package.resolved.
ios_tor="$(grep -oE 'TOR_VERSION="[0-9.]+"' iosApp/scripts/build-tor-xcframework.sh | head -1 | grep -oE '[0-9.]+')"
ios_sqlc="$(grep -A5 '"identity" : "swift-sqlcipher"' iosApp/iosApp.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved | grep -oE '"version" : "[0-9.]+"' | head -1 | grep -oE '[0-9.]+')"
gate "iOS Tor (tor.xcframework TOR_VERSION)" "$ios_tor"  "0.4.9.13" "" \
     "keep in lockstep with the Android tor-android pin (same Tor core)"
gate "iOS SQLCipher (swift-sqlcipher SPM)"   "$ios_sqlc" "1.13.0"   "" \
     "SQLCipher core for the iOS vault; wrapper version — 1.13.0 wraps core 4.19.0"

# The About-box Tor version SHOWN TO USERS must match the bundled
# pin. It silently drifted (0.4.9.8 displayed while the bundle was 0.4.9.11) because
# nothing checked it. Assert it here so a future Tor bump that misses AboutContent
# fails the gate.
about_tor="$(grep -oE 'torVersion: String = "[0-9.]+"' shared/src/commonMain/kotlin/com/vg/run/AboutContent.kt | grep -oE '[0-9]+\.[0-9.]+' | head -1)"
if [ "$about_tor" = "$tor" ]; then
  echo "  ✓ About-box torVersion matches the Tor pin ($about_tor)"
else
  echo "  ✗ About-box torVersion ($about_tor) != bundled tor-android pin ($tor) — update AboutContent.kt" >&2
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  echo "✗ A security-critical dependency is stale past its exception window — upgrade it or renew the exception (with rationale)." >&2
  exit 1
fi
echo "✓ Dependency freshness gate passed (any stale deps are within their exception window)."
exit 0

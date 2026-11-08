#!/usr/bin/env bash
# Sign the Linux-built `foss` release APK with the release key, for the GitHub release asset
# that F-Droid verifies against (docs/fdroid-recipe.yml `Binaries:`).
#
#   scripts/reproducible/sign-foss-apk.sh <unsigned.apk> <out-signed.apk>
#
# WHY LINUX-BUILT: the Android NDK ships a different clang binary per host. Same version,
# same sources, but the Linux build is compiled with MLGO (ML-guided register allocation and
# inlining) and BOLT, the macOS build is not — the .so each produces differs by a few bytes
# (seen 2026-11-08: librunargon2.so arm64 23880 vs 23888 bytes). F-Droid rebuilds on Linux, so
# the APK we sign must come from a Linux build too: the `reproducible-foss` workflow's artifact
# (gh run download). This script only adds the signature; it changes nothing else.
#
# Signing material stays OUT of the repo tree ($RUN_SIGNING_DIR, default ~/.run-signing,
# keystore.properties with storeFile/storePassword/keyAlias/keyPassword — the same file the
# Gradle release build reads). Passwords are handed to apksigner through the environment, never
# on the command line, and this script prints none of them.
set -euo pipefail

UNSIGNED="${1:-}"; OUT="${2:-}"
[ -f "$UNSIGNED" ] && [ -n "$OUT" ] || { sed -n '2,6p' "$0"; exit 2; }

SIGNING_DIR="${RUN_SIGNING_DIR:-$HOME/.run-signing}"
PROPS="$SIGNING_DIR/keystore.properties"
[ -f "$PROPS" ] || { echo "no keystore.properties at $PROPS" >&2; exit 1; }

# (`sed -n 1p`, not `head -1`: under pipefail an early-closing reader is a SIGPIPE exit.)
prop() { sed -n "s/^$1=//p" "$PROPS" | sed -n '1p'; }
STORE_FILE="$(prop storeFile)"
case "$STORE_FILE" in /*) ;; *) STORE_FILE="$SIGNING_DIR/$STORE_FILE" ;; esac
[ -f "$STORE_FILE" ] || { echo "keystore not found: $STORE_FILE" >&2; exit 1; }
KEY_ALIAS="$(prop keyAlias)"
export RUN_KS_PASS="$(prop storePassword)"
export RUN_KEY_PASS="$(prop keyPassword)"

# apksigner from build-tools 34.0.0, DELIBERATELY not the newest: F-Droid verifies by copying our
# signature onto its own rebuild (apksigcopier). apksigner 35.0.0-rc1 and later write the APK in a
# way that copy cannot reproduce ("DOES NOT VERIFY … CHUNKED_SHA512 digest mismatch", seen here
# with 37.0.0 on 2026-11-08); F-Droid's own documentation says to use 34. Install it with
# `sdkmanager "build-tools;34.0.0"` or set RUN_APKSIGNER to a 34.0.0 apksigner.
SDK_BT="${ANDROID_HOME:-$HOME/Library/Android/sdk}/build-tools"
APKSIGNER="${RUN_APKSIGNER:-$SDK_BT/34.0.0/apksigner}"
[ -x "$APKSIGNER" ] || { echo "apksigner 34.0.0 not found at $APKSIGNER (newer versions break F-Droid's signature copy)" >&2; exit 1; }

# minSdk 30: v1 (JAR) signing adds nothing and only slows installs; v2 + v3 like the store build.
"$APKSIGNER" sign \
  --ks "$STORE_FILE" --ks-key-alias "$KEY_ALIAS" \
  --ks-pass env:RUN_KS_PASS --key-pass env:RUN_KEY_PASS \
  --v1-signing-enabled false --v2-signing-enabled true --v3-signing-enabled true \
  --out "$OUT" "$UNSIGNED"
unset RUN_KS_PASS RUN_KEY_PASS

"$APKSIGNER" verify --print-certs "$OUT" 2>/dev/null | grep -E 'SHA-256' | sed -n '1p'
echo "signed: $OUT"
# The release gate (signer identity, zero Google code, manifest) must pass on the result:
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
"$REPO_ROOT/scripts/verify-release-artifact.sh" "$OUT"

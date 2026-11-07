#!/usr/bin/env bash
#
# build-tor-xcframework.sh — reproducibly (re)build the vendored, DYNAMIC
# Tor.xcframework at iosApp/Frameworks/tor.xcframework.
#
# Why this exists / what it does, end to end:
#   1. Clone iCepa/Tor.framework at a pinned tag and run its
#      build-xcframework.sh -c to compile Tor + OpenSSL + libevent + liblzma
#      from pinned official upstream tags into a STATIC `tor` lib per slice.
#   2. Re-link each slice into a DYNAMIC framework that exports ONLY the
#      tor_api + logging entry points the in-app iCepa Obj-C wrapper
#      (iosApp/Tor/*.m) calls. The dynamic framework gives Tor a two-level
#      namespace so its internal base16/base32/... symbols stay PRIVATE and do
#      NOT collide with the identically-named symbols in SQLCipher's bundled
#      libtomcrypt (a static-link collision crashes Tor at startup in
#      base16_decode; see iosApp/SwiftTor-VERIFICATION.md).
#   3. Assemble the two slices into iosApp/Frameworks/tor.xcframework.
#
# Toolchain (Homebrew): autoconf automake libtool po4a gettext. NOTE: Apple's
# /usr/bin/libtool must win for the `-static` archive merge, while GNU
# `libtoolize` must be available for the autotools deps — so we DO NOT prepend
# Homebrew libtool's gnubin; instead we expose only `libtoolize` via a shim.
#
# Usage:  iosApp/scripts/build-tor-xcframework.sh
# Output: iosApp/Frameworks/tor.xcframework  (device + iOS-sim slices)
# Idempotent. Takes ~20-40 min (compiles OpenSSL + Tor for 3 arch/SDK combos).
set -euo pipefail

# --- pins (bump these to update Tor; keep SwiftTor-VERIFICATION.md in sync) ---
ICEPA_REPO="https://github.com/iCepa/Tor.framework.git"
ICEPA_TAG="v409.14.1"         # bundles Tor 0.4.9.14 / OpenSSL 3.6.5 / libevent 2.1.13 / xz 5.8.4
# A git TAG is mutable — upstream can re-point it at
# a different commit. Pin the immutable commit the tag currently resolves to and
# assert it after clone (below), so a silently-moved tag fails the build instead
# of building unknown source. Keep in sync with SwiftTor-VERIFICATION.md.
ICEPA_COMMIT="2b1192c81fc359bcf1c21a16526b76a2a2c1f419"
TOR_VERSION="0.4.9.14"
# TOR OVERRIDE (generic, normally INACTIVE). When Tor ships a security release
# that iCepa has not re-tagged for yet, set this to the `tor-X.Y.Z.W` value of
# the ONE `TOR_VERSION=` line in the pinned iCepa build-xcframework.sh; the
# script then rewrites only that line so the Tor source cloned is the tag
# TOR_VERSION names, keeping iCepa's audited OpenSSL/libevent/xz pins and
# recipe. The rewrite refuses unless exactly one line matches, and the built
# binary is asserted to embed exactly TOR_VERSION below. Used once for 0.4.9.12
# (2026-09-21, on iCepa v409.11.1). Leave EMPTY whenever the pinned iCepa tag's
# own pin already equals tor-$TOR_VERSION (as v409.13.1 does).
TOR_OVERRIDE_ICEPA_PIN=""
# CFBundleShortVersionString must be <= 3 period-separated integers (App Store
# ITMS-90060), so the embedded framework advertises the 3-component prefix.
# The exact Tor version (TOR_VERSION) is asserted from the binary below and
# recorded in SwiftTor-VERIFICATION.md.
TOR_SHORT="$(echo "$TOR_VERSION" | cut -d. -f1-3)"
IOS_MIN="15.0"

# Symbols the in-app wrapper (iosApp/Tor) binds to. Everything else stays
# internal to the dylib (that is the whole point — keep Tor's codec symbols
# private so they cannot collide with SQLCipher/libtomcrypt).
EXPORTS=(
  _tor_main_configuration_new
  _tor_main_configuration_set_command_line
  _tor_main_configuration_free
  _tor_run_main
  _tor_api_get_provider_version
  _tor_main_configuration_setup_control_socket
  _add_callback_log
  _set_log_severity_config
  _event_enable_debug_logging
  _event_set_log_callback
)

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEST="$REPO_ROOT/iosApp/Frameworks/tor.xcframework"
WORK="$(mktemp -d /tmp/tor-xcf-build.XXXXXX)"
# Keep the workdir on FAILURE (a ~25-min build's artifacts are the only way to
# debug a layout/assertion problem); clean it only on success.
trap '[[ $? -eq 0 ]] && rm -rf "$WORK" || echo "NOTE: kept workdir for debugging: $WORK" >&2' EXIT

command -v brew >/dev/null || { echo "Homebrew required"; exit 1; }
for t in autoconf automake po4a gettext; do brew list "$t" >/dev/null 2>&1 || brew install "$t"; done
brew list libtool >/dev/null 2>&1 || brew install libtool   # installs glibtoolize

# Shim: provide GNU `libtoolize` WITHOUT shadowing Apple's /usr/bin/libtool.
SHIM="$WORK/shim"; mkdir -p "$SHIM"
ln -sf "$(command -v glibtoolize)" "$SHIM/libtoolize"
export PATH="$PATH:$SHIM"

echo "==> [1/3] clone iCepa $ICEPA_TAG and build static tor (-c)"
git clone --depth 1 --branch "$ICEPA_TAG" "$ICEPA_REPO" "$WORK/icepa"
# Assert the tag still resolves to the pinned commit BEFORE the long
# build. A re-pointed tag (or a compromised mirror) yields a different HEAD and
# aborts here rather than compiling unknown Tor source.
ACTUAL_COMMIT="$(git -C "$WORK/icepa" rev-parse HEAD)"
[[ "$ACTUAL_COMMIT" == "$ICEPA_COMMIT" ]] \
  || { echo "ERROR: iCepa $ICEPA_TAG resolved to $ACTUAL_COMMIT, expected pinned $ICEPA_COMMIT (SwiftTor-VERIFICATION.md). Tag moved or repo compromised — refusing to build."; exit 1; }
# Apply the Tor tag override (see TOR_OVERRIDE_ICEPA_PIN above): exactly one
# line must match, or iCepa's script changed shape and the override is unsafe.
if [[ -n "${TOR_OVERRIDE_ICEPA_PIN:-}" && "$TOR_OVERRIDE_ICEPA_PIN" != "tor-$TOR_VERSION" ]]; then
  N="$(grep -c "^TOR_VERSION=\"$TOR_OVERRIDE_ICEPA_PIN\"" "$WORK/icepa/build-xcframework.sh" || true)"
  [[ "$N" == "1" ]] || { echo "ERROR: expected exactly one TOR_VERSION=\"$TOR_OVERRIDE_ICEPA_PIN\" line in iCepa's build-xcframework.sh, found $N — refusing to override"; exit 1; }
  sed -i '' "s/^TOR_VERSION=\"$TOR_OVERRIDE_ICEPA_PIN\"/TOR_VERSION=\"tor-$TOR_VERSION\"/" "$WORK/icepa/build-xcframework.sh"
  echo "==> Tor tag override: iCepa pin $TOR_OVERRIDE_ICEPA_PIN -> tor-$TOR_VERSION"
fi
( cd "$WORK/icepa" && ./build-xcframework.sh -c )
STATIC="$WORK/icepa/tor.xcframework"
# Newer iCepa build-xcframework.sh (v409.11.x) emits ZIPPED output
# (tor.xcframework.zip + tor-nolzma.xcframework.zip) instead of an unzipped
# tor.xcframework/ dir. Unzip the lzma variant (what we have always shipped).
if [[ ! -d "$STATIC" && -f "$STATIC.zip" ]]; then
  mkdir -p "$WORK/unzipped"
  unzip -q "$STATIC.zip" -d "$WORK/unzipped"
  STATIC="$(find "$WORK/unzipped" -maxdepth 2 -name "*.xcframework" -type d | head -1)"
  [[ -n "$STATIC" ]] || STATIC="$WORK/unzipped"   # zip may contain slices at its root
fi
[[ -d "$STATIC" ]] || { echo "ERROR: iCepa build produced neither tor.xcframework/ nor tor.xcframework.zip"; exit 1; }

# Locate the per-slice static tor libs WITHOUT hardcoding layout — v409.8.x
# used ios-arm64/tor.framework/tor (lowercase), newer tags may capitalize the
# framework, add a macOS slice, or nest differently.
find_lib() { # $1 = required path fragment, $2 = excluded fragment ("" = none)
  find "$STATIC" -type f \( -name tor -o -name Tor \) -path "*$1*" \
    ${2:+! -path "*$2*"} ! -name "*.plist" 2>/dev/null | head -1
}
DEV_LIB="$(find_lib ios-arm64 simulator)"
SIM_LIB="$(find_lib simulator macos)"
if [[ -z "$DEV_LIB" || -z "$SIM_LIB" ]]; then
  echo "ERROR: could not locate device/simulator tor libs under $STATIC — layout:" >&2
  find "$STATIC" -maxdepth 4 >&2
  exit 1
fi
# The relink step links the STATIC archive into our dynamic framework; a dylib
# here would silently produce an empty re-export — refuse it.
[[ "$(file "$DEV_LIB")" == *archive* || "$(file "$DEV_LIB")" == *object* ]] \
  || { echo "ERROR: $DEV_LIB is not a static archive: $(file "$DEV_LIB")"; exit 1; }
# NOTE: `strings BIG | grep -q` is a pipefail TRAP — grep -q exits on the first
# match, strings dies with SIGPIPE (141), and pipefail reports the SUCCESSFUL
# match as failure. grep -c drains the stream, so the pipeline status is grep's.
[[ "$(strings "$DEV_LIB" | grep -cE "tor $TOR_VERSION")" -gt 0 ]] \
  || { echo "ERROR: built Tor is not $TOR_VERSION (lib: $DEV_LIB)"; exit 1; }

IOS_SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
SIM_SDK="$(xcrun --sdk iphonesimulator --show-sdk-path)"
EXPORTS_FILE="$WORK/exports.txt"; printf '%s\n' "${EXPORTS[@]}" > "$EXPORTS_FILE"

mk_info() { cat > "$1" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>Tor</string>
<key>CFBundleIdentifier</key><string>org.torproject.Tor</string>
<key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
<key>CFBundleName</key><string>Tor</string>
<key>CFBundlePackageType</key><string>FMWK</string>
<key>CFBundleShortVersionString</key><string>$TOR_SHORT</string>
<key>CFBundleVersion</key><string>1</string>
<key>MinimumOSVersion</key><string>$IOS_MIN</string>
</dict></plist>
PLIST
}

# $1=static tor lib  $2=output Tor.framework dir  $3=sdk path  $4..=clang arch flags
relink() {
  local static_lib="$1" out="$2" sdk="$3"; shift 3
  local hdrs; hdrs="$(dirname "$static_lib")/Headers"
  [[ -d "$hdrs" ]] || { echo "ERROR: no Headers/ next to $static_lib"; find "$STATIC" -maxdepth 4 >&2; exit 1; }
  mkdir -p "$out/Headers"
  xcrun clang -dynamiclib "$@" -isysroot "$sdk" \
    -o "$out/Tor" -Wl,-exported_symbols_list,"$EXPORTS_FILE" \
    "$static_lib" -lz -framework Security -framework CoreFoundation \
    -install_name @rpath/Tor.framework/Tor
  cp -R "$hdrs/" "$out/Headers/"
  mk_info "$out/Info.plist"
}

echo "==> [2/3] re-link dynamic frameworks (device + iOS sim)"
relink "$DEV_LIB" "$WORK/dev/Tor.framework" "$IOS_SDK" \
  -arch arm64 -miphoneos-version-min=$IOS_MIN
relink "$SIM_LIB" "$WORK/sim/Tor.framework" "$SIM_SDK" \
  -arch arm64 -arch x86_64 -mios-simulator-version-min=$IOS_MIN

echo "==> [3/3] assemble tor.xcframework"
rm -rf "$DEST"
xcodebuild -create-xcframework \
  -framework "$WORK/dev/Tor.framework" \
  -framework "$WORK/sim/Tor.framework" \
  -output "$DEST"

# Verify the collision-causing symbols are NOT exported (kept internal).
# (grep -c, not -q: -q under pipefail can misreport via SIGPIPE — see above.)
if [[ "$(nm -gU "$DEST/ios-arm64/Tor.framework/Tor" | grep -cE "_base16_decode$")" -gt 0 ]]; then
  echo "ERROR: base16_decode is EXPORTED — symbol isolation failed"; exit 1
fi

# Record per-slice SHA-256 of the freshly built Tor binaries.
# scripts/verify-tor-xcframework.sh re-hashes these on every pre-push so tampering
# with the committed framework BETWEEN rare rebuilds fails closed. The record MUST
# only ever change via a genuine rebuild — commit it alongside the framework.
REC="$REPO_ROOT/iosApp/Frameworks/tor.xcframework.sha256"
{
  echo "# SHA-256 of the committed tor.xcframework Tor binaries AND its Info.plists"
  echo "# (binaries and Info.plists both covered)."
  echo "# Regenerated by build-tor-xcframework.sh on rebuild; verified by"
  echo "# scripts/verify-tor-xcframework.sh (pre-push). Update ONLY via a real rebuild."
  echo "#"
  echo "# The root Info.plist is the SLICE-SELECTION MANIFEST — its \`LibraryIdentifier\`"
  echo "# entries are what Xcode follows to decide which Tor.framework to link — so an"
  echo "# unpinned one let an attacker add a slice and repoint the build at it with every"
  echo "# recorded binary hash still matching. The per-slice Info.plists carry the"
  echo "# framework identity (name, minimum OS, platform). The verifier additionally"
  echo "# ENUMERATES the tree, so a file listed in no record at all is a failure."
  for slice in ios-arm64/Tor.framework/Tor ios-arm64_x86_64-simulator/Tor.framework/Tor \
               Info.plist ios-arm64/Tor.framework/Info.plist \
               ios-arm64_x86_64-simulator/Tor.framework/Info.plist; do
    sha="$(shasum -a 256 "$DEST/$slice" | cut -d' ' -f1)"
    echo "$sha  $slice"
  done
} > "$REC"
echo "OK: recorded tor.xcframework binary + Info.plist SHA-256 → $REC"

# Regenerate the HEADERS-tree record here too. It used to
# be produced by hand, so a rebuild left it stale — and now that a missing/stale
# headers record is a hard FAILURE in the verifier (not a warning), a rebuild that
# did not rewrite it would fail the next pre-push. Same digest the verifier
# recomputes: per-file shasum over the sorted tree, hashed again.
HREC="$REPO_ROOT/iosApp/Frameworks/tor.xcframework.headers.sha256"
{
  echo "# Tree-digest of each slice's compiled Tor.framework/Headers."
  echo "# The headers are COMPILE INPUTS (SYSTEM_HEADER_SEARCH_PATHS → the app compiles the"
  echo "# iCepa Obj-C wrapper incl. tor_api.h), so a tampered/added header would compile"
  echo "# into the app while the binary-only gate (tor.xcframework.sha256) passed. This is a"
  echo "# whole-tree digest computed by verify-tor-xcframework.sh:"
  echo "#   ( cd <slice>/Tor.framework/Headers && find . -type f | LC_ALL=C sort | xargs shasum -a256 ) | shasum -a256"
  echo "# so it catches a modified header (content) AND an added/removed one (the file list)."
  echo "# Regenerated by build-tor-xcframework.sh on rebuild — never by hand."
  for slice in ios-arm64/Tor.framework/Headers ios-arm64_x86_64-simulator/Tor.framework/Headers; do
    sha="$( ( cd "$DEST/$slice" && find . -type f | LC_ALL=C sort | xargs shasum -a256 ) | shasum -a256 | cut -d' ' -f1 )"
    echo "$sha  $slice"
  done
} > "$HREC"
echo "OK: recorded tor.xcframework headers-tree SHA-256 → $HREC"

echo "OK: tor.xcframework rebuilt (Tor $TOR_VERSION, dynamic, codecs private) at $DEST"

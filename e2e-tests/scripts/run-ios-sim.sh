#!/usr/bin/env bash
# Run the single-device specs on an iOS SIMULATOR (not a physical device).
#
# Why a separate script: the config selects the target via env (WDIO_IOS_UDID /
# _DEVICE / _VERSION / _APP_PATH), so "run on the simulator" is: build the app
# for the simulator SDK, boot a sim, point the suite at it, and run.
#
# Notes:
#   * The simulator is NOT integrity-blocked: IntegrityCheck.swift returns false
#     under `#if targetEnvironment(simulator)`, so the app reaches the PIN screen.
#   * No prebuilt WDA needed — WDA builds fast and stays stable on a simulator
#     (the prebuilt-WDA dance is only for the flaky PHYSICAL-device WDA).
#
# cross:multi (the real send-over-Tor flow) still runs on PHYSICAL devices; this
# script is only for the Tor-independent single-device specs.
#
# Usage:
#   ./scripts/run-ios-sim.sh                            # auto-pins a stable
#                                                       # iOS 18.x sim (see below)
#   WDIO_IOS_UDID=<sim-udid> ./scripts/run-ios-sim.sh   # override the auto-pick
set -uo pipefail
cd "$(dirname "$0")/.."

DDP="${TMPDIR:-/tmp}/run-ios-sim"                       # derivedDataPath for the sim build
APP="$DDP/Build/Products/Debug-iphonesimulator/Run.app"
LOG="${TMPDIR:-/tmp}/e2e-ios-sim.log"

# Repair Appium's driver cache if this repo was moved/renamed (absolute paths
# baked into node_modules/.cache/appium go stale on a move — see the script).
./scripts/ensure-appium-home.sh

# Pick the sim. Priority (this comment described the
# RETIRED iOS 18.x pin and contradicted the code below it — the 18.x pin is gone;
# iOS 26.x is now the target runtime):
#   1. explicit WDIO_IOS_UDID (override — wins over everything)
#   2. an ALREADY-BOOTED iPhone sim — definitely bootable, which sidesteps the
#      registered-but-data-gone sims that simctl still lists as "available".
#   3. any iPhone on an iOS 26.x runtime.
#   4. fallback: newest available iPhone, with a loud warning.
# Historical note kept because it explains the boot guard below: some sims WEDGE
# mid-boot — they report `(Booted)` while their services never start, so
# `bootstatus -b` blocks forever (a 75-minute hang on an iOS 26.5 iPhone 17 Pro,
# 2026-06-15; erase+reboot did not fix it). Hence the bounded wait.
UDID="${WDIO_IOS_UDID:-}"
if [ -z "$UDID" ]; then
  # Prefer an ALREADY-BOOTED iPhone sim (definitely bootable — sidesteps the
  # registered-but-data-gone sims simctl still lists as "available"). The
  # `[- ]?` gap tolerates BOTH stock names ("iPhone 17 Pro", a space) and
  # custom/renamed sims ("e2e-iPhone17Pro", no separator at all) — a plain
  # `iPhone [0-9]` silently misses the latter and falls through to the noisy
  # "no iOS 26.x sim found" warning branch below even when a perfectly good
  # sim is booted (caught 2026-08-21 triaging a custom-named sim).
  UDID=$(xcrun simctl list devices booted | awk -F'[()]' '/iPhone[- ]?[0-9].*Booted/{print $2; exit}')
  # Otherwise pick an iOS 26.x iPhone sim (the iOS 18.x pin was retired).
  [ -z "$UDID" ] && UDID=$(xcrun simctl list devices available | awk -F'[()]' '
    /^-- iOS 26/{ok=1; next} /^-- /{ok=0}
    ok && $1 ~ /iPhone[- ]?[0-9]/ {print $2; exit}')
  if [ -n "$UDID" ]; then
    echo "Selected sim: $UDID"
  else
    UDID=$(xcrun simctl list devices available | awk -F'[()]' '/iPhone[- ]?[0-9]/{u=$2} END{print u}')
    [ -z "$UDID" ] && { echo "No iPhone simulator available." >&2; exit 1; }
    echo "WARNING: no iOS 26.x sim found; falling back to $UDID" >&2
  fi
fi
echo "Simulator: $UDID"

# Ensure the chosen sim is BOOTED before anything else. A pinned WDIO_IOS_UDID
# skips the boot branch above; on a Shutdown sim the pre-run
# `simctl uninstall` below then fails SILENTLY (|| true), and Appium with
# noReset:true happily reuses whatever STALE app is still installed — the
# whole suite passes/fails against yesterday's binary with no visible hint
# (caught 2026-06-12: groups.spec failed against a pre-groups build).
# bootstatus -b boots if needed and blocks until the sim is usable.
xcrun simctl bootstatus "$UDID" -b >/dev/null

# Derive deviceName + runtime version for the appium caps. Use a `|` delimiter
# because device names contain spaces (e.g. "iPhone 17").
IFS='|' read -r DEV_NAME OS_VER < <(xcrun simctl list devices --json | python3 -c '
import json,sys
udid=sys.argv[1]; d=json.load(sys.stdin)
for rt,devs in d["devices"].items():
    for dev in devs:
        if dev["udid"]==udid:
            ver=rt.split("iOS-")[-1].replace("-",".") if "iOS-" in rt else ""
            print("{}|{}".format(dev["name"], ver)); sys.exit(0)
print("|"); ' "$UDID")
echo "Device: ${DEV_NAME:-?}  iOS: ${OS_VER:-?}"

echo "Building Run.app for the simulator SDK (SIGNED with Keychain entitlements)..."
# IMPORTANT: do NOT pass CODE_SIGNING_ALLOWED=NO, and DO pass an explicit
# CODE_SIGN_ENTITLEMENTS that OVERRIDES the project's. The project's
# iosApp.entitlements sets data-protection but NOT keychain-access-groups, so a
# plain simulator build still lacks the team-prefixed keychain group -> every
# Keychain call fails with errSecMissingEntitlement (-34018) ->
# IosAppController.setRealCredential throws an uncaught Kotlin exception -> the
# app SIGABRTs during PIN setup and the suite hangs at "Confirm your PIN". The
# sim's securityd requires the keychain-access-group to be TEAM-PREFIXED, so we
# synthesize a minimal entitlements plist (command-line CODE_SIGN_ENTITLEMENTS
# wins over the project setting) and let xcodebuild embed it in one signing pass
# (post-hoc `codesign --force` only re-signs the main bundle and SpringBoard
# then rejects the launch). On a device this is auto-provided by the profile.
TEAM="${WDIO_IOS_TEAM_ID:-YOUR_TEAM_ID}"
ENT="${TMPDIR:-/tmp}/run-sim-entitlements.plist"
cat > "$ENT" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>application-identifier</key><string>$TEAM.com.vg.run</string>
  <key>com.apple.developer.team-identifier</key><string>$TEAM</string>
  <key>keychain-access-groups</key><array><string>$TEAM.com.vg.run</string></array>
  <key>com.apple.developer.default-data-protection</key><string>NSFileProtectionComplete</string>
</dict></plist>
PLIST
xcodebuild build -project ../iosApp/iosApp.xcodeproj -scheme Run -configuration Debug \
  -derivedDataPath "$DDP" -destination "platform=iOS Simulator,id=$UDID" \
  -allowProvisioningUpdates CODE_SIGN_STYLE=Automatic DEVELOPMENT_TEAM="$TEAM" \
  CODE_SIGN_ENTITLEMENTS="$ENT" >"${TMPDIR:-/tmp}/ios-sim-build.log" 2>&1 \
  || { echo "Sim build failed — see ${TMPDIR:-/tmp}/ios-sim-build.log" >&2; tail -5 "${TMPDIR:-/tmp}/ios-sim-build.log"; exit 1; }
[ -d "$APP" ] || { echo "Built app not found at $APP" >&2; exit 1; }

# Fresh install: the suite runs noReset:true, so Appium reuses the INSTALLED app
# and a rebuild alone won't deploy your changes. Uninstall first so Appium
# installs the freshly built bundle (the iOS analog of `adb install -r`).
xcrun simctl uninstall "$UDID" com.vg.run >/dev/null 2>&1 || true

echo "Running specs [${WDIO_SPEC:-all}] on $UDID (log: $LOG)..."
WDIO_IOS_UDID="$UDID" \
WDIO_IOS_DEVICE="${DEV_NAME:-iPhone}" \
WDIO_IOS_VERSION="${OS_VER:-}" \
WDIO_IOS_APP_PATH="$APP" \
  npx wdio run ./wdio.ios.conf.ts ${WDIO_SPEC:+--spec "$WDIO_SPEC"} 2>&1 | tee "$LOG"
rc=${PIPESTATUS[0]}
echo ""
grep -E "Spec Files" "$LOG" | tail -1
exit "$rc"

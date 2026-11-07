#!/usr/bin/env bash
# Run the single-device specs on an Android EMULATOR (not a physical device).
#
# Why a separate script: the configs select the device purely via env
# (WDIO_ANDROID_UDID), so "run on the emulator" is just: build the debug APK,
# install it FRESH onto the emulator, point the suite at the emulator, and run.
#
# Two lessons are baked in:
#   1. noReset:true reuses the INSTALLED app — so `assembleDebug` alone
#      never deploys your changes. We always `adb install -r` the freshly
#      built APK.
#   2. uiautomator2/UiAutomation state on an emulator can get wedged
#      ("UiAutomationService already registered!" -> DeadObjectException ->
#      pin_dots never appears) — most often after a previously KILLED run left a
#      stale UiAutomation connection. Pass --reboot to cold-reboot the emulator
#      first and clear it.
#
# cross:multi (the real send-over-Tor flow) still runs on PHYSICAL devices; this
# script is only for the Tor-independent single-device specs.
#
# Usage:
#   ./scripts/run-android-emu.sh [--reboot]
#   WDIO_ANDROID_UDID=emulator-5554 ./scripts/run-android-emu.sh   # pin a device
#   WDIO_SPEC=tests/update-nudge.spec.ts ./scripts/run-android-emu.sh   # one spec (mirrors run-ios-sim.sh)
set -uo pipefail
cd "$(dirname "$0")/.."

ADB="${ANDROID_HOME:-$HOME/Library/Android/sdk}/platform-tools/adb"
APK="../androidApp/build/outputs/apk/debug/androidApp-debug.apk"
LOG="${TMPDIR:-/tmp}/e2e-android-emu.log"

# Repair Appium's driver cache if this repo was moved/renamed (absolute paths
# baked into node_modules/.cache/appium go stale on a move — see the script).
./scripts/ensure-appium-home.sh

# Pick the emulator: explicit env, else the first running `emulator-*` device.
UDID="${WDIO_ANDROID_UDID:-$("$ADB" devices | awk '/^emulator-/{print $1; exit}')}"
if [ -z "$UDID" ]; then
  echo "No Android emulator found. Boot one first (e.g. \`emulator -avd <name>\`)." >&2
  exit 1
fi
echo "Emulator: $UDID"

if [ "${1:-}" = "--reboot" ]; then
  echo "Cold-rebooting emulator to clear any stale UiAutomation state..."
  "$ADB" -s "$UDID" uninstall io.appium.uiautomator2.server >/dev/null 2>&1 || true
  "$ADB" -s "$UDID" uninstall io.appium.uiautomator2.server.test >/dev/null 2>&1 || true
  "$ADB" -s "$UDID" reboot
  "$ADB" -s "$UDID" wait-for-device
  for _ in $(seq 1 60); do
    [ "$("$ADB" -s "$UDID" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ] && break
    sleep 5
  done
fi

echo "Building debug APK..."
(cd .. && ./gradlew :androidApp:assembleDebug -q) || { echo "APK build failed" >&2; exit 1; }

# DeviceLockPolicy (2026-07-21): a device with NO lock screen is FORCED to the
# MAXIMUM tier, whose credential is a >=70-bit PASSPHRASE — this PIN-only suite
# cannot provision on a lock-less device (EulaHelper fails loudly at the
# chooser). Fresh AVDs ship with no lock, so set one. Idempotent: `verify`
# first, because `set-pin` refuses when a credential already exists.
if "$ADB" -s "$UDID" shell locksettings verify --old 1111 2>/dev/null | grep -qi "successful"; then
  echo "$UDID already has the test lock PIN"
else
  "$ADB" -s "$UDID" shell locksettings set-pin 1111 >/dev/null 2>&1 \
    && echo "$UDID lock PIN set to 1111" \
    || echo "WARNING: $UDID — could not set a lock PIN; the app will force MAXIMUM there" >&2
fi

echo "Installing fresh APK (noReset reuses the installed app)..."
"$ADB" -s "$UDID" install -r "$APK" || { echo "APK install failed" >&2; exit 1; }

# English pin (PHASE 0 localization): a fresh/reinstalled APK loses any
# earlier per-app locale pin, so re-pin right after install too (best-effort).
"$ADB" -s "$UDID" shell cmd locale set-app-locales com.vg.run --locales en-US || true

echo "Running specs [${WDIO_SPEC:-all}] on $UDID (log: $LOG)..."
WDIO_ANDROID_UDID="$UDID" npx wdio run ./wdio.android.conf.ts ${WDIO_SPEC:+--spec "$WDIO_SPEC"} 2>&1 | tee "$LOG"
rc=${PIPESTATUS[0]}
echo ""
grep -E "Spec Files" "$LOG" | tail -1
exit "$rc"

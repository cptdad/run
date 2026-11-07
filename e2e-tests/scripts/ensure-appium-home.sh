#!/usr/bin/env bash
# Keep Appium's driver cache consistent with WHERE this repo currently lives.
#
# Appium records each installed driver's location as an ABSOLUTE path in
# node_modules/.cache/appium/extensions.yaml. That cache moves with the repo
# (it lives under node_modules) but its baked-in paths do NOT update, so after
# the source tree is moved or renamed every driver lookup fails with:
#
#   Could not find a driver for automationName 'UiAutomator2' ...
#   Could not read the driver manifest at <OLD_PATH>/.../package.json: ENOENT
#
# (The XCUITest driver can mask this if its old path happens to still exist —
# which is exactly how a move can break Android while iOS keeps passing.)
#
# Fix: if any cached installPath points outside the current checkout, drop the
# cache. Appium regenerates it from the driver packages installed in this
# repo's own node_modules (they are declared as deps in package.json) on the
# next start, with correct absolute paths. Safe to run every time; a no-op when
# the cache already matches.
set -uo pipefail
cd "$(dirname "$0")/.."

HERE="$(pwd)"
CACHE="node_modules/.cache/appium/extensions.yaml"

if [ -f "$CACHE" ] && grep -q "installPath:" "$CACHE" \
   && grep "installPath:" "$CACHE" | grep -vq "installPath: $HERE/"; then
  echo "Appium driver cache points outside $HERE — clearing stale extensions cache so Appium regenerates it..."
  rm -f node_modules/.cache/appium/extensions.yaml node_modules/.cache/appium/package.hash
fi

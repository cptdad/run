#!/bin/sh
# WDIO 9 breaks on Node 26 (UND_ERR_INVALID_ARG at Appium session creation).
# Prefix Homebrew node@22 so wdio/appium and all child scripts run on Node 22.
NODE22_BIN="/opt/homebrew/opt/node@22/bin"
if [ ! -x "$NODE22_BIN/node" ]; then
  echo "with-node22.sh: node@22 not found at $NODE22_BIN (brew install node@22)" >&2
  exit 1
fi
export PATH="$NODE22_BIN:$PATH"
# Hold the Mac awake for the whole command (idle/display/system sleep + user-
# idle assertion). run-fleet.mjs already does this for fleet passes; standalone
# `npm run test:device:*` and ad hoc runs did not, and a scheduled macOS
# "Maintenance Sleep" froze the Appium/WDA stack mid-suite on 2026-09-16 —
# surfacing as "relay never held lit" / socket hang-ups ~16 min in, i.e. as
# fake Tor flakiness. caffeinate exits with the command it wraps.
if command -v caffeinate >/dev/null 2>&1; then
  exec caffeinate -dimsu "$@"
fi
exec "$@"

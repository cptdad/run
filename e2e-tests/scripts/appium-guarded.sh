#!/bin/sh
# Appium launch guard: never silently ride a foreign Appium server.
#
# 2026-07-13: a cross:multi3 run died mid-flight because an ORPHANED Appium
# (leftover from a previous suite, parent long gone) was still bound to 4723.
# wdio's appium-service hit EADDRINUSE, printed "Continue..." and adopted the
# orphan — which exited 4 minutes later, taking all three device sessions
# with it.
#
# This wrapper is the appium-service `command` (wdio.shared.conf.ts), so it
# guards EVERY suite on ITS OWN port (incl. run-parallel's 4723/4724):
#   - port free                  -> exec the real appium
#   - OUR appium, orphaned       -> kill it, wait for the port, exec appium
#   - OUR appium, live parent    -> fail loud; suites must run serialized
#   - anything else on the port  -> NEVER kill; fail loud, the user decides
# "Ours" = the command line runs node_modules/.bin/appium (what this wrapper
# execs). ppid alone cannot classify: on macOS every GUI app and LaunchAgent
# has ppid 1, so a Dock-launched Appium Desktop or a launchctl service would
# look "orphaned" — command-line gating keeps those off the kill path.
set -u
cd "$(dirname "$0")/.."

PORT=4723
prev=""
for a in "$@"; do
  [ "$prev" = "--port" ] && PORT="$a"
  prev="$a"
done

holder="$(lsof -nP -tiTCP:"$PORT" -sTCP:LISTEN 2>/dev/null | head -n 1 || true)"
if [ -n "$holder" ]; then
  ppid="$(ps -o ppid= -p "$holder" 2>/dev/null | tr -d ' ')"
  cmd="$(ps -o command= -p "$holder" 2>/dev/null || true)"
  if [ -z "$cmd" ]; then
    # Holder exited between the lsof probe and ps. Re-probe: a now-free port
    # is just the normal launch path; anything new on it is churn we won't race.
    if lsof -nP -tiTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
      echo "appium-guarded: :$PORT holder (pid $holder) vanished mid-probe but the port is busy again — aborting, re-run the suite" >&2
      exit 1
    fi
    echo "appium-guarded: :$PORT holder (pid $holder) exited between probes; port is free — continuing" >&2
  else
    case "$cmd" in
    *node_modules/.bin/appium*)
      if [ -n "$ppid" ] && [ "$ppid" != "1" ] && ps -p "$ppid" >/dev/null 2>&1; then
        pcmd="$(ps -o command= -p "$ppid" 2>/dev/null || true)"
        echo "appium-guarded: port :$PORT held by a LIVE appium (pid $holder, ppid $ppid): $cmd" >&2
        case "$pcmd" in
        *wdio* | *node*)
          echo "appium-guarded: another suite appears to be running — suites must be serialized. Aborting." >&2
          ;;
        *)
          echo "appium-guarded: its parent ($pcmd) is not a wdio/node runner — started by hand? Refusing to kill. Aborting." >&2
          ;;
        esac
        exit 1
      fi
      echo "appium-guarded: killing ORPHANED appium on :$PORT (pid $holder, ppid ${ppid:-?}): $cmd" >&2
      kill "$holder" 2>/dev/null
      i=0
      while [ $i -lt 20 ] && lsof -nP -tiTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; do
        i=$((i + 1))
        sleep 0.5
        [ $i -eq 10 ] && kill -9 "$holder" 2>/dev/null
      done
      if lsof -nP -tiTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
        echo "appium-guarded: port :$PORT still busy after kill — aborting" >&2
        exit 1
      fi
      ;;
    *)
      # Not ours (Appium Desktop, a launchctl service, anything else): never
      # a kill candidate, whatever its ppid says.
      echo "appium-guarded: port :$PORT held by a FOREIGN listener (pid $holder): $cmd" >&2
      echo "appium-guarded: not started by this guard — refusing to kill it; free the port yourself. Aborting." >&2
      exit 1
      ;;
    esac
  fi
fi

# Diagnostic (2026-07-13): the Android SDK moved to an external volume and
# runs began failing "SDK root does not exist" at session create while shell
# probes saw the path fine. Surface THIS process's view so the next such
# failure is attributable without external probing. Non-fatal.
if [ -n "${ANDROID_HOME:-}" ] && ! [ -e "$ANDROID_HOME" ]; then
  echo "appium-guarded: WARNING — ANDROID_HOME '$ANDROID_HOME' is NOT visible from this process" >&2
fi

exec ./node_modules/.bin/appium "$@"

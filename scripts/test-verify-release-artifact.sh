#!/usr/bin/env bash
# ADVERSARIAL regression test for verify-release-artifact.sh.
#
# Written from the ATTACKER's capability, not the author's: an adversary who can
# modify the built .aab between bundleRelease and upload can add ANY unsigned file
# AND edit any UNSIGNED metadata file (incl. META-INF/MANIFEST.MF). An earlier
# gate checked coverage against MANIFEST.MF — which the attacker CAN edit — and so
# passed a co-edited bundle. The gate must instead detect against the
# SIGNED META-INF/*.SF (attacker-uneditable without the key). These cases include
# that exact bypass so the gate can't regress into false-green again.
#
# Uses a real signed .aab as the fixture; copies it to a temp dir before tampering,
# so the repo/build output is never modified.
#
#   usage: scripts/test-verify-release-artifact.sh [<signed .aab>]
# Skips (exit 0) if no signed .aab is available — like the artifact gate itself.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
GATE="$HERE/verify-release-artifact.sh"
AAB="${1:-$HERE/../androidApp/build/outputs/bundle/release/androidApp-release.aab}"

if [ ! -f "$AAB" ]; then
  echo "⚠ no signed .aab at $AAB — skipping artifact-gate regression test (build one with bundleRelease to run it)"
  exit 0
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
cp "$AAB" "$TMP/clean.aab"

# Tamper 1 — naive: append an UNSIGNED entry, no re-sign, no manifest edit.
cp "$AAB" "$TMP/tampered.aab"
printf 'injected\n' > "$TMP/evil.txt"
( cd "$TMP" && zip -q tampered.aab evil.txt )

# Tamper 2 — the co-edit bypass: inject a file AND add its Name: line to MANIFEST.MF
# (which the earlier gate trusted). The SIGNED .SF is left untouched (the attacker
# has no private key), so a .SF-based gate must still catch it.
cp "$AAB" "$TMP/coedit.aab"
mkdir -p "$TMP/mfwork/META-INF" "$TMP/mfwork/base/dex"
unzip -o -q "$AAB" META-INF/MANIFEST.MF -d "$TMP/mfwork"
printf 'Name: base/dex/evil.dex\r\nSHA-256-Digest: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\n\r\n' >> "$TMP/mfwork/META-INF/MANIFEST.MF"
printf 'EVIL-PAYLOAD' > "$TMP/mfwork/base/dex/evil.dex"
( cd "$TMP/mfwork" && zip -q "$TMP/coedit.aab" META-INF/MANIFEST.MF base/dex/evil.dex )

pass=0 failn=0
check() { if eval "$2"; then echo "  ✓ $1"; pass=$((pass+1)); else echo "  ✗ $1" >&2; failn=$((failn+1)); fi; }

echo "artifact-gate regression: verify-release-artifact.sh .aab fail-closed"

# (a) a clean, legitimately-signed .aab PASSES (exit 0).
clean_out="$(bash "$GATE" "$TMP/clean.aab" 2>&1)"; clean_rc=$?
check "clean signed .aab passes (exit 0)" "[ $clean_rc -eq 0 ]"

# (b) the .aab manifest checks actually RUN (an earlier gate skipped them).
check "clean .aab runs manifest checks (not skipped)" \
  "printf '%s' \"\$clean_out\" | grep -q 'not debuggable' && printf '%s' \"\$clean_out\" | grep -q 'allowBackup=false'"

# (c) naive injected UNSIGNED entry FAILS closed.
tam_out="$(bash "$GATE" "$TMP/tampered.aab" 2>&1)"; tam_rc=$?
check "naive injected unsigned entry fails (exit non-zero)" "[ $tam_rc -ne 0 ]"

# (d) THE CO-EDIT BYPASS: inject + MANIFEST.MF co-edit FAILS closed. This is the case
#     that silently passed the earlier gate. The regression guard for it.
co_out="$(bash "$GATE" "$TMP/coedit.aab" 2>&1)"; co_rc=$?
check "co-edit: MANIFEST.MF co-edit bypass fails (exit non-zero)" "[ $co_rc -ne 0 ]"
check "co-edit: co-edit caught against the SIGNED .SF (not MANIFEST.MF)" \
  "printf '%s' \"\$co_out\" | grep -qiE 'not in the signed .SF|unsigned entries'"

# (e) INDEPENDENT-ORACLE cross-check: jarsigner itself must NOT flag the clean
#     artifact but MUST flag the tampered ones — a second mechanism that reasons
#     differently from the .SF-name coverage, so a shared blind spot can't pass both.
check "clean .aab: jarsigner reports NO unsigned entries" \
  "! jarsigner -verify \"\$TMP/clean.aab\" 2>/dev/null | grep -qi 'unsigned entries'"
check "co-edit .aab: jarsigner DOES report unsigned entries" \
  "jarsigner -verify \"\$TMP/coedit.aab\" 2>/dev/null | grep -qi 'unsigned entries'"

# (f) a DUPLICATE central-directory record for an ALREADY-SIGNED name
#     (Android "Master Key" / Bug-8219321 class) must fail closed. It defeats the two
#     coverage signals (the name IS signed → passes .SF coverage; jarsigner emits a
#     DIGEST error, not "unsigned entries"), so the duplicate-name rejection is the
#     guard. `zip` dedups on write, so craft the true duplicate with python's zipfile
#     (which appends a second record for the same name).
DUP_ENTRY="$(unzip -Z1 "$AAB" | grep -vE '^META-INF/|/$' | head -1)"
cp "$AAB" "$TMP/dupname.aab"
python3 -c "import sys,zipfile; z=zipfile.ZipFile(sys.argv[1],'a'); z.writestr(sys.argv[2], b'EVIL-DUPLICATE'); z.close()" "$TMP/dupname.aab" "$DUP_ENTRY"
dup_out="$(bash "$GATE" "$TMP/dupname.aab" 2>&1)"; dup_rc=$?
check "duplicate-name: entry fails (exit non-zero)" "[ $dup_rc -ne 0 ]"
check "duplicate-name: caught by the injected-entry detector" \
  "printf '%s' \"\$dup_out\" | grep -qiE 'DUPLICATE entry names'"

# (g) CANARY for the dev-relay scrub check (S6 2026-11-06): a fake v3-onion-shaped
#     string planted in a text member of a copy, announced through RELAY_DEV_ONION_URL,
#     must make the gate fail with the LEAK message (not merely "some other check
#     failed" — the planted member is itself unsigned). The previous
#     `strings | grep -q` pipeline under pipefail never reported a present string.
CANARY="$(printf 'q%.0s' $(seq 1 56)).onion"   # 56 chars + .onion, a v3-onion-shaped fake
cp "$AAB" "$TMP/canary.aab"
mkdir -p "$TMP/canarywork/assets"
printf 'prefix padding\nhttp://%s/\nsuffix\n' "$CANARY" > "$TMP/canarywork/assets/canary.txt"
( cd "$TMP/canarywork" && zip -q "$TMP/canary.aab" assets/canary.txt )
can_out="$(RELAY_DEV_ONION_URL="http://$CANARY" bash "$GATE" "$TMP/canary.aab" 2>&1)"; can_rc=$?
check "canary: planted dev onion string fails the gate (exit non-zero)" "[ $can_rc -ne 0 ]"
check "canary: caught by the dev-relay scrub check itself" \
  "printf '%s' \"\$can_out\" | grep -q 'release scrub bypassed'"
# ... and the same artifact WITHOUT the env var set must not report a leak.
nocan_out="$(env -u RELAY_DEV_ONION_URL bash "$GATE" "$TMP/clean.aab" 2>&1)"
check "no canary configured: scrub check reports no leak" \
  "! printf '%s' \"\$nocan_out\" | grep -q 'release scrub bypassed'"

echo "artifact-gate regression: $pass passed, $failn failed"
[ "$failn" -eq 0 ]

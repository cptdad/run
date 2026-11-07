#!/usr/bin/env bash
# L10n freshness gate.
#
# Android's androidApp/src/main/res/values{,-<locale>}/ (12 non-English locales)
# strings_*.xml tree is the single source of truth for every user-facing
# string; scripts/l10n/gen-l10n.mjs derives the iOS String Catalogs
# (Localizable.xcstrings, InfoPlist.xcstrings), the typed Swift accessors
# (L10n.swift) and the Kotlin key map (L10nKeys.kt) from it. This gate makes
# sure nobody hand-edits a generated file, or edits the XML tree and forgets
# to regenerate, by re-running the generator in --check mode (diff against
# what's committed, no writes) and then proving the resulting catalog is
# actually well-formed by compiling it with Apple's own tool.
#
# Mirrors scripts/verify-release-clean.sh's style/conventions.
#
#   usage: scripts/verify-l10n-fresh.sh
set -uo pipefail
cd "$(dirname "$0")/.."
fail=0

# Resolve Node 22 the way e2e-tests/scripts/with-node22.sh does — WDIO 9 (and,
# defensively, this script) breaks on newer Node in some environments, so
# prefer the pinned Homebrew node@22 and fall back to whatever `node` is on
# PATH if it isn't installed (the generator itself has zero npm deps and runs
# fine on either).
NODE22_BIN="/opt/homebrew/opt/node@22/bin"
if [ -x "$NODE22_BIN/node" ]; then
  NODE_BIN="$NODE22_BIN/node"
elif command -v node >/dev/null 2>&1; then
  NODE_BIN="$(command -v node)"
else
  echo "FAIL: no node binary found (checked $NODE22_BIN and PATH)." >&2
  exit 1
fi

echo "=== L10n: generator freshness (gen-l10n.mjs --check) ==="
if ! "$NODE_BIN" scripts/l10n/gen-l10n.mjs --check; then
  echo "FAIL: generated l10n outputs are stale or invalid — run 'node scripts/l10n/gen-l10n.mjs' and commit the result." >&2
  fail=1
fi

echo ""
echo "=== L10n: translation drift (l10n-sync.mjs status --check) ==="
# Every locale must carry every English key AND be locked to the CURRENT
# English text (scripts/l10n/l10n.lock.json) — same for the store copy in
# docs/store-listing/. Run `/l10n` (or `node scripts/l10n/l10n-sync.mjs tasks
# … / apply …`) to translate what's missing/stale, or `… relock` to accept a
# typo-only English edit as-is.
if ! "$NODE_BIN" scripts/l10n/l10n-sync.mjs status --check; then
  echo "FAIL: translations are missing or stale for at least one locale (see above)." >&2
  fail=1
fi

echo ""
echo "=== L10n: existing-translation lint (l10n-sync.mjs lint) ==="
# The apply-time validators (placeholders, line breaks, glossary present and
# uninflected, Rún never declined, store limits, no Android/Google in App
# Store copy) over what is already on disk — hand edits bypass `apply`.
if ! "$NODE_BIN" scripts/l10n/l10n-sync.mjs lint; then
  echo "FAIL: an existing translation violates the l10n validators (see above)." >&2
  fail=1
fi

echo ""
echo "=== L10n: store metadata freshness (gen-store-metadata.py --check) ==="
# fastlane/metadata/** and the manual-paste fallbacks are generated from
# docs/store-listing/; they must be regenerated and committed after any edit.
# The public repository ships neither, so the step is skipped there.
if [ ! -d docs/store-listing ]; then
  echo "skipped: docs/store-listing is not part of this checkout (store copy is private)"
elif ! python3 scripts/l10n/gen-store-metadata.py --check; then
  echo "FAIL: generated store metadata is stale — run 'python3 scripts/l10n/gen-store-metadata.py' and commit the result." >&2
  fail=1
fi

# Only compile-verify the catalogs when the checks above actually passed and
# they exist — a --check failure already fails closed above, and compiling a
# known-stale/invalid catalog would just produce a confusing second error.
if [ "$fail" -eq 0 ]; then
  echo ""
  echo "=== L10n: Localizable.xcstrings / InfoPlist.xcstrings compile check ==="
  if ! command -v xcrun >/dev/null 2>&1; then
    echo "FAIL: xcrun not found — cannot verify the String Catalogs compile." >&2
    fail=1
  else
    TMP_OUT="$(mktemp -d)"
    trap 'rm -rf "$TMP_OUT"' EXIT
    if ! xcrun xcstringstool compile iosApp/iosApp/Localizable.xcstrings --output-directory "$TMP_OUT" >"$TMP_OUT/localizable.log" 2>&1; then
      echo "FAIL: iosApp/iosApp/Localizable.xcstrings failed to compile:" >&2
      cat "$TMP_OUT/localizable.log" >&2
      fail=1
    fi
    if ! xcrun xcstringstool compile iosApp/iosApp/InfoPlist.xcstrings --output-directory "$TMP_OUT" >"$TMP_OUT/infoplist.log" 2>&1; then
      echo "FAIL: iosApp/iosApp/InfoPlist.xcstrings failed to compile:" >&2
      cat "$TMP_OUT/infoplist.log" >&2
      fail=1
    fi
  fi
fi

if [ "$fail" -ne 0 ]; then
  echo "✗ L10n freshness gate failed." >&2
  exit 1
fi
echo "✓ L10n freshness gate passed: generated outputs match the strings_*.xml source tree and both String Catalogs compile."

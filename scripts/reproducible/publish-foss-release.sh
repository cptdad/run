#!/usr/bin/env bash
# Publish the F-Droid artifact for one version as a GitHub release asset on github.com/cptdad/run:
#
#   scripts/reproducible/publish-foss-release.sh v<versionName>
#
# 1. Finds the successful `reproducible-foss` workflow run for that tag (the LINUX build — see
#    sign-foss-apk.sh for why the APK F-Droid verifies cannot be built on this Mac) and downloads
#    its unsigned APK.
# 2. Signs it with the release key (apksigner 34.0.0) and runs the release-artifact gate.
# 3. Proves F-Droid's acceptance criterion locally: `apksigcopier compare` between the signed APK
#    and the unsigned build must pass — that is exactly what their server does before it publishes
#    a developer-signed APK.
# 4. Creates (or reuses) the GitHub release at the tag and uploads `run-<version>-foss.apk` plus its
#    SHA-256 — the `Binaries:` URL in docs/fdroid-recipe.yml.
# Nothing here changes git. Needs: gh (logged in), the release keystore (sign-foss-apk.sh), build-tools
# 34.0.0, apksigcopier (`python3 -m pip install --user apksigcopier`).
set -euo pipefail

TAG="${1:-}"
case "$TAG" in v[0-9]*.[0-9]*.[0-9]*) ;; *) echo "usage: $0 v<versionName>" >&2; exit 2 ;; esac
VER="${TAG#v}"
REPO="cptdad/run"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
SDK_BT="${ANDROID_HOME:-$HOME/Library/Android/sdk}/build-tools"
BT34="$SDK_BT/34.0.0"
[ -x "$BT34/apksigner" ] || { echo "build-tools 34.0.0 missing under $SDK_BT (needed for an F-Droid-compatible signature)" >&2; exit 1; }
APKSIGCOPIER="$(command -v apksigcopier || ls "$HOME"/Library/Python/*/bin/apksigcopier 2>/dev/null | tail -1 || true)"
[ -n "$APKSIGCOPIER" ] || { echo "apksigcopier not found — python3 -m pip install --user apksigcopier" >&2; exit 1; }
AAPT2="$(ls "$SDK_BT"/*/aapt2 2>/dev/null | sort -V | tail -1)"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/foss-release.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

echo "== reproducible-foss run for $TAG"
RUN_ID="$(gh run list -R "$REPO" -w reproducible-foss -L 30 \
  --json databaseId,headBranch,conclusion,status \
  --jq "[.[] | select(.headBranch == \"$TAG\" and .status == \"completed\" and .conclusion == \"success\")][0].databaseId")"
[ -n "$RUN_ID" ] && [ "$RUN_ID" != "null" ] || { echo "no successful reproducible-foss run for $TAG yet (gh run list -R $REPO -w reproducible-foss)" >&2; exit 1; }
echo "   run $RUN_ID"
gh run download -R "$REPO" "$RUN_ID" -D "$WORK/ci"
# No `| head -1` anywhere: under pipefail the reader closing early turns into SIGPIPE (141) and
# `set -e` aborts the script before the version check.
UNSIGNED="$(find "$WORK/ci" -name '*.apk' -print -quit)"
[ -f "$UNSIGNED" ] || { echo "run $RUN_ID has no APK artifact" >&2; exit 1; }

# The artifact must be the version the tag says it is.
BADGING="$("$AAPT2" dump badging "$UNSIGNED" 2>/dev/null | sed -n '1p')"
APK_VER="$(printf '%s' "$BADGING" | sed -nE "s/.*versionName='([^']+)'.*/\1/p")"
APK_CODE="$(printf '%s' "$BADGING" | sed -nE "s/.*versionCode='([0-9]+)'.*/\1/p")"
[ "$APK_VER" = "$VER" ] || { echo "artifact is $APK_VER, tag says $VER" >&2; exit 1; }
echo "   unsigned Linux build: Rún $APK_VER ($APK_CODE), $(stat -f %z "$UNSIGNED") bytes"

ASSET="$WORK/run-$VER-foss.apk"
echo "== sign (apksigner 34.0.0) + release gate"
"$HERE/sign-foss-apk.sh" "$UNSIGNED" "$ASSET" | grep -E '^✓|^✗|signed:|passed|FAILED' | sed "s|$WORK/||"

echo "== apksigcopier compare (F-Droid's acceptance check)"
if PATH="$BT34:$PATH" "$APKSIGCOPIER" compare "$ASSET" --unsigned "$UNSIGNED" 2>/dev/null; then
  echo "   OK: signed APK == unsigned Linux build + signature"
else
  echo "✗ apksigcopier compare FAILED — F-Droid would not publish this APK" >&2; exit 1
fi

SHA="$(shasum -a 256 "$ASSET" | cut -d' ' -f1)"
printf '%s  run-%s-foss.apk\n' "$SHA" "$VER" > "$ASSET.sha256"

NOTES="$WORK/notes.md"
cat > "$NOTES" <<EOF
Rún $VER ($APK_CODE) — the Android build for F-Droid and direct installation.

\`run-$VER-foss.apk\` is the \`foss\` flavour: no Google code (UnifiedPush only, no Play Billing, no Play
Review). It was built on GitHub Actions from this tag (workflow \`reproducible-foss\`, run $RUN_ID) and
signed by the maintainer. The signature can be copied onto your own rebuild of this tag
(\`apksigcopier compare\`), which is how F-Droid verifies it.

- SHA-256: \`$SHA\`
- Signing certificate SHA-256: \`29b4d5195bbc4ffd9be87c2547ee33371c7edff46f14ba8f93eadd7e2d2d2422\`
- Build instructions: BUILDING.md §4; verification: \`scripts/reproducible/compare-apks.py\`

Google Play and the App Store ship the \`google\` flavour of the same source; their What's New text
describes the user-facing changes.
EOF

echo "== GitHub release $TAG"
if gh release view -R "$REPO" "$TAG" >/dev/null 2>&1; then
  echo "   release exists — uploading assets (replacing same-named ones)"
else
  gh release create -R "$REPO" "$TAG" --verify-tag --title "Rún $VER ($APK_CODE)" --notes-file "$NOTES" >/dev/null
  echo "   created"
fi
gh release upload -R "$REPO" "$TAG" "$ASSET" "$ASSET.sha256" --clobber
echo "== published: https://github.com/$REPO/releases/download/$TAG/run-$VER-foss.apk"
echo "   sha256 $SHA"

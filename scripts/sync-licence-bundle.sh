#!/bin/sh
# ---------------------------------------------------------------------------
# Copy the four root licence/notice files byte-for-byte into BOTH platforms'
# app bundles, so the in-app "Licences and notices" screen (Android
# LicencesScreen in AboutInfoModal.kt, iOS LicencesView in ContactListView.swift)
# shows exactly the texts the repository is published under.
#
# The copies are COMMITTED (same single-source + fan-out shape as
# sync-runestone-assets.sh): edit the ROOT file, then re-run this script.
# androidApp/src/test/.../LicenceBundleTest.kt fails the JVM suite when an
# Android copy drifts from its root file or either platform's file list changes.
#
# Targets:
#   androidApp/src/main/assets/licences/   (read via AssetManager at display time)
#   iosApp/iosApp/Licences/                (folder reference in the Xcode project)
#
# Idempotent: only copies when the target differs (cmp), so a steady-state run
# produces no working-tree churn. Usage: no arguments. Exit 0 = in sync (or
# synced); non-zero = a source file is missing or a copy failed (set -eu).
# ---------------------------------------------------------------------------
set -eu

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ANDROID_DIR="$REPO_ROOT/androidApp/src/main/assets/licences"
IOS_DIR="$REPO_ROOT/iosApp/iosApp/Licences"

# Display order (LICENSE-EXCEPTION, LICENSE, THIRD_PARTY_NOTICES.md, OFL.txt)
# lives in the two screens; this list only names what is bundled.
FILES="LICENSE-EXCEPTION
LICENSE
THIRD_PARTY_NOTICES.md
assets/fonts/OFL.txt"

mkdir -p "$ANDROID_DIR" "$IOS_DIR"

for rel in $FILES; do
    src="$REPO_ROOT/$rel"
    name="$(basename "$rel")"
    if [ ! -f "$src" ]; then
        echo "sync-licence-bundle: missing source $rel" >&2
        exit 1
    fi
    for dir in "$ANDROID_DIR" "$IOS_DIR"; do
        dst="$dir/$name"
        if [ ! -f "$dst" ] || ! cmp -s "$src" "$dst"; then
            cp "$src" "$dst"
            echo "sync-licence-bundle: updated ${dst#"$REPO_ROOT"/}"
        fi
    done
done

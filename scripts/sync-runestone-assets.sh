#!/bin/sh
# ---------------------------------------------------------------------------
# Fan the canonical runestone PNGs (assets/runestone/) out to BOTH platforms'
# native asset stores. This is the single-source-of-truth pipeline: edit the
# file ONCE under assets/runestone/ and every build re-syncs the two platform
# copies, so the Android drawable and the iOS imageset can never drift.
#
# Why not one shared asset? The UIs are native (Compose reads res/drawable via
# R.drawable.*; SwiftUI reads Assets.xcassets from the app bundle) — a KMP
# module can't hand a raw PNG to both, so we keep one source + copy.
#
# Idempotent: only copies when the target differs (compared by SHA-256), so a
# steady-state build produces NO working-tree churn. Run automatically by the
# Android build (preBuild) and the pre-push hook; run by hand for local Xcode:
#     ./scripts/sync-runestone-assets.sh
# Usage: no arguments. Exit 0 = in sync (or synced); non-zero = a source PNG is
# missing or a copy failed (set -eu). Not a release gate.
# ---------------------------------------------------------------------------
set -eu

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$REPO_ROOT/assets/runestone"
ANDROID_DIR="$REPO_ROOT/androidApp/src/main/res/drawable"
IOS_XCASSETS="$REPO_ROOT/iosApp/iosApp/Assets.xcassets"

# The runestone matrix shared by both platforms (all 624x1254): three
# connection states (dim / bright / bright_and_lit) x three protection tiers
# (plain / _ring / _forcefield — Casual / Private / Maximum). The blue-forcefield
# tiers replaced the old Ægishjálmr-projection max-level variants.
#
# Each entry is <canonical source name>:<platform resource name>. The canonical
# PNGs keep the artist's numbered names; Android resource names cannot start
# with a digit, so the fan-out maps them onto the stable runestone_* names the
# code references (same name on iOS so the platforms can't drift).
#
# Also the three "Adding contacts" carousel panels (720x767) — real app
# screenshots of the pairing flow (Choice / Show-secret QR / connected chat),
# shipped identically to both platforms so the onboarding art can't drift.
PAIRS="01_dark_ring_dark_r:runestone_dim
02_dark_ring_dark_r_blue_base_ring:runestone_dim_ring
03_dark_ring_dark_r_full_blue_forcefield:runestone_dim_forcefield
04_red_runes_dark_r:runestone_bright
05_red_runes_dark_r_blue_base_ring:runestone_bright_ring
06_red_runes_dark_r_full_blue_forcefield:runestone_bright_forcefield
07_red_runes_white_r:runestone_bright_and_lit
08_red_runes_white_r_blue_base_ring:runestone_bright_and_lit_ring
09_red_runes_white_r_full_blue_forcefield:runestone_bright_and_lit_forcefield
pairing_choice:pairing_choice
pairing_secret:pairing_secret
pairing_chat:pairing_chat"

sha() { shasum -a 256 "$1" 2>/dev/null | cut -d' ' -f1; }

# Copy $1 -> $2 only if they differ (or $2 is missing). Echoes on change.
copy_if_changed() {
    src="$1"; dst="$2"
    if [ ! -f "$src" ]; then
        echo "  ERROR: canonical asset missing: $src" >&2
        return 1
    fi
    if [ ! -f "$dst" ] || [ "$(sha "$src")" != "$(sha "$dst")" ]; then
        mkdir -p "$(dirname "$dst")"
        cp "$src" "$dst"
        echo "  synced -> ${dst#"$REPO_ROOT"/}"
    fi
}

changed=0
for pair in $PAIRS; do
    # NB: copy_if_changed assigns src/dst globally (no locals in sh) — keep
    # these loop names distinct.
    from="${pair%%:*}"; to="${pair##*:}"
    before_a=$(sha "$ANDROID_DIR/$to.png" 2>/dev/null || echo "")
    before_i=$(sha "$IOS_XCASSETS/$to.imageset/$to.png" 2>/dev/null || echo "")
    copy_if_changed "$SRC/$from.png" "$ANDROID_DIR/$to.png"
    copy_if_changed "$SRC/$from.png" "$IOS_XCASSETS/$to.imageset/$to.png"
    if [ "$before_a" != "$(sha "$SRC/$from.png")" ]; then changed=1; fi
    if [ "$before_i" != "$(sha "$SRC/$from.png")" ]; then changed=1; fi
done

if [ "$changed" -eq 0 ]; then
    echo "runestone assets: already in sync (Android + iOS)"
else
    echo "runestone assets: sync complete"
fi

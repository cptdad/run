# Runestone assets — single source of truth

These PNGs are the ONE canonical copy of the main-screen runestone background,
all **624 × 1254**, a 3 × 3 matrix: three connection states — `dark_ring_dark_r`
(dim) → `red_runes_dark_r` (Tor up) → `red_runes_white_r` (relay up) — each in
three protection tiers matching the threat-level slider: plain (Casual),
`blue_base_ring` (Private), `full_blue_forcefield` (Maximum). The forcefield
tiers replaced the old Ægishjálmr-projection max-level variants. The dim tier
images double as the protection-level chooser's card art. **Edit them here,
keeping these numbered names** — the sync script maps each one onto the stable
`runestone_*` resource name the code references (Android resource names cannot
start with a digit; see the PAIRS table in the script). The dim/bright/lit
tiers map to `runestone_dim` / `runestone_bright` / `runestone_bright_and_lit`
(+ `_ring` / `_forcefield` suffixes).

They can't be shared as one native asset (Compose reads `res/drawable` via
`R.drawable.*`; SwiftUI reads `Assets.xcassets` from the app bundle), so
`scripts/sync-runestone-assets.sh` fans this canonical copy out to both:

- `androidApp/src/main/res/drawable/<name>.png` — auto-synced by the Android build
  (`syncRunestoneAssets` runs before `preBuild`).
- `iosApp/iosApp/Assets.xcassets/<name>.imageset/<name>.png` — synced by the
  pre-push hook (before the iOS build, which `xcodebuild` runs).

The sync is **idempotent** (a no-op when already in sync). After changing an
asset for a **local Xcode** build, run it by hand:

    ./scripts/sync-runestone-assets.sh

The two platform copies are kept committed so fresh checkouts and the IDE work
without a sync step; the build keeps them matching this canonical source. (If you
prefer a leaner git tree, the platform copies can be `.gitignore`d — but then a
local Xcode build needs a sync run first.)

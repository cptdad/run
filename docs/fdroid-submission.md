# Submitting Rún to F-Droid

Status 2026-11-08: the merge request is OPEN with a GREEN pipeline (round 3, see below) —
<https://gitlab.com/fdroid/fdroiddata/-/merge_requests/56360> ("New app: Rún (com.vg.run)", from
the fork `cptdad12/fdroiddata`, branch `com.vg.run`), with the recipe at v1.6.62 (1055), commit
`64dee175a8213f5619ad2def85eb7adf7b437f0c`. It was opened through the GitLab API with `glab`
(fork → file commit with `start_branch` → merge request), not through the web UI. This page is
the runbook for what was done and for keeping the app updated afterwards.

Pipeline: the MR pipeline runs on the fork, and GitLab refused it with 0 jobs ("The pipeline failed
due to the user not being verified" — a fresh gitlab.com account without a card or phone number).
fdroiddata's own template says not to verify in that case but to leave a note so a maintainer
triggers the CI; that note is posted on the MR. The owner then verified the account and the pipeline
ran (round 1): lint, rewritemeta, schema, source scan and the tool checks green; `fdroid build`
stopped in the scanner with 6 errors and `checkupdates` failed. Fixes: (a) the Guardian Project
raw-GitHub Maven mirror (gpmaven) removed from `settings.gradle.kts` — tor-android is on Maven
Central and the verification metadata already pins Central's checksums; F-Droid accepts only known
repositories (needs a new tag); (b) `scandelete` corrected to `iosApp/Frameworks/tor.xcframework`
and extended with `e2e-tests` (its package.json is exported without the lock file); (c)
`UpdateCheckData: version.properties|…` because the version is not literal in build.gradle.kts, so
`checkupdates` found nothing. The ~45 `fuzz/src/test/resources/**` inputs are WARNINGS (binary test
vectors), explained on the MR rather than deleted.

Round 2 (recipe at v1.6.63, after the maintainer linsui had rebased the branch onto master): the
scanner passed; the Gradle build failed with `CXX1100: Both android.ndkPath and ndk.dir in
local.properties are set` — fdroidserver writes `ndk.dir=` into local.properties and our build
set `android.ndkPath` from `run.ndkPath`. `checkupdates --auto` added `AutoName: Rún` and the job
fails whenever it changes the recipe. Fixes: `AutoName: Rún` in the recipe; prebuild
`sed -i '/^ndk\.dir=/d' ../local.properties` so only our path remains (needed for v1.6.63);
`shared/build.gradle.kts` now honours a plain `ndk.dir=` and leaves `ndkPath` unset in that case,
so the recipe can drop both NDK prebuild lines from the first tag that carries the change.

Round 3 (2026-11-08 ~21:30): ALL NINE JOBS GREEN. F-Droid's build server built 1.6.63 (1056) from
`cc1f26ee`, downloaded `run-1.6.63-foss.apk` and logged "compared built binary to supplied reference
binary successfully" with our signer `29b4d519…2422` as the allowed key — the reproducible build is
proven on their infrastructure. Awaiting maintainer review/merge.

## What F-Droid will do with our recipe

F-Droid builds the `foss` flavour from the tag on its own Debian build server, then compares
the result byte for byte with the APK attached to the GitHub release of the same version
(`Binaries:` in the recipe). When they match, F-Droid publishes **our** signed APK
(`AllowedAPKSigningKeys` is exclusive; the F-Droid key is never used), so an F-Droid install
updates like a direct install and never asks anyone to reinstall.

What makes that work, all already in the repository:

- `foss` flavour: zero Google code (`BUILDING.md` §4).
- Tag `v<versionName>` on every pushed version (`scripts/export/publish-public.sh`).
- The unsigned Linux build of every tag as a CI artifact (`.github/workflows/reproducible-foss.yml`).
- The signed asset `run-<version>-foss.apk` on the GitHub release
  (`scripts/reproducible/publish-foss-release.sh`), signed with apksigner 34.0.0 — newer apksigners
  write APKs that F-Droid's signature copy (`apksigcopier`) cannot reproduce.
- Deterministic native build (`shared/src/androidMain/cpp/CMakeLists.txt`): the one component that
  cannot be reproduced on macOS, because the NDK ships a different clang per host, which is why the
  asset is always the Linux build.

Verified locally for v1.6.60, v1.6.61 and v1.6.62 (each published by `publish-foss-release.sh`): `apksigcopier compare run-1.6.60-foss.apk --unsigned <Linux build>`
passes, and the Linux and macOS builds differ only in `librunargon2.so`.

## Opening the merge request (maintainer, once)

1. Sign in to gitlab.com and fork `fdroid/fdroiddata` (the fork lives under your account).
2. Clone the fork and add the recipe:

   ```
   git clone git@gitlab.com:<you>/fdroiddata.git && cd fdroiddata
   git checkout -b com.vg.run
   cp ~/code/run/docs/fdroid-recipe.yml metadata/com.vg.run.yml
   ```

   Remove the comment header (fdroiddata keeps metadata comment-free; the body is already in
   `fdroid rewritemeta` order). Two checklist rules that cost a push the first time: `commit:` must
   be the FULL HASH of the tagged public commit (`git ls-remote git@github.com:cptdad/run.git
   'refs/tags/v<version>^{}'`), never the tag; and the recipe carries no Summary/Description —
   fdroiddata reads title, short/full description and changelogs from
   `fastlane/metadata/android/<locale>/` (en-US required) AT THE BUILD COMMIT, so the tag the recipe
   points at must already contain that tree (public since v1.6.62, export rule in
   `scripts/export/public-paths.txt`).
3. Optional local checks (`pipx install fdroidserver`, run INSIDE the fdroiddata checkout so the
   `config/` category and anti-feature definitions are found; outside it every category and
   anti-feature is reported invalid): `fdroid lint com.vg.run` and `fdroid rewritemeta com.vg.run`.
   Both were clean for this recipe on 2026-11-08. fdroiddata's own CI runs the real build on the
   merge request, so these are a convenience, not a requirement.
4. Commit and push: `git add metadata/com.vg.run.yml && git commit -m "New app: Rún (com.vg.run)"
   && git push -u origin com.vg.run`.
5. Open the merge request against `fdroid/fdroiddata` `master` with the text below. Tick
   "Allow commits from members who can merge" so a reviewer can fix nits directly.
6. Watch the pipeline on the MR: the `fdroid build` job must go green and the
   reproducibility check (`fdroid verify`-style comparison with our release asset) must report a
   match. A red build is normally a recipe detail (NDK name, cmake version, a path); fix it in the
   fork and push again.

### Merge-request title

```
New app: Rún (com.vg.run)
```

### Merge-request description

```
Rún — anonymous, end-to-end encrypted messenger over Tor. No accounts, no phone number;
contacts are exchanged in person (QR) or by vouched introduction; messages live in RAM only.

Source: https://github.com/cptdad/run (GPL-3.0-or-later, with a GPLv3 §7 additional
permission for the platform libraries of the store builds — LICENSE-EXCEPTION). The `foss`
flavour this recipe builds contains no Google code (UnifiedPush only).

Reproducible build / developer signature:
- `Binaries:` points at the GitHub release asset `run-<version>-foss.apk`, which is the
  unsigned build from our own Linux CI (`.github/workflows/reproducible-foss.yml`) signed with
  the key in `AllowedAPKSigningKeys` using apksigner 34.0.0.
- Verified locally with `apksigcopier compare` for every published tag.
- The native library (Argon2, `shared/src/androidMain/cpp`) is built with the NDK pinned in the
  recipe; the macOS NDK clang produces different bytes than the Linux one, so the asset is
  always Linux-built.

Build notes: `relay.properties.example` carries the production relay's onion addresses and is
copied into place in `prebuild` (the build reads `relay.properties`, which is gitignored). The
NDK path is passed through `run.ndkPath` in `local.properties`. CMake ≥ 3.22 and Ninja come
from apt.

Two things I want to flag rather than have you discover:
1. Tor ships as a prebuilt binary via Maven (`info.guardianproject:tor-android`, the artefact
   Guardian Project publishes for Orbot). If that is not acceptable for the main repo, tell me what you would accept
   (building Tor from source in the recipe, or a specific F-Droid-built artefact) and I will
   adapt the build.
2. Anti-features: NonFreeNet (the relay server's source is not published yet) and NonFreeAssets
   (the artwork is CC BY-NC-ND, see LICENSE-ART).

Localized store metadata lives in the repository under `fastlane/metadata/android/<locale>/`
(12 locales including `en-US`: title, short and full description, changelogs). No screenshots yet.
```

## Keeping F-Droid updated (every release)

Nothing manual beyond the normal push procedure:

1. `/push` tags `v<version>` on the public repo, the public CI builds the unsigned `foss` APK,
   and `scripts/reproducible/publish-foss-release.sh v<version>` publishes the signed asset.
2. F-Droid's update bot (`AutoUpdateMode: Version`, `UpdateCheckMode: Tags`) picks the new tag,
   adds a `Builds:` entry copied from the last one, builds, compares against the asset and
   publishes our APK. If the comparison fails, the version is skipped (not published with the
   F-Droid key), and the fdroiddata issue tracker shows why.
3. When a build-relevant detail changes (NDK version, a new native library, a new flavour
   name, the relay file), update the `Builds:` fields in `metadata/com.vg.run.yml` in a small
   fdroiddata merge request before pushing the version that needs them.

## Things that would break reproducibility

- Building the asset on macOS (NDK host compiler differs). Always the Linux CI artifact.
- Signing with apksigner ≥ 35.0.0. `sign-foss-apk.sh` refuses anything but 34.0.0.
- A `RELAY_ONION_URL` environment variable that differs from `relay.properties.example` on the
  machine that builds the Mac artefacts; `scripts/verify-release-artifact.sh` fails on it.
- Changing the NDK or CMake flags without updating the recipe's `ndk:` / `sudo:` lines.

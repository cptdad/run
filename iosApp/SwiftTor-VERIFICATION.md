# Tor.framework supply-chain verification (iOS)

This file records the provenance of the iOS Tor runtime so future reviews can
confirm it hasn't been silently swapped or regressed.

> **History:** the app previously consumed Tor via the `SwiftTor` Swift Package
> (a single-developer fork that shipped a prebuilt `Tor.xcframework` containing
> **Tor 0.4.4.6**, EOL October 2021 — a ship-blocker).
> That dependency was removed on 2026-05-31 and replaced with a Tor runtime
> **built from source** off the iCepa project (the upstream that the SwiftTor
> binary was itself derived from), at a current Tor release.

## What ships now

The iOS app uses Tor as two cooperating pieces, both from iCepa source:

1. **C library, as a DYNAMIC framework** — `iosApp/Frameworks/tor.xcframework`
   (`Tor.framework`, a dylib, EMBEDDED + code-signed). Built from iCepa's
   `build-xcframework.sh -c` (static `tor` = Tor + OpenSSL + libevent + liblzma),
   then re-linked into a dynamic framework that exports ONLY the `tor_api` +
   logging entry points the wrapper needs (see export list below).
   **Why dynamic, not static:** SQLCipher (`swift-sqlcipher`) bundles
   **libtomcrypt**, which defines the same flat C symbols as Tor —
   `base16/32/64_{decode,encode}`, `ed25519_sign`, `poly1305_init`,
   `sha512_224_init`, `sha512_256_init` (10 total). Linked as two static libs,
   the linker silently bound Tor's calls to libtomcrypt's incompatible
   implementations → SIGSEGV at startup in `base16_decode` (via
   `parse_dir_authority_line`). A dynamic framework gives Tor its own two-level
   namespace, so its internal calls resolve to its own symbols. Verified: the
   dylib does NOT export `base16_decode` etc. (`nm -gU` → absent).
2. **Objective-C wrapper** — `iosApp/Tor/*.{h,m}` (iCepa `Tor/Classes/Core` +
   `CTor`), compiled into the app target, exposed to Swift via
   `iosApp/Tor/Run-Bridging-Header.h`. Provides `TorThread` / `TorController` /
   `TorConfiguration` (the `TOR*` classes carry `NS_SWIFT_NAME` to those Swift
   names — `TorManager.swift` is unchanged apart from dropping `import Tor`).

**Two vendored-source fixes applied to `iosApp/Tor/`:**
- `TORThread.m`: upstream declares `char *argv[argc]` then writes `argv[argc]`
  (one past the end — a stack overflow); changed to `char *argv[argc + 1]`.
- Removed the unused onion-auth files (`TORX25519KeyPair`, `TOROnionAuth`,
  `TORAuthKey`) — the app never uses them and `TORX25519KeyPair` itself calls
  the colliding `base32` symbols. `TORCircuit`/`TORNode` are kept (used by
  `TORController`) and call none of the colliding symbols.

`Arti` and `Onionmasq` subspecs are intentionally NOT included (Rust, unused).

### Dynamic-framework export list (symbols the app/wrapper bind to)

```
tor_main_configuration_new   tor_main_configuration_set_command_line
tor_main_configuration_free  tor_run_main
tor_api_get_provider_version tor_main_configuration_setup_control_socket
add_callback_log  set_log_severity_config
event_enable_debug_logging   event_set_log_callback
```

### TorManager torrc note

`UseDefaultFallbackDirs 0` was set while diagnosing the collision crash above
(and later grew an 18-entry curated `FallbackDir` list on top of it). **Both were
removed on 2026-09-15** — the crash was the static-link collision, not Tor's
fallback parser, and it has been fixed since the dynamic framework landed. The
torrc is now stock on this point, matching Android. Verified against this
framework's binary: the compiled-in fallback list is present and intact — 200
entries, set-identical to upstream `tor-0.4.9.11
src/app/config/fallback_dirs.inc`. Re-check this if Tor is ever linked statically
again.

## Source pin

- **Repository:** `https://github.com/iCepa/Tor.framework.git`
- **Tag:** `v409.14.1`  (commit `2b1192c81fc359bcf1c21a16526b76a2a2c1f419`)
- **Maintainer posture:** multi-maintainer project used in production by Onion
  Browser and Orbot — substantially stronger than the prior single-dev fork.

### Component versions (pinned inside `build-xcframework.sh`, from upstream)

| Component | Version | Upstream cloned at build |
|---|---|---|
| **Tor** | **0.4.9.14** (`tor-0.4.9.14`, iCepa's own pin — `TOR_OVERRIDE_ICEPA_PIN` is empty/inactive) | `gitlab.torproject.org/tpo/core/tor.git` (tag object `4d6a948ca00eac5722a866ddde65e27830921856` → commit `3c575400909efe6599d88e61e7daf0012655ca44`) |
| OpenSSL | 3.6.5 (`openssl-3.6.5`) | `github.com/openssl/openssl.git` |
| libevent | 2.1.13-stable | `github.com/libevent/libevent.git` |
| xz/liblzma | 5.8.4 (`v5.8.4`) | `github.com/tukaani-project/xz.git` |

Confirmed embedded (2026-10-12): `strings .../Tor.framework/tor | grep 'tor 0.4.9'` →
`(tor 0.4.9.14)` in both slices; runtime line on device still to be read after the
next fleet deploy (expected `Tor 0.4.9.14 ... Libevent 2.1.13-stable, OpenSSL 3.6.5, ... Liblzma 5.8.4`).

Note: iCepa's `build-xcframework.sh` at v409.11.x and later emits ZIPPED xcframeworks
(`tor.xcframework.zip` + `tor-nolzma.xcframework.zip`); our wrapper script
unzips the lzma variant before the relink step. From v409.13.1 the static
framework is a "deep" bundle (`Versions/A/...` + symlinks), its headers are
run through iCepa's `fix_includes.pl` (in-tree `#include`s rewritten to
relative paths) and a `tor_umbrella.h` is added; the relink step copies that
Headers tree as-is, so the committed headers carry those rewrites and the
umbrella header (the headers-tree digest covers them).

### SHA-256 of each built slice (`<slice>/tor.framework/tor`)

Recorded by the build (2026-10-12, Tor 0.4.9.14) in `iosApp/Frameworks/tor.xcframework.sha256`:

```
98a1bde7643bb0bd10a1409c34946598621aee0e2486a45ea31834e46283273d  ios-arm64/Tor.framework/Tor
f070e39f387acdbb846558306d428b339173ac0dd255938a2e3550931818c8db  ios-arm64_x86_64-simulator/Tor.framework/Tor
```

## How to rebuild (re-run on every dependency bump)

The entire static-build → dynamic-relink → xcframework-assembly pipeline is
scripted and pinned. From the repo root:

```sh
iosApp/scripts/build-tor-xcframework.sh
```

It clones iCepa at the pinned tag, runs `build-xcframework.sh -c` (with the
Apple-`libtool` / GNU-`libtoolize` PATH handling), re-links each slice into the
dynamic framework exporting only the wrapper's entry points, assembles
`iosApp/Frameworks/tor.xcframework`, and asserts the codec symbols stay
private. Bump `ICEPA_TAG`/`TOR_VERSION`/`EXPORTS` at the top of the script (and
this file) to update Tor. The Obj-C wrapper in `iosApp/Tor/` is committed
separately (with the `TORThread.m` off-by-one fix + onion-auth pruning) and is
NOT regenerated by the script — re-apply those if you re-vendor the wrapper.

The built `tor.xcframework` is committed to the repo (Xcode Cloud uses it
directly; building Tor from source on CI is impractical). Re-run the script to
regenerate/verify it after any pin bump.

## Verification log

| Date | Verifier | iCepa tag | Tor version | Notes |
|---|---|---|---|---|
| 2026-10-12 | maintainer | v409.14.1 (commit `2b1192c8`) | 0.4.9.14 | Security release 2026-10-07 (TROVE-2026-062/064/067; client fixes 41412/41420/41437). iCepa re-tagged same day (OpenSSL 3.6.4→3.6.5); tag commit verified against the GitHub API; override OFF. |
| 2026-09-29 | maintainer | v409.13.1 (commit `51cc492a`) | 0.4.9.13 | Emergency security release 2026-09-23. iCepa re-tagged, so the Tor override is inactive again. OpenSSL 3.6.4 / libevent 2.1.13 / xz 5.8.4 per iCepa's pins. gitlab.torproject.org was failing clones server-side (`remote: unable to create thread`) during the build, so the `tor-0.4.9.13` tag was fetched from gitlab into a local bare repo (tag object id matched `git ls-remote`) and iCepa's clone was pointed at it via a process-scoped `url.insteadOf`; the recipe is otherwise unchanged. Binaries + header trees re-recorded (header digests also recomputed by hand, identical); verify-tor-xcframework.sh ✓; Android bumped to tor-android 0.4.9.13 (compileSdk stays 37.1). |
| 2026-09-21 | maintainer | v409.11.1 (pinned commit) + Tor tag override | 0.4.9.12 | Security release 2026-09-08; iCepa had not re-tagged. Built via the guarded override in build-tor-xcframework.sh; binaries + header trees re-recorded; verify-tor-xcframework.sh ✓; Android bumped to tor-android 0.4.9.12 (compileSdk 37.1) the same day. |
| 2026-05-05 | maintainer | SwiftTor `c2106380` | 0.4.4.6 | EOL — ship-blocker (old dep) |
| 2026-05-31 | migration | iCepa `v409.8.1` | **0.4.9.8** | built from source; SwiftTor removed |
| 2026-07-01 | deps pass | iCepa `v409.11.1` | **0.4.9.11** | built from source; zipped-output unzip fix in wrapper |

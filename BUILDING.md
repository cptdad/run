# Building Rún

From a fresh clone to an Android APK, an iOS app on your own devices, and the
test suites, without access to the maintainers' relay, keys, or store accounts.

## 1. What you get

You can build a debug APK, an unsigned or self-signed release APK / AAB, an iOS
app for the simulator or for your own devices, and run the JVM tests, lint, and
the single-device end-to-end specs against a local mock relay.

You cannot get:

- **Store-signed binaries.** Your build is signed with your key (or unsigned)
  and is a different app identity from the store releases.
- **Push notifications on iOS.** The relay's APNs key is bound to the official
  bundle id.
- **Messaging without a relay.** With no relay address the app runs but cannot
  send or receive. Section 3 shows how to use the production relay.

## 2. Prerequisites

- JDK 17 (Gradle never downloads toolchains; install one). Gradle 9.7.1 via `./gradlew`;
  AGP 9.4.0, Kotlin 2.4.20 (pinned in `gradle/libs.versions.toml`).
- Android SDK platform 37.1 (`compileSdk`; minSdk 30). Set `sdk.dir` in `local.properties`
  or `ANDROID_HOME`.
- Android NDK 30.0.16248370, CMake 4.4.5, Ninja (native Argon2 build, below).
- iOS only: current Xcode (deployment target iOS 16.0).
- E2E: Node.js 22. Pre-commit hook: gitleaks.

### NDK, CMake, Ninja (space-free paths)

`librunargon2.so` is compiled with CMake from the sources in `iosApp/Argon2`.
NDK and CMake mishandle paths containing a space, so install them in a
space-free location. On macOS with Homebrew:

```
brew install cmake ninja
brew install --cask android-ndk
```

Then, in `local.properties` (gitignored):

```
sdk.dir=/path/to/Android/sdk
cmake.dir=/opt/homebrew
```

The NDK is found via the `RUN_NDK_PATH` environment variable, then
`run.ndkPath=` in `local.properties`, then `/opt/homebrew/share/android-ndk`.
The directory must contain `source.properties` for NDK 30.0.16248370. Without an NDK the native tasks fail with a clear message (iOS builds need
none). On Linux, use `sdkmanager "ndk;30.0.16248370"` and set `RUN_NDK_PATH`
and `cmake.dir`.

## 3. Relay configuration

The relay is a Tor onion service; its address is compiled in at build time
from one of these sources, in order of precedence:

1. The `RELAY_ONION_URL` environment variable, if non-empty.
2. `relayOnionUrl=` in a repo-root `relay.properties` (gitignored). The
   committed `relay.properties.example` carries the production relay's
   address, the one the store apps use; copying it to `relay.properties` is
   enough to message with them.
3. Empty: valid. The app starts and you can explore it, but it cannot message.

```
export RELAY_ONION_URL=http://<your-relay-v3-address>.onion
```

- The value may be a comma-separated list of up to 3 v3 `.onion` addresses of
  the same relay. A non-empty environment variable replaces the file's list.
- **Emulator and simulator builds** (debug) use host loopback instead
  (`10.0.2.2` on the Android emulator, `localhost` on the iOS simulator). This
  is how the end-to-end suites reach the local mock relay (section 7).
- **Dev relay.** `RELAY_DEV_ONION_URL` / `relayDevOnionUrl` names a second
  relay used only by debug builds on physical devices. The build fails if any
  dev address equals a production address, and release builds compile the dev
  value as empty, so a release artifact is pinned to the production address.
- A release build with a non-`.onion` relay disables messaging; it never falls
  back to clearnet.
- Instead of the embedded Tor you can point Android at your own SOCKS5 proxy;
  see `docs/external-socks-proxy.md`.

## 4. Android

### Debug APK

```
./gradlew :androidApp:assembleDebug
```

Output: `androidApp/build/outputs/apk/debug/androidApp-debug.apk`.

Run this task **alone**, never combined with a release task (see "Refused
invocations"). Debug builds use a cheap Argon2 cost and can log; do not use one
for real data.

### Release APK / AAB

```
./gradlew :androidApp:assembleRelease     # APK
./gradlew :androidApp:bundleRelease       # AAB
```

Outputs: `androidApp/build/outputs/apk/release/`, `.../bundle/release/`.

**Signing.** `keystore.properties` is looked up in `$RUN_SIGNING_DIR`, then
`~/.run-signing`, then the repo root (keep it out of the repo tree). Keys:
`storeFile` (relative paths resolve against that file's directory),
`storePassword`, `keyAlias`, `keyPassword`. With no keystore the release build
still succeeds but is **unsigned**; sign it yourself (e.g. `apksigner`) before
installing.

**Firebase.** `google-services.json` is gitignored; place yours at
`androidApp/src/debug/` and `androidApp/src/release/`.

- Debug builds without it compile with a warning and FCM is unconfigured.
- **Release builds fail without a valid file.** Use your own Firebase project's
  file. Push to your build also needs a relay holding matching FCM credentials;
  the official relay's belong to the official app.

**Version.** `versionName` / `versionCode` come from `version.properties`
(the pre-push hook bumps the patch; edit major and minor by hand).

### Refused invocations

The build deliberately fails these, with an explanatory message:

- Bare `build` or `assemble` (any project path): they build both variants, so
  the debug APK would get an empty dev-relay constant and silently use the
  production relay.
- A debug artifact task together with a release-intent task (name containing
  `release`, `CONFIGURATION=Release`, or `STRIP_DEV_RELAY=1`), for the same
  reason.

Run variants separately. For tests plus lint use `./gradlew test lint`.

`STRIP_DEV_RELAY=1` forces the dev-relay scrub. Gradle camel-case task
abbreviations (`aR`) are not detected by the scrub; use full task names.

## 5. iOS

The iOS app links `shared.xcframework`, which an Xcode script phase builds
with `./gradlew :shared:embedAndSignAppleFrameworkForXcode`. The JDK from
section 2 and the relay variables from section 3 must be available to Xcode.

The committed `iosApp/iosApp.xcodeproj` is authoritative. `iosApp/project.yml`
(xcodegen) has drifted from it; do not run `xcodegen generate` casually. If
you do, diff the result against the committed project first, since hand-made
changes (target membership, the `tor.xcframework` wiring) live only there.

### Simulator build (no signing)

```
xcodebuild build -project iosApp/iosApp.xcodeproj -scheme Run \
  -destination 'generic/platform=iOS Simulator' -configuration Debug \
  CODE_SIGNING_ALLOWED=NO
```

### Device build

1. Open `iosApp/iosApp.xcodeproj` and select the `Run` target.
2. Under Signing & Capabilities, set **your own Team ID** (`project.yml` holds
   the placeholder `YOUR_TEAM_ID`; replace it there too if you regenerate).
3. Change the **bundle identifier** from `com.vg.run` to one in your own
   namespace; you cannot register the official one.
4. Remove or re-provision team-bound entitlements (push) as Xcode requires.
5. Build and run.

A self-built iOS app gets no push notifications: the relay's APNs key is bound
to the official bundle id.

### Vendored native code

- `iosApp/Frameworks/tor.xcframework` is a committed binary build of Tor;
  `iosApp/scripts/build-tor-xcframework.sh` rebuilds it. Hashes are recorded
  beside it (`tor.xcframework.sha256`, `tor.xcframework.headers.sha256`).
- `iosApp/Argon2` holds the vendored reference Argon2 C sources, used by iOS
  and by the Android native build; hashes in `iosApp/Argon2/argon2-src.sha256`.

Verify both:

```
scripts/verify-tor-xcframework.sh
scripts/verify-argon2-src.sh
```

## 6. Gates and hooks

Enable the hooks once per clone with `git config core.hooksPath .githooks`.
**pre-commit** scans staged changes with `gitleaks` (blocks if not installed).
**pre-push** runs the gates below, then bumps the patch in `version.properties`;
it also has maintainer-only steps you can remove in a fork. To run the gates by
hand:

`verify-gradle-wrapper.sh` (wrapper hashes), `check-network-api-usage.sh` (network APIs only
in approved transport files), `check-logging-gated.sh` (log calls behind a debug gate),
`verify-release-clean.sh` (debug hooks stay gated), `security-deps-report.sh` (security
dependencies not past their minimum version), `verify-tor-xcframework.sh`,
`verify-argon2-src.sh`, `verify-l10n-fresh.sh` (generated localization files current),
all under `scripts/`, plus `iosApp/ci_scripts/test_build_prerequisites.sh`.
The localisation gate skips the store-copy checks when the store texts are not present, which is the case in the public repository.

`scripts/verify-release-artifact.sh <file.apk|file.aab>` inspects a **built**
release artifact: signature validity, no injected unsigned entries, a hardened
manifest (not debuggable, backups off, network security config present, only
the main activity exported), and that the dev relay address does not appear in
it. Needs the Android SDK build-tools (`ANDROID_HOME`) and, for `.aab`,
`bundletool`.

## 7. Tests

```
./gradlew test                                        # JVM unit tests
./gradlew test --tests "com.vg.run.<TestClass>"       # one class
./gradlew lint
./gradlew connectedAndroidTest                        # needs a device or emulator
```

`connectedAndroidTest` uninstalls the app, erasing its data.
End-to-end specs (`e2e-tests/`, WebdriverIO + Appium) must be run through
`npm run`, which selects Node 22; never raw `wdio`:

```
cd e2e-tests
npm install
npm run mock:relay               # local mock relay (mock-relay/server.js)
npm run test:emulator:android    # builds, installs, runs on an already-booted emulator
npm run test:emulator:ios        # same on an iOS simulator (boots one if needed)
npm run test:emulator:all        # both, sequentially
```

The `test:emulator:*` suites run only on an emulator or simulator against the
mock relay; run them one at a time. The `test:device:*` suites need physical
devices and a live relay and are out of scope here. See `e2e-tests/README.md`.

## 8. Troubleshooting

- **`build` / `assemble` refused.** Intended (section 4). Run `./gradlew test
  lint`, `:androidApp:assembleRelease`, and `:androidApp:assembleDebug` separately.
- **"Android NDK 30.0.16248370 not found".** Install the NDK in a space-free
  path and set `RUN_NDK_PATH` or `run.ndkPath` (section 2).
- **First unlock is slow in release, fast in debug.** Release derives the vault
  key with Argon2id at 64 MiB x 3 passes; debug uses 1 MiB x 1. A vault created
  by a debug build keeps its weak cost, so do not reuse one for real data.
- **App starts but cannot message.** No relay is compiled in (empty
  `RELAY_ONION_URL`, no `relay.properties`), or a release build's relay is not
  a `.onion` address.
- **Simulator or emulator cannot reach a `.onion` relay.** By design: they use
  host loopback. Run `npm run mock:relay`, or test the real relay on a device.
- **Xcode build cannot find the framework.** Launch Xcode from a shell that has
  `JAVA_HOME` and `RELAY_ONION_URL` set, or build once from the command line.

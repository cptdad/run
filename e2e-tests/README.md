# Rún end-to-end tests (emulator / simulator)

End-to-end UI tests for the Rún messenger, driven with WebdriverIO 9, Appium 3 and Mocha.
They run the real debug build of the app on an **Android emulator** or an **iOS simulator**
and exercise it through its accessibility tree. Everything here is hermetic: no Tor, no
`.onion` relay and no network. The relay is a local mock (`mock-relay/`) on the host.

The maintainer additionally runs multi-device suites on physical phones (iPhone and
Android, paired against a live relay over Tor). Those suites need hardware and
infrastructure that cannot be shared, so they are not part of this repository.

## What is covered

One spec per file in `tests/`. Each spec starts from a wiped app and provisions its own vault.

| Spec | Covers |
|---|---|
| `pin.spec.ts` | PIN setup, entry and rejection of wrong PINs |
| `vault.spec.ts` | Single-vault lifecycle: create, lock, unlock |
| `security.spec.ts` | Security behaviour such as the wrong-PIN wipe |
| `reauth.spec.ts` | Periodic random re-authentication at the MAXIMUM protection level |
| `contacts.spec.ts` | Contact list and the add-contact flow |
| `messaging.spec.ts` | Conversation screen and sending |
| `groups.spec.ts` | Group creation and management on one device |
| `contact-list-layout.spec.ts` | First row clear of the bars, relay banner on screen (iOS simulator) |
| `connect-log.spec.ts` | Triple-tap connect-log panel on the connecting caption |
| `log-viewer.spec.ts` | Hidden log viewer |
| `about.spec.ts` | About and Support modals |
| `language.spec.ts` | In-app language picker |
| `l10n-sweep.spec.ts` | Screenshot sweep across locales for visual QA (opt-in, `WDIO_L10N_SWEEP=1`) |
| `push-prompt.spec.ts` | Notification prompt shown at the first relay answer |
| `settings-relay-gate.spec.ts` | The five relay-dependent settings rows disable and re-enable with relay reachability |
| `relay-loss.spec.ts` | Relay drops inboxes, contacts flip to "Re-pair required" |
| `mock-relay.spec.ts` | App connects to the mock and flips the relay-reachable gate |
| `update-nudge.spec.ts` | Update-available modal driven by the relay's version headers |
| `update-nudge-layout.spec.ts` | Geometry of the update dialog per variant and locale |
| `move-scan.spec.ts` | "Move to new device" camera-scan path |
| `tor-recycle.spec.ts` | Dead-Tor process recycle (iOS) |
| `ugc.spec.ts` | iOS user-safety gate: terms acceptance, block and report |

## Prerequisites

- **Node 22.** WDIO 9 breaks on newer Node (session creation fails with
  `UND_ERR_INVALID_ARG`). Every npm script goes through `scripts/with-node22.sh`, which
  puts Homebrew's `node@22` first on `PATH` (`brew install node@22`) and keeps the Mac
  awake for the run. Always use `npm run ...`, never raw `wdio`.
- **Appium 3** with the UiAutomator2 and XCUITest drivers. Both are in `devDependencies`,
  so `npm install` is enough. `scripts/ensure-appium-home.sh` repairs Appium's driver
  cache if the checkout was moved or renamed.
- **Android:** an emulator that is **already booted** (the script never boots one for the
  single-device suite), the Android SDK (`ANDROID_HOME`, default `~/Library/Android/sdk`)
  and a JDK for Gradle. The emulator needs a lock screen set. Fresh AVDs have none, and a
  device without one forces the app to its MAXIMUM tier, whose passphrase these PIN-based
  specs cannot enter. The script sets PIN `1111` when none exists.
- **iOS:** macOS with Xcode and an iPhone simulator. The script prefers an
  already-booted simulator, otherwise picks an iOS 26.x iPhone and boots it.
- **The debug build.** Release builds do not expose the test hooks or accessibility ids.
  The run scripts build and install a fresh debug build themselves.

No lockfile (`package-lock.json`) is shipped, so the first step is always `npm install`:

```bash
cd e2e-tests
npm install
```

## Running

```bash
npm run test:emulator:android   # builds the debug APK, installs it fresh, runs tests/*.spec.ts
npm run test:emulator:ios       # builds for the simulator, boots one if needed, runs the same specs
npm run test:emulator:all       # both, sequentially
npm run mock:relay              # standalone mock relay on :8080 (for manual poking)
```

Useful switches:

```bash
WDIO_SPEC=tests/update-nudge.spec.ts npm run test:emulator:android   # one spec
WDIO_ANDROID_UDID=emulator-5554 npm run test:emulator:android        # pin an emulator
WDIO_IOS_UDID=<simulator-udid> npm run test:emulator:ios             # pin a simulator
./scripts/run-android-emu.sh --reboot    # cold-reboot the emulator first (clears wedged UiAutomation state)
npm run test:emulator:android:raw        # run wdio directly, no build or install (you deploy the app)
npm run test:emulator:ios:raw
```

The run scripts always reinstall the app. The configs use `noReset`, which reuses an
installed app, so a build alone never deploys your changes. If you use the `:raw`
scripts, install the APK or app yourself first. `WDIO_APPIUM_PORT` (default 4723) selects
the Appium port so an Android and an iOS run can overlap.

## The mock relay

On an emulator or simulator build the app's relay address is rewritten to the host's
loopback: `http://10.0.2.2:8080` on the Android emulator and `http://localhost:8080` on the
iOS simulator. Whatever listens on host port 8080 is "the relay", spoken to over plain HTTP
(no Tor, because the URL is not `.onion`).

`mock-relay/server.js` is a dependency-free, in-memory implementation of the relay's
capability-based protocol:

- **Inbox minting** behind a proof-of-work handshake (`POST /inbox` answers `400` with a
  challenge, then `201` with the inbox id and read/write capabilities). Difficulty defaults
  to 0, so minting is instant while keeping the real handshake shape.
- **Blob transport:** append (`POST /inbox/{id}` with a write capability), drain-on-read
  (`GET /inbox/{id}`), non-destructive `GET /inbox/{id}/peek`, capability rotation and
  inbox deletion.
- **Retrieve lease and ack.** `GET /inbox/{id}?lease=1` returns `{blobs, ids, token}`,
  deletes nothing and leases the blobs for `MOCK_RELAY_LEASE_MS` (default 60000).
  `POST /ack` deletes the acknowledged ids and releases the rest of that token's lease.
  Leased blobs are invisible to peek. Plain `GET` keeps the legacy delete-on-fetch.
- **Push registration** (`PUT` / `DELETE /inbox/{id}/push`). Pushes are recorded for
  inspection and never sent anywhere.
- Every auth failure, missing inbox or dropped inbox answers the same
  `404 {"error":"request rejected"}`, like the real relay.

Specs steer it through `helpers/MockRelay.ts` (backed by `/__control/*`, which only tests
call): `start`, `stop`, `reset`, `dropAllInboxes`, `dropInbox`, `restoreInbox`,
`setRateLimit` and `setVersions` / `clearVersions` (advertise an update-nudge version
header). A spec that never starts the mock sees an unreachable relay, which is the
deliberate way specs such as `connect-log` and `contact-list-layout` keep the "connecting"
state on screen.

Contract tests for the mock itself need no device:

```bash
npm run mock:relay:selftest   # protocol self-test
npm run test:mock-push        # push registration contract
npm run test:mock-lease       # lease + ack contract
```

## Accessibility ids

`helpers/AccessibilityIds.ts` (`Ids`) is the single list of ids the tests select by. The
same strings are set in the app: `.accessibilityIdentifier("...")` in SwiftUI and
`Modifier.testTag("...")` with `testTagsAsResourceId = true` in Compose, so one selector
(`~pin_dots`) works on both platforms. When you add UI, give the element the same id on
both platforms and add it to `Ids`. Widen a selector rather than narrowing it: helpers
are shared by every spec.

## Test hooks

- **`TEST_WIPE`** (Android, `--ez TEST_WIPE true` in the launch intent) and
  **`--test-wipe-on-launch=<nonce>`** (iOS launch argument) make a debug build wipe all
  app state before any vault state loads, so each spec starts fresh. They are compiled
  out of release builds. `helpers/AppReset.ts` triggers the wipe between specs.
- **Language pin.** Android gets `--es test_language ...` and iOS gets language arguments
  (`helpers/AppLocale.ts`), so the suite runs in English regardless of the device locale.
  `language.spec.ts` and the sweep change it on purpose.
- **Keep-alive.** UI automation produces no touch events, so an idle app would auto-lock
  mid-test. `helpers/KeepAwake.ts` resets the idle clock for the length of a run.

## Reading a failure

- The spec reporter prints each failure with a classification: `[TEST-FAILURE]` is an
  assertion or product failure, while `[INFRA-FAULT]` is a dead automation transport
  (dropped session, Appium or WebDriverAgent torn down, `socket hang up`). Infra faults
  are retried by re-running the spec file in a fresh session. See `helpers/infraFaults.ts`.
- **Screenshots per phase.** After every `it` the harness saves a screenshot to
  `e2e-tests/screenshots/<suite>/<device>/`, with names ending `__PASS.png` or
  `__FAIL.png`. This is on by default: set `WDIO_SCREENSHOT_EACH_PHASE=0` to turn it off,
  and `WDIO_SCREENSHOT_BUDGET_BYTES` caps the size (oldest are pruned first).
- **Video.** The published emulator suites take per-phase screenshots only and do not
  record video.
- Android failures: `adb logcat` on the emulator. iOS simulator: `xcrun simctl spawn
  booted log stream`. The run scripts also tee the full wdio output to a log file under
  the system temp directory.
- Appium diagnostics: set `WDIO_APPIUM_LOG=<file>` and `WDIO_APPIUM_LOGLEVEL=debug`.
- Android emulator hangs at the PIN screen (`pin_dots` never appears) usually means stale
  UiAutomation state from a killed run. Re-run with `--reboot`.

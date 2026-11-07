# Architecture: a code tour

This file is for someone opening the repository for the first time who wants to find the vault,
the ratchet, the wire format, the wipe and the connect path quickly, and read them in a sensible
order. It names files and entry functions; it does not restate the security model or the relay
protocol. For those, read:

- [`docs/SECURITY_OVERVIEW.md`](docs/SECURITY_OVERVIEW.md): threat model, what each protection
  does and does not do, known limitations.
- [`docs/RELAY_SPEC.md`](docs/RELAY_SPEC.md): every relay endpoint, what the relay stores and sees.
- [`docs/vault-relay-internals.md`](docs/vault-relay-internals.md): the detailed reference for the
  vault, KDF, device key, wipe, envelope, anti-replay and retrieve-ack rules. Read it before
  changing any of that code.

Citations use the form `path/File.kt` → `ClassName.functionName`. Kotlin paths below are under
`shared/src/<sourceSet>/kotlin/com/vg/run/` unless a full path is given.

## 1. Repository layout

| Path | What it is |
|---|---|
| `shared/` | Kotlin Multiplatform module with nearly all protocol, crypto and vault logic. Source sets: `commonMain` (platform-free code and `expect` declarations), `androidMain`, `iosMain`, plus `commonTest`, `androidUnitTest` (JVM) and `iosTest`. For iOS it builds `shared.xcframework` (`XCFramework("shared")` in `shared/build.gradle.kts`, targets `iosArm64`, `iosSimulatorArm64`, `iosX64`) with a `runcrypto` cinterop (`shared/src/iosMain/cinterop/runcrypto.def`). For Android it builds `librunargon2.so` from `shared/src/androidMain/cpp/` using the same vendored Argon2 sources as iOS (`iosApp/Argon2/`). |
| `androidApp/` | Single-activity Jetpack Compose app (`MainActivity`, `RunViewModel`, the `*Screen.kt` files) that consumes `:shared`. |
| `iosApp/` | SwiftUI app (`RunApp.swift`, `AppState.swift`, the `*View.swift` files) linking `shared.xcframework`, plus the Swift implementations behind the Kotlin bridge holders (section 2), the Swift `TorManager`, and the pinned `iosApp/Frameworks/tor.xcframework` with its checksum files. |
| `e2e-tests/` | WebdriverIO + Appium suites. `tests/*.spec.ts` are single-device specs for an emulator or simulator against `mock-relay/server.js`. See `e2e-tests/README.md` and `e2e-tests/mock-relay/README.md`. The maintainer's multi-device lab suites are not in this repository. |
| `fuzz/` | Jazzer harnesses for the hand-written parsers of untrusted input (`fuzz/README.md`). |
| `security-tests/` | Manual on-device checks for RAM hygiene and on-disk residue. |
| `scripts/`, `.githooks/` | Build and release gates (below), and the localisation pipeline in `scripts/l10n/`. |

Settings: `settings.gradle.kts` includes `:shared`, `:androidApp` and `:fuzz`, and uses
`RepositoriesMode.FAIL_ON_PROJECT_REPOS`, so every repository is declared centrally with content
filters. Most versions are in `gradle/libs.versions.toml`.

**Gates.** `.githooks/pre-commit` runs gitleaks on staged changes (`.gitleaks.toml`).
`.githooks/pre-push` runs `scripts/verify-gradle-wrapper.sh`, `check-network-api-usage.sh` (no
network API that could resolve DNS outside Tor), `check-logging-gated.sh`,
`verify-release-clean.sh`, `security-deps-report.sh`, `verify-tor-xcframework.sh` and
`verify-argon2-src.sh`, plus the localisation freshness check. `scripts/verify-release-artifact.sh`
checks a built release artifact (expected signer, hardened manifest).

**Generated files. Do not edit by hand.** English strings in
`androidApp/src/main/res/values/strings_*.xml` and the English store texts are the only
hand-edited text. From them, `scripts/l10n/gen-l10n.mjs` generates
`iosApp/iosApp/Localizable.xcstrings`, `iosApp/iosApp/InfoPlist.xcstrings`,
`iosApp/iosApp/L10n.swift` and `androidApp/src/main/java/com/vg/run/l10n/L10nKeys.kt`.
`scripts/l10n/l10n-sync.mjs` and its lock file (`scripts/l10n/l10n.lock.json`) record which English
each translation was made from, and `scripts/l10n/gen-store-metadata.py` generates the
`fastlane/metadata/**` store metadata (the store copy and the generator inputs are not published). The relay address constants are generated into the build
directory by the `generateRelayUrl` task (section 5).

## 2. The expect/actual seam

Platform-specific crypto, storage and transport live behind `expect` declarations in `commonMain`,
so protocol code never touches a platform API directly. When you change one side, change the other.

| `commonMain` declaration | Android actual | iOS actual |
|---|---|---|
| `PlatformCrypto.kt`: `sha256`, `constantTimeEquals`, `aesGcmEncrypt`/`aesGcmDecrypt`, `pbkdf2Sha256`, `argon2id`, `platformHmacSha256`, `x25519GenerateKeypair`, `x25519Ecdh` (top-level `expect fun`s) | `PlatformCrypto.android.kt` (JCA/Tink; native Argon2 via `NativeArgon2.kt`) | `PlatformCrypto.ios.kt` (calls the AES-GCM, X25519 and Argon2 bridges) |
| `PlatformHttpClient` (`expect class`); `RelayHttp` interface and `asRelayHttp()` | `PlatformHttpClient.android.kt`: OkHttp; `PlatformHttpClient.direct()` / `PlatformHttpClient.torProxy(socksPort)` | `PlatformHttpClient.ios.kt`: `PlatformHttpClient()` direct, `PlatformHttpClient(socksPort)` via `HttpBridge` → `SwiftTorHttp` (SOCKS5h with remote DNS over `NWConnection`) |
| `KeyValueStore` | `KeyValueStore.android.kt` (SharedPreferences, synchronous `commit`) | `KeyValueStore.ios.kt` (Keychain via `KeychainBridge`, write-ahead journal) |
| `CryptoProvider` (device-key AEAD) | `CryptoProvider.android.kt` + `CryptoManager.kt` (Tink keyset wrapped by an AndroidKeystore key) | `CryptoProvider.ios.kt` (Keychain-held device key, AES-GCM bridge) |
| `RelayConfig` (`expect object`; `BASE_URL`, `isTorRequired`) | `RelayConfig.android.kt` | `RelayConfig.ios.kt` |
| `Platform.kt` (logging, Base64, `generateSecureRandom`, clocks, `ioDispatcher`), `BuildFlags.kt` (`isDebugBuild`), `SyncLock`, `PowSolver.kt` (`solvePowParallel`), `L10n.kt` (`platformString`) | `*.android.kt` | `*.ios.kt` |

Several seams are ordinary interfaces with platform factories rather than `expect`:

- `VaultDatabase` (`VaultDatabase.kt`): `DatabaseManager.kt` on Android (SQLCipher),
  `IosVaultDatabase.kt` on iOS (through `DatabaseBridge` → `SwiftDatabaseBridge.swift`).
- `VaultFactory` (`VaultFactory.kt`): `androidVaultFactory(context)` / `iosVaultFactory()`.
- `DbKeyProtector` (`DbKeyProtector.kt`): `AndroidDbKeyProtector.kt` / `IosDbKeyProtector.kt`;
  `CryptoProviderDbKeyProtector` is the shared device-key-only variant.

Not part of the seam: **Tor** is platform code on both sides (`androidMain/.../TorManager.kt`, a
`TorManager` class that runs the Tor binary as a child process; `iosApp/iosApp/TorManager.swift`,
`TorManager.shared`, over `tor.xcframework`). `JsonParser.kt` is plain common code.

**iOS bridge registration order.** Kotlin code on iOS reaches Swift through seven holder objects
in `iosMain`: `AesGcmBridgeHolder`, `X25519BridgeHolder`, `Argon2BridgeHolder`,
`KeychainBridgeHolder`, `DatabaseBridgeHolder`, `HttpBridgeHolder`, `SecureEnclaveBridgeHolder`.
Common code calls them synchronously while it constructs crypto, the database and HTTP clients, so
every holder must be set before the first `KeyValueStore()` or `IosAppController()` is created.
All seven are set in one place, `iosApp/iosApp/AppState.swift` → `AppState.registerBridges()`.
That function is idempotent and is called first in `RunApp.init()` and again at the top of
`AppState.init()`, before `controller = IosAppController()`. A missing `Argon2BridgeHolder` fails
the vault unlock. Do not move any construction ahead of `registerBridges()`.

## 3. Reading order for the security core

1. **`VaultSelector.kt` → `VaultSelector`**: the only way into the vault. Start at
   `VaultSelector.unlock`, then `setRealCredential` → `provisionCredentialAndVault`. Look for:
   constant-time verifier check (`evalCredential`); Argon2id as `CURRENT_KDF_VERSION`, with the
   cost pinned per vault and a weaker cost in debug builds (`runtimeArgon2MemoryKiB`); upgrade of
   older KDFs on unlock (`needsCredentialRewrap`, `migrateCredentialToCurrentKdf`); the optional
   hardware auth-bound DB key (called Lever B in the code: `setDbKeyAuthBinding`,
   `enableDbKeyAuthBindingWithRecovery`); the recovery code, a second, PIN-independent path to the
   same DB key (`recoverWithCode`, `VaultStoreKeys.RECOVERY_BLOB`); legacy values upgraded on their next
   write (migrate-on-write); the provision guard and rollback (`ExistingVaultException`,
   `rollBackFailedProvision`, `storeWriteProven`); and `isConfigured()`, which deliberately
   returns `true` on an unreadable store so a real vault is never provisioned over. Callers must
   not read `true` as proof that a vault exists.
2. **`DbKeyProtector.kt`** (`DbKeyProtector`, `DbKeyScheme`): how the DB key blob is tagged and
   wrapped. Then the platform protectors: `AndroidDbKeyProtector.kt` + `AuthBoundKeyStore.kt`
   (Keystore key gated by `BiometricGate.kt`) and `IosDbKeyProtector.kt` +
   `iosApp/iosApp/SecureEnclaveHelper.swift` (Secure Enclave key).
3. **`KeyValueStore.ios.kt` → `KeyValueStore.putStringsSync`**: the Keychain has no
   transactions, so coupled writes (verifier plus wrapped key) go through a write-ahead journal
   (`vlt_txn_journal`) that `recoverPendingBatch` replays at the next construction. Single Keychain
   writes can fail silently while the device is locked; this is why.
4. **Wipe.** Android: `androidApp/.../WipeRoutine.kt` → `WipeRoutine.wipePersistentState`, the
   single deletion list. iOS: `iosApp/iosApp/AppState.swift` → `AppState.emergencyWipe` and
   `IosAppController.emergencyWipe` (`iosMain`), with `IosUserDefaultsKeys.all` as the iOS key
   list. Look for crypto-erase first: keys are destroyed before any file is deleted, so an
   interrupted wipe leaves only ciphertext.
5. **Wipe triggers.** `androidApp/.../InactivityWipe.kt` → `InactivityWipe.checkAndWipeIfNeeded`
   and `iosApp/iosApp/InactivityWipe.swift` (`InactivityWipe.isExpired`), with the shared
   threshold in `InactivityPolicy.kt`. Wrong attempts: `PinAttemptsStore.kt` →
   `PinAttemptsStore.recordWrongAttemptInWindowAndCheckLimit`, called from `PinEntryScreen.kt` and
   `PinEntryView.swift`. Look for the rule that only positive evidence triggers a wipe.
6. **`MessageManager.kt` → `MessageManager`**: the relay protocol. Inbox minting with proof of
   work (`mintInboxPair`); sending (`sendMessageWithOutcome` → `sendEnvelopeSerialized`); envelope
   parsing (`parseEnvelope`); draining (`prepareDrain` → `finishDrainCore`, per-blob
   `BlobOutcome`); acknowledgement (`AckBatch`, `sendAcks`, `RETRIEVE_LEASE_QUERY`); pending
   counts (`peekInboxesBatch`, `peekUnreadCountsWithGroup`). Also the top-level
   `ratchetMetaKeysForContact` (ContactMetaPurge.kt), the purge list both `deleteContact` actuals use.
7. **`RatchetManager.kt` → `RatchetManager`** (`tryEncrypt`, `decryptBatch`, `commitPending`) and
   **`DoubleRatchet.kt` → `DoubleRatchet`** (`initAsAlice`/`initAsBob`, `encrypt`, `decrypt`,
   `serialize`, role derivation in `ratchetSelfIsBobFromRoleOrder`). Look at when a contact
   leaves the static envelope and how a pending advance stays in memory until committed.
8. **`GroupManager.kt` → `GroupManager`**: groups are a fan-out over pairwise inboxes.
   `sendGroupMessage`, `ingest` (control messages), `pollAllControls`.
9. **`ReferralManager.kt` → `ReferralManager`**: introductions between two contacts with X25519
   key agreement (`startReferral`, `acceptOffer`, `handleControl`).
10. **Push.** `PushRegistration.kt` → `PushRegistration.register` / `unregister`, and
    `allPushableInboxes`. Android: `VendorPush.kt` (`VendorPush.isAvailable` picks FCM when Play
    Services is present, else UnifiedPush), `RunFcmService.kt`, `RunPushService.kt`,
    `UnifiedPushSupport.kt`. iOS: `AppState.registerPushToken`, `AppState.handleRemotePushWake`.
11. **Diagnostics that leave the device, all opt-in.** `ConnectTelemetry.kt` →
    `ConnectTelemetry.send`, `DebugMode.kt` (`DebugMode.setEnabled`, `DebugLogRedactor.redactLine`,
    `DebugLogUploader`), `BugReportSender.kt` → `BugReportSender.send`. Look at what is redacted
    and when each one is allowed to send.
12. **`ExternalTorProxy.kt` → `ExternalTorProxy`**: the user's own SOCKS5 proxy instead of the
    embedded Tor (`parse`, `classify`). Enforced in `RunViewModel.connectViaExternalProxy`; the iOS
    implementation (`iosApp/iosApp/ExternalProxyMode.swift`) exists but the setting is hidden in the
    iOS app for now (see `docs/external-socks-proxy.md`).

## 4. Four flows end to end

### (a) Launch → unlock → first relay answer → contact list

Android:
1. `MainActivity.onCreate` picks the start route (unlock if a vault is configured or its file
   exists). `RunViewModel.startSpeculativeTor` may start Tor before unlock, and
   `armPreUnlockRelayWarmup` → `RelayWarmup.warmAttempt` opens the onion circuit early.
2. `PinEntryScreen.kt` calls `VaultSelector.unlock`; on `UnlockResult.Opened`,
   `RunViewModel.onVaultOpened`.
3. `onVaultOpened` chooses the transport: `connectViaExternalProxy`, `connectViaTor`, or (debug
   or emulator only) `PlatformHttpClient.direct()`. In a release build a relay that is not
   `.onion` disables messaging; there is no clearnet fallback.
4. `connectViaTor` → `TorManager.start` (reads the SOCKS port from Tor's notice log) →
   `startTorMonitor` sees `TorManager.ConnectionState.Connected` →
   `wireRelayTransport(vault, PlatformHttpClient.torProxy(port))`, which creates `MessageManager`.
5. `wireRelayTransport` → `startRelayCheck` (first relay answer) and `startUnreadPrime` (`GroupManager.primeUnreadCounts`
   → `MessageManager.peekInboxesBatch`, one batch `POST /peek`) → `settleUnreadPrime` → `ConnectReveal.primeSettle`.
6. `RunViewModel.contactsReady` combines both through `ConnectReveal.contactsReady`; the contact
   list is shown when it turns true.

iOS:
1. `RunApp.init()` → `AppState.registerBridges()`; `AppState.init()` creates
   `IosAppController`. `AppState.startSpeculativeTor` and `warmRendezvousIfPreUnlock` →
   `IosAppController.warmRelayRendezvous` mirror the Android early start.
2. `AppState.unlock(pin:completion:)` → `IosAppController.unlock` → `VaultSelector.unlock`.
3. `AppState.startTorOrDirect` → `TorManager.shared.start()`.
4. `AppState.wireRelayTransport(socksPort:reason:)` → `IosAppController.connectTor(socksPort)` creates
   `MessageManager`.
5. `AppState.startRelayCheck` → `checkRelayReachability` and `startUnreadPrime` →
   `settleUnreadPrime` → `recomputeContactsReady`, which uses the same `ConnectReveal` rules.

Android tears the session down when the app goes to the background: `MainActivity.onStop` calls
`finishAndRemoveTask()` and `RunViewModel.onCleared` closes the vault and stops Tor. A short,
bounded keep-alive (`TorKeepAliveService`, armed by `RunViewModel.armTorKeepAliveOnBackground`)
can keep the process, and Tor with it, alive briefly; the vault is still locked. iOS has the same
bounded keep-alive; its rules are in `BackgroundTorKeepAlive.kt`.

### (b) Sending a text

1. UI: `RunViewModel.sendMessageInBackground` / `AppState.sendMessage` →
   `MessageManager.sendMessageWithOutcome` → `sendEnvelope` → `sendEnvelopeSerialized`.
2. If the ratchet has a sending chain, `sendOverTextRatchet` pads the envelope (`padMessage`) and
   encrypts it with `RatchetManager.tryEncrypt`.
3. Otherwise (no inbound ratchet message from the peer yet) the static envelope is used: a
   per-contact counter is persisted before sending, the JSON envelope carries epoch, counter,
   minute-rounded time, channel tag `ch` and destination inbox `di`, and it is padded
   (`padMessage`, power-of-two buckets) and sealed with `aesGcmEncrypt`.
4. `POST /inbox/{id}` over `RelayHttp.post`, with the write capability in the headers
   (`sendHeaders`).
5. The relay stores an opaque, padded blob until it is fetched and acknowledged or its TTL ends.
   What the relay can see is listed in `docs/RELAY_SPEC.md` §6.

### (c) Receiving

1. The conversation screen polls: `ConversationScreen.kt` → `GroupManager.pollDirectPending`
   (iOS: `AppState.pollDirectPending`), which reaches `MessageManager.pollChannelPendingOutcome`
   → `prepareDrain`.
2. `GET /inbox/{id}?lease=1` leases the blobs; nothing is deleted yet.
3. `finishDrainCore` decides each blob: ratchet wire → `receiveOverTextRatchet` /
   `RatchetManager.decryptBatch` (advance kept in memory); static wire → `aesGcmDecrypt`,
   `unpadMessage`, `parseEnvelope`, then the epoch, strict counter, `ch` and `di` checks. Old
   envelopes without a counter are dropped. Every blob gets a `BlobOutcome`.
4. The screen adds the messages to its in-memory list, then calls `PendingDrain.commit()`: it
   persists the ratchet and anti-replay state, then sends a `POST /ack` in the background that
   deletes the handled blobs on the relay. If the screen is left before commit, the drain is
   abandoned and the relay re-delivers after the lease.
5. Burn on read: the vault has no message table. Messages exist only in the screen's memory and
   are gone when you leave the conversation.

### (d) Wipe

1. Triggers: wrong-attempt limit (`PinAttemptsStore`), inactivity on launch
   (`InactivityWipe`), after a device move, and "Erase and start over" on an orphaned vault file
   (`VaultSelector.orphanedVaultFile`).
2. Android `RunViewModel.performEmergencyWipe`: best-effort push deregistration for every
   pushable inbox (`unregisterPushBestEffort`), cancel jobs, close the vault,
   `CryptoProvider.wipeKey`, then `WipeRoutine.wipePersistentState`: `ProcessWipeLatch.latch()`
   (in-memory only), `CryptoManager.eraseMasterKey`, `AuthBoundKeyStore.deleteKey`, the push key
   material, then the databases, preference files and Tor state. After that, in-memory scrubs
   (`MessageManager.scrubInMemory` and the group and referral managers) and Tor is stopped with
   its state discarded.
3. iOS `AppState.emergencyWipe`: `KeychainHelper.deleteKey` and `SecureEnclaveHelper.deleteKey`
   first, then push deregistration (`unregisterCurrentInboxesBestEffort`), stop polling and Tor,
   then `IosAppController.emergencyWipe` (Keychain sweep, `IosUserDefaultsKeys.all`,
   `wipeAllTables`, database files), then the in-memory state.
4. What remains: ciphertext with no key, plus the filesystem traces listed in
   `docs/SECURITY_OVERVIEW.md` §8.

## 5. Build-time configuration

- **Relay address.** The `generateRelayUrl` task in `shared/build.gradle.kts` reads a non-empty
  `RELAY_ONION_URL` environment variable first, then the gitignored `relay.properties`
  (`relayOnionUrl=`; see `relay.properties.example`). Up to three comma-separated onion addresses
  of the same relay are allowed. Empty means no relay. It emits `RELAY_URL_FROM_PROPERTIES` and
  the list form, which both `RelayConfig` actuals read. Emulators and simulators use the host
  loopback instead (`10.0.2.2:8080` / `localhost:8080`).
- **Dev relay scrub.** An optional `relayDevOnionUrl` / `RELAY_DEV_ONION_URL` is used only by
  debug builds. The build fails if it equals a production address. It is emitted empty for any
  release-intent build (a task name containing "release", Xcode `CONFIGURATION=Release`, or
  `STRIP_DEV_RELAY=1`).
- **Refused invocations.** Because the scrub depends on the whole invocation, Gradle refuses a bare
  `build` / `assemble` and any invocation that mixes a Debug artifact task with a release-intent
  task. Build the debug APK on its own (`./gradlew :androidApp:assembleDebug`).
- **Version.** `version.properties` holds `versionName` and `versionCode` for both platforms.
- **Signing.** `androidApp/build.gradle.kts` looks for `keystore.properties` in
  `$RUN_SIGNING_DIR`, then `~/.run-signing/`, then the repo root. Without it, release builds are
  unsigned.
- **Native Argon2 on Android** needs an NDK, CMake and Ninja; iOS builds do not.

For the step-by-step setup, see `BUILDING.md`.

## 6. Tests

- **JVM unit tests** (`./gradlew test`): `shared/src/commonTest` covers the protocol and vault
  logic against fakes: envelope binding and replay (`AntiSpliceReplayTest`), retrieve-ack
  (`RetrieveAckTest`), the ratchet (`DoubleRatchetTest`, `RatchetManagerTest`), the KDF
  (`VaultKdfTest`), groups, referrals, push registration, connect timing and the reveal gate.
  `shared/src/androidUnitTest` adds JVM-only tests such as the Argon2 known-answer vectors
  (`Argon2BouncyCastleKatTest`) and schema pins (`MigrationSchemaPinTest`).
  `androidApp/src/test` covers app-level policy. `shared/src/iosTest` runs on the simulator.
- **Source-pinning tests.** Some invariants are about ordering or about something never being
  called, and a behaviour test cannot see them easily. These tests read source files as text and
  assert on them: for example that no preferences write uses `apply()`
  (`PrefsApplySourceGuardTest`), that no message table comes back
  (`LegacyMessageTableRemovalTest`), that the push opt-out paths use the right teardown
  (`VendorPushOptOutTeardownSourceTest`), and that Android and iOS keep matching behaviour (the
  `*ParitySourceTest` files). Most are named `*SourceTest` or `*SourceGuardTest`. When one fails
  after a refactor, re-establish the invariant; do not just update the expected text.
- **Instrumented tests** (`androidApp/src/androidTest`, `./gradlew connectedAndroidTest`) run real
  SQLCipher and Keystore on a device or emulator. They replace the installed app and its data.
- **Emulator e2e** (`e2e-tests/`, `npm run test:emulator:android`, `test:emulator:ios`): debug builds against the local mock relay
  (`npm run mock:relay`), which implements the lease and ack contract. No Tor is involved.
- **Physical devices.** The maintainer also runs multi-device suites (cross-platform messaging,
  groups, push, resilience) on a phone lab against a live relay over Tor. Those suites, the device
  allowlist and the lab tooling are not in this repository; the relay server source is not either.

## 7. Where not to look for secrets

The tree contains no relay address, signing keystore, push credentials or App Store / Play
credentials. These files are gitignored and stay local:

- `relay.properties`: production and dev onion addresses (or use the environment variables).
- `local.properties`: SDK, NDK and CMake paths.
- `keystore.properties`, `*.jks`, `*.keystore`: Android signing, normally outside the repo in
  `~/.run-signing/`.
- `androidApp/src/*/google-services.json`: Firebase client config; release builds fail without
  it, debug builds continue without FCM.
- `fastlane/.env*`, `fastlane/*.p8`, `fastlane/*service-account*.json`: store API credentials.

The pre-commit gitleaks scan and `scripts/verify-release-artifact.sh` exist to keep it that way.

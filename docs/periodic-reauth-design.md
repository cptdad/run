# Periodic random re-authentication at MAXIMUM — design

Status: IMPLEMENTED (shipped; design accepted 2026-08-21). Requirement (2026-08-21):
on the MAXIMUM protection level the user must re-enter the passphrase after a **random** time
while actively using the app — **at least once every ten minutes** — independent of inactivity.

## 1. Existing machinery this plugs into

Tier / credential rules (commonMain)
- `ProtectionLevel.MAXIMUM` (`usesPassphrase`), Lever C timeouts CASUAL 15 min / PRIVATE 2 min /
  MAXIMUM 60 s, wrong-credential budgets 10/8/5 — `shared/src/commonMain/kotlin/com/vg/run/ProtectionLevel.kt`.
- `CredentialPolicy`: `AUTO_LOCK_CHECK_INTERVAL_MS` 10 s, `AUTO_LOCK_WARNING_MS` 5 s,
  `AUTO_LOCK_FINE_WINDOW_MS` 15 s, `AUTO_LOCK_FINE_CHECK_INTERVAL_MS` 1 s; per-read
  `maxConsecutiveAttempts(read)` / `autoLockTimeoutMs(read)` — Damaged and Unreadable get the
  *shortest* timeout (fail-safe: locking sooner loses no data).
- Enforcement read `VaultSelector.protectionLevelForEnforcement()` (unauthenticated/unknown token
  ⇒ `Present(MAXIMUM)`, key unavailable ⇒ `Unreadable`, AEAD failure ⇒ `Damaged`). The entry-widget
  selector `isPassphraseMode()` is display-only and must never gate enforcement.
- `isDebugBuild` (`BuildFlags.kt`), CSPRNG `generateSecureRandom(size)` (`Platform.kt`),
  monotonic time `TimeSource.Monotonic`.

Credential verification paths — the load-bearing distinction
- `VaultSelector.unlock(credential)` → `Opened/Denied/Error/RecoveryRequired`; only `Denied` is a
  counted guess, and the UI counts it through `PinAttemptsStore` + the 24 h window + the wipe budget.
- `VaultSelector.verifyCredential(credential)` is the change-PIN gate: side-effect-free, never opens
  the vault, throttled by a uniform 5 s sleep, and its caller counts through `ChangePinAttemptStore`
  (daily budget) — a verify-only re-auth would NOT count identically.

Android (Lever C, lock, unlock)
- `MainActivity`: `lastInteractionMs`/`onUserInteraction`; `autoLockCheck` Runnable reads the
  enforcement tier, locks via `finishAndRemoveTask()`, drives `lockCountdownSecs` and the
  fine/coarse cadence; compiled out of debug (`if (!BuildConfig.DEBUG)` in `onResume`, removed in
  `onPause`); `onStop → finishAndRemoveTask()`.
- There is **no in-process lock on Android today**: "lock" == Activity finish →
  `RunViewModel.onCleared()` (cancel jobs, `vault.close()`, scrub managers, clear id maps,
  `cryptoProvider.wipeKey()`, cancel notifications, `torManager.stop()`).
- Unlock: `PinEntryScreen` (ids `pin_prompt`, `passphrase_field`, `unlock_button`, `pin_dots`),
  pre-evaluation durable counter write, `Denied` → 24 h window + budget → emergency wipe.
  `onVaultOpened` is the single vault-open callback; `connectViaTor` **adopts a live Tor** instead
  of restarting (`torInstanceIsLive`).
- Debug `TestHooks.handleTestWipe` reads intent extra `TEST_WIPE`; release stub is a no-op.

iOS (Lever C, lock, unlock)
- `InactivityAutoLock` (systemUptime clock); `ContentView` `autoLockTimer` with the whole
  `.onReceive` body inside `#if !DEBUG`; `guard scenePhase == .active, appState.isUnlocked`;
  `lockAndResetNavigation()` → `appState.lock()` (Tor stays up for a foreground lock),
  `navPath = NavigationPath()`, sheet flags cleared. `.background`-not-`.inactive` gate.
- `PinEntryView` (same a11y ids), half-typed credential zeroed on `phase != .active`.
- `--test-wipe-on-launch=<nonce>` parsed under `#if DEBUG` in `RunApp.swift`.

e2e
- `KeepAwake.ts` is touch-based and opt-in; single-device specs are PIN-only (`EulaHelper` picks
  CASUAL); device suites run iOS seats on MAXIMUM for multi-minute Tor waits.

## 2. Decisions

**Tier gate.** Enabled iff `protectionLevelForEnforcement()` is `Present(MAXIMUM)`, `Damaged` or
`Unreadable` (same fail-safe direction as Lever C). `Present(CASUAL)`, `Present(PRIVATE)`, `Absent`
→ off. Re-read at arm time (every unlock) and on every tick, so a tier change takes effect
immediately. Never gate on `isPassphraseMode()`.

**Interval.** Uniform on **[3 min, 10 min]**, drawn from `generateSecureRandom` (8 bytes reduced mod
range; bias 2^-45, documented), drawn fresh at **every vault open** (the re-auth *is* an unlock, so
"after every successful auth" and "on every unlock" coincide). Deadline = monotonic now + interval
(`SystemClock.elapsedRealtime` / `ProcessInfo.systemUptime`), RAM-only, never persisted; wall-clock
changes cannot move it. The 3-minute floor (a) prevents back-to-back prompts, (b) is strictly above
MAXIMUM's and PRIVATE's Lever C windows so an idle user always hits Lever C first, (c) bounds the
Argon2id re-derive cost. "Since unlock", not "active time".

**Firing mid-action: interrupt, don't defer.** The requirement is a hard bound; a defer-until-safe
needs every screen on both platforms to report busy-ness (a drift surface). UX concession: a 5 s
warning overlay inside the window (reuse the Lever C overlays, copy "Passphrase check in N…") with
**no "tap to stay"** — the deadline never moves. Consequences are exactly those of a Lever C lock
today (draft lost, in-flight send cancelled and scrubbed, camera/referral sheets torn down).

**Full lock, not a verify gate.** (a) Threat model: the AFU-window hardening is about RAM; a verify
gate leaves the SQLCipher key, Tink/Keychain key, ratchet state and decrypted messages resident,
the lock path wipes them. (b) Attempt accounting: only `PinEntryScreen`/`PinEntryView` →
`VaultSelector.unlock` counts into `PinAttemptsStore` and the wipe budget; `verifyCredential` uses a
different store and a 5 s sleep. (c) Cost is marginal and Tor stays up on both platforms.
CR-1 / brick-safety hold trivially: no new code touches the credential store.

**Android gains an in-process lock (parity).** Extract `RunViewModel.lockSession(stopTor: Boolean)`
from `onCleared` (ONE teardown body; `onCleared` = `lockSession(stopTor = true)` + Tor null-out).
`MainActivity` navigates to `"pin"` with `popUpTo(0) { inclusive = true }` via a StateFlow collector
modeled on the `vaultSessionRetired` collector. Re-unlock lands in `onVaultOpened`, whose
`connectViaTor` adopts the still-live `TorManager` and rebuilds `MessageManager` from the replayed
`Connected` state. Lever C itself stays on `finishAndRemoveTask` (follow-up for parity).

**Background/foreground.** Trivially "since unlock": Android tears down on `onStop`, iOS locks on
`.background`, so every foreground return is a fresh unlock and a fresh draw. iOS `.inactive` skips
the check but the deadline keeps running; overdue fires on the first `.active` tick. Android
`onPause` removes the watchdog, `onResume` re-posts it; overdue fires on the first post-resume tick.

**Interaction with Lever C.** Idle → Lever C fires first (floor > 60 s, pinned by unit test). Active
→ only the re-auth matters. Both end in the same lock primitive and both no-op once locked. ONE
watchdog per platform: `remaining = min(leverCRemaining, reauthRemaining)`, shared cadence, one
overlay whose copy depends on which deadline is nearer. The wholesale debug gates move inward to
wrap only the Lever C branch.

**Build flavour / e2e.** NOT compiled out of debug. Rule:
`enabled = tierGate && (!isDebugBuild || testIntervalOverrideMs != null)`.
Release: always on at MAXIMUM with the random draw; no override path exists in a release binary.
Debug: OFF by default (mandatory — the device suites run iOS seats on MAXIMUM and KeepAwake cannot
defeat a touch-independent timer), ON with a fixed deterministic interval when
`--test-reauth-interval-ms=<n>` (iOS) / `--el TEST_REAUTH_INTERVAL_MS <n>` (Android) is passed;
floor 1000 ms. Update the `BuildFlags.kt` kdoc and the `KeepAwake.ts` header.

**State across re-auth.** Nothing survives (as with every lock today); preserving a plaintext draft
across a RAM-hygiene lock would contradict it. One papercut fixed: a lock inside a conversation
would otherwise leave the clean-leave flag at "0" and show "Conversation interrupted" on the next
unlock — the re-auth lock first calls `markCleanLeave()` on both platforms (precedent:
`GroupInfoScreen.onLeft`). NOT applied to `AppState.lock()` generally (background locks keep the
warning).

**Other tiers.** Explicitly off, pinned by unit test. Lever B never intersects this feature.

**a11y ids.** The prompt IS the existing unlock screen: reuse `pin_prompt`, `passphrase_field`,
`unlock_button` (`pin_dots` for a PIN vault landing here via Damaged/Unreadable). New optional id
on both warning overlays: `reauth_countdown`.

## 3. Implementation plan

commonMain
1. New `shared/src/commonMain/kotlin/com/vg/run/ReauthPolicy.kt`: `MIN_INTERVAL_MS = 3*60_000`,
   `MAX_INTERVAL_MS = 10*60_000`, `WARNING_MS = CredentialPolicy.AUTO_LOCK_WARNING_MS`;
   `appliesTo(read)`, `isEnabled(read, debugBuild = isDebugBuild, override = testIntervalOverrideMs)`,
   pure `intervalFromRandom(bytes)`, `nextIntervalMs(random = ::generateSecureRandom)` (override ⇒
   fixed), `setTestIntervalOverrideMs(ms): Boolean` (refuses unless `isDebugBuild`; clamp ≥ 1000),
   deadline helpers `remainingMs(deadline, now)` / `phase(remaining): Fire | Warn(seconds) | Idle`.
2. `BuildFlags.kt` kdoc: list the debug-only TestHook uses (KDF cost, `ProcessWipeLatch.resetForTest`,
   re-auth override).
3. `IosAppController`: `reauthEnabled()`, `nextReauthIntervalMs()` next to `autoLockTimeoutMs()`.

androidApp
4. `RunViewModel`: extract `lockSession(stopTor)` from `onCleared` (job cancels incl.
   `torMonitorJob`, `vault.close()`/null, manager scrubs, `clearInMemoryIdentifierMaps()`,
   `cryptoProvider.wipeKey()`, `NotificationHelper.cancelAll`; `torManager.stop()`/null only when
   `stopTor`). `reauthDeadlineElapsedMs: Long?` armed in `onVaultOpened` when enabled, cleared in
   `lockSession`. `_reauthLocked` StateFlow + `lockForReauth()` =
   `cleanLeaveTracker.markCleanLeave(); lockSession(stopTor = false); _reauthLocked.value = true`.
   REVIEW: `vault`-null race against an in-flight `changeCredentialInner`
   rotation (`vaultProvider = { vault }`), `retireRekeyedVaultHandle`, and that Tor-monitor
   re-attachment on adoption rebuilds `messageManager` after a lock that nulled it.
5. `MainActivity.autoLockCheck`: compute `reauthRemaining`; Lever C branch gated on
   `!BuildConfig.DEBUG` *inside* the Runnable, Runnable always posted from `onResume`; fire
   `vm.lockForReauth()`; overlay state `(secondsLeft, isReauth)`; `LaunchedEffect` collecting
   `reauthLocked` → `navigate("pin") { popUpTo(0) { inclusive = true } }` + reset; overlay copy
   variant + `reauth_countdown`.
6. Debug `TestHooks.handleTestReauth(intent)` reading `TEST_REAUTH_INTERVAL_MS` (long extra) →
   `ReauthPolicy.setTestIntervalOverrideMs`; release stub no-op; call after `handleTestWipe`.
7. `PinEntryScreen`: no functional change; verify fresh composition re-reads mode/budget and that
   `pinAttempts.read()` works after `wipeKey()`.
8. `AddContactScreen`: confirm the CameraX binding is composition-scoped (pop releases the camera).

iosApp
9. `ContentView`: `@State reauthDeadlineUptime: TimeInterval?` armed on `isUnlocked` → true when
   `controller.reauthEnabled()`; `#if !DEBUG` moved to wrap only the Lever C computation; shared
   `guard scenePhase == .active, appState.isUnlocked`; `remaining = min(...)`; fire
   `controller.markCleanLeave(); lockAndResetNavigation()`; clear the deadline in
   `lockAndResetNavigation()`; overlay copy variant + `reauth_countdown`.
10. `RunApp.swift`: under the existing `#if DEBUG`, parse `--test-reauth-interval-ms=<n>` →
    `ReauthPolicy.setTestIntervalOverrideMs`.
11. `AppState`: no change (deadline lives in `ContentView`; do NOT mark clean-leave in `lock()`).

e2e
12. `PinHelper.completePassphraseSetup(phrase)` / `enterPassphrase(phrase)`; `EulaHelper` chooser
    level parametrised (default unchanged = CASUAL); `AppReset.resetAppWithArgs({ reauthIntervalMs })`
    appending the platform launch arg. Must not change the 14 existing single-device specs.
13. New `e2e-tests/tests/reauth.spec.ts` (emulator + simulator): (1) prompt appears within the
    fixed 20 s interval at MAXIMUM (and not before 10 s), `unlocked_root` gone; (2) 5 wrong
    passphrases at the prompt → emergency wipe (proves shared `PinAttemptsStore` + MAXIMUM budget);
    (3) correct passphrase re-arms; (4) off at CASUAL. On Android never `relaunchApp()` after
    arming (`activateApp` drops intent extras); iOS inherits args across relaunch.
    `KeepAwake.ts` header note.

Sequencing: 1 → (4, 3) → (5, 6, 9, 10) → 12 → 13; compile both platforms after 10, then e2e.

## 4. Tests

commonTest `ReauthPolicyTest`: 10k draws within bounds; MIN/MAX constants; `MIN >` MAXIMUM's and
PRIVATE's Lever C timeouts; `WARNING_MS <= MIN/2`; distribution mean within 5 % of midpoint, both
halves populated, two draws differ; tier gate (MAXIMUM/Damaged/Unreadable true; CASUAL/PRIVATE/
Absent false) and agreement with `CredentialPolicy.autoLockTimeoutMs` fail direction; flavour gate
(`debugBuild=true, override=null` → false; `debugBuild=false` → true; override → true and constant;
`< 1000` rejected; setter refuses in release); `phase()` boundaries. One forged-tier assertion in
`SelectorMetaGuardTest` and the `VaultSelectorTest` androidTest loop.
Android instrumented: `lockSession(stopTor=false)` leaves `vault/messageManager/deadline` null and
`torManager` non-null; `stopTor=true` nulls it. SwiftUI timer/lifecycle is build + e2e verified.

## 5. Risks
- Android in-process lock is new surface — mitigated by `onCleared` delegating to `lockSession`;
  dedicated review of the `vault`-null races and the pause-cover / multi-window teardowns.
- Play Billing / full-screen covers: watchdog removed in `onPause`, `onStop` tears down — no new hazard.
- Push-prompt dialog is one-shot and lost by a re-auth while open (pre-existing with Lever C);
  follow-up: `showPushPrompt = showPushPrompt || consumePushPromptOnce()` both platforms.
- Tor bootstrap in progress: iOS keeps Tor in foreground lock; Android adoption keeps it; confirm the
  stall hint cannot fire onto the PIN screen.
- Timer lateness ≤ 1 s with the fine cadence; if a hard ≤ 10:00.000 is required draw
  `MAX = 10 min − AUTO_LOCK_FINE_CHECK_INTERVAL_MS`.
- `isDebugBuild` semantics on iOS (shared framework) — a release app with a debug framework already
  fails loud; fix the `BuildFlags.kt` kdoc.
- e2e helpers assume PIN — new helpers must not change existing specs' defaults.
- Clean-leave marking on the re-auth lock changes one semantic (a lock mid-conversation no longer warns).
- `Unreadable ⇒ enabled` prompts CASUAL/PRIVATE users with their PIN during a transient Keystore/
  Keychain outage (loses no data; alternative: gate on `Present(MAXIMUM) | Damaged` only).

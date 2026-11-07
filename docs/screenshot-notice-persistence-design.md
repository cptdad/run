# Persistent 24-hour screenshot notices — root cause + design

Status: IMPLEMENTED (shipped; design accepted 2026-08-21). Requirements (2026-08-21):
(1) PROD BUG — when user A (iOS) takes a screenshot in a conversation, the notice is visible only on
A's device, never on B's; (2) the notice must NOT be burn-on-read: it stays in B's conversation for
24 h, shows the time the screenshot was taken, and multiple notices coexist.

## 0. Root cause of the production bug (CONFIRMED by code reading)

The 1:1 notice rides a `"screenshot"` control envelope (`MessageManager.sendScreenshotNotice` →
`sendDirectControl(..., noPush = true)`), push-suppressed by design and delivered only through the
app-wide background control sweep `GroupManager.pollAllControls()` — a **destructive** relay drain
(25–45 s idle cadence). Once drained, the notice is moved into a **RAM-only** per-conversation
buffer (`GroupManager.pendingScreenshotNotices`, cap 16) and is rendered **only when B opens that
exact conversation**. Both platforms tear the whole session down on backgrounding (every
foreground return is a full re-bootstrap) and that teardown calls
`groupManager.scrubInMemory()` (Android `RunViewModel.onCleared`, iOS `IosAppController.lock`),
which clears the buffer. So unless B has the conversation open at drain time, the notice is
**permanently lost** — no trace on the relay (already deleted) or on the device. The e2e step that
"proved" the feature kept B's conversation open and polling for the whole wait (the physical-device helper's doc
comment: "The caller's 1:1 conversation must already be open"; maintainer suite, not published), the one condition production almost
never satisfies. What A "sees" is the unrelated, always-firing local banner from
`ScreenshotProtection.swift` ("Screenshot saved to Photos …"); the peer-notify send's boolean is
discarded unlogged in `ConversationView.swift` (~:205).

Ruled out with evidence: relay-side handling (content-blind opaque blobs, no kind allow-list, prod
logs clean), R8/ProGuard, `isDebugBuild` gating, `#if DEBUG`, TestHooks, protocol negotiation.
Plausible but unverifiable: B's installed store build predating the feature (old builds drop
unknown kinds silently by design).

**Fix = persist on receipt** (this design), plus log the send result on iOS.

## 1. Current architecture (file references as of 2026-08-21)

- Wire: `MessageManager.CONTROL_KIND_SCREENSHOT = "screenshot"` (~:661), group twin
  `GroupManager.KIND_SCREENSHOT` (~:175). Sealed envelope
  `{"e","c","t":roundTimestampToMinute(now),"ch","di","k":"screenshot","b":"{}","m":""}` — **the
  sender's capture time already rides every envelope, minute-rounded, inside the AEAD**.
- Receive: legacy path ~:2566-2571 (after the strict-monotonic counter check), ratchet fallback
  ~:2192-2194; both call `noteScreenshotNotice(contactId)` and currently discard `env.timestamp`.
  Unknown kinds dropped at ~:2509-2514 / `GroupManager.handleControl` else-arm (forward compat).
- RAM buffers: `noteScreenshotNotice`/`drainDirectScreenshotNotices` (MessageManager ~:210-242,
  cap 32); `GroupManager.collectDirectScreenshotNotices` (~:523-540), `bufferScreenshotNotice`
  (cap 16/conversation), `drainScreenshotNotices` (destructive), `handleScreenshotNotice`
  (~:1847-1859), `scrubInMemory` (~:580-591).
- Model `ScreenshotNotice(conversationId, isGroup, senderContactId, senderAlias, timestamp)`
  (`ScreenshotNotice.kt`), header claims "ephemeral by construction".
- Storage: none. `_meta` KV is the generic store (`VaultDatabase.kt` ~:222-256). Android
  `DATABASE_VERSION = 8`; iOS has no schema-version system (idempotent DDL). Purge: exact-key list
  `ratchetMetaKeysForContact` + classifier predicates (`isGroupMetaResidueForGroup/Contact`,
  referral classifier) iterated by `DatabaseManager.deleteContact/deleteGroup`,
  `IosVaultDatabase.deleteContact/deleteGroup`, and the commonTest `InMemoryVault`.
- UI: Android `ConversationScreen` (`DisplayMessage.isNotice`, drain in the poll loop, bubble
  `testTag("screenshot_notice")`, `formatTime` HH:mm), `GroupConversationScreen`
  (`screenshot_notice_group`); iOS `ConversationView` (`screenshot_notice`), `GroupViews`
  (`screenshot_notice_group`, `insertByTimestamp`), `AppState.drainScreenshotNotices`.
- Unread: contact map replaced wholesale each sweep from `/peek` on the inbound TEXT inbox
  (`GroupManager.contactUnreadCounts`); prime is merge-only and a zero peek REMOVES the entry; group
  dot is RAM `groupUnread`. Push: `X-No-Push: 1`; tokens only on inbound text inboxes.
- e2e: ids `screenshot_notice` / `screenshot_notice_group` (`AccessibilityIds.ts`), helpers
  `waitForScreenshotNotice`, `waitForGroupScreenshotNotice`, `triggerHardwareScreenshot` (iOS
  only); step 2c of the maintainer's physical-device suite (not published) asserts
  `toContain('screenshot')`; that suite already terminates+relaunches both devices later.
- Unit: `ScreenshotNoticeTest.kt` (`groupNotice_doesNotTouchTheUnreadCounters` pins the opposite of
  the new unread decision and must be rewritten deliberately); purge parity `MetaResiduePurgeTest`.

## 2. Design

### 2.1 Storage — `_meta` keys, one per notice; NO schema bump
- Key `ssn:<conversationId>:<senderContactId>:<receivedAtMs>` (contactIds are UUIDs, groupIds
  Base64Url — `:`-safe). Value `<takenAtMs>|<isGroup 0/1>|<seen 0/1>`, lenient parse (unparseable →
  dropped on load). Never stores alias/text; alias resolved from the vault at read time.
- Caps: 16 per conversation (oldest evicted on insert); `SCREENSHOT_NOTICE_TTL_MS = 24 h`.
  Collision on `receivedAtMs` → bump by 1 ms.
- Why not a table: a v9 file opened by a 0.8.179 binary fails with "Can't downgrade" = unlock
  failure; `_meta` reuses the purge machinery both actuals already iterate; bounded residue.

### 2.2 Shared store — new commonMain `ScreenshotNoticeStore.kt`
`ScreenshotNoticeStore(vault, clock = { currentTimeMillis() })` with `record(conversationId,
isGroup, senderContactId, senderClaimedTakenAtMs): StoredScreenshotNotice?`,
`list(conversationId)` (unexpired, ascending `(receivedAt, key)`, prunes that conversation),
`markSeen(conversationId)`, `unseenCounts(): Map<String, Int>`, `pruneExpired()`.
`StoredScreenshotNotice(conversationId, isGroup, senderContactId, takenAt, receivedAt, seen)` with
`expiresAt = receivedAt + TTL`. Owned by `GroupManager` (already the one surface for both
contexts; has the vault). `record` wraps evict+insert in `vault.withTransaction`, never under
`bufferLock` (non-reentrant on iOS). iOS `putMeta` throws → catch, fall back to RAM-only for the
open screen. `ScreenshotNotice` gains `receivedAt`, `expiresAt`; `timestamp` keeps its name and
now means the display time (clamped `takenAt`) so existing UI call sites compile.

### 2.3 Timestamp semantics
- `receivedAt` = local clock at receive → authoritative for **expiry and ordering** (attacker-free).
- `takenAt` = sender's `t` if `0 < t ≤ receivedAt + 5 min` and `receivedAt − t ≤ 24 h` (clamped
  to `receivedAt` if in the future), else `receivedAt` → **display only** ("· 14:32"). Identical
  trust to text bubbles (`ReceivedMessage.timestamp = env.timestamp`).
- Expiry = `receivedAt + 24 h`, NOT `takenAt + 24 h`: with a sender-anchored expiry the
  screenshotter could backdate `t` and make their own notice vanish in a minute. Honest delivery
  over Tor is seconds; B-offline divergence errs toward showing longer. (Deliberate deviation from
  a literal "24 h from capture".)
- Plumbing: `noteScreenshotNotice(contactId, env.timestamp)` at both receive sites;
  `GroupManager.handleControl(..., timestampMs: Long = 0L)` passed from `ingest` into
  `handleScreenshotNotice`.

### 2.4 Expiry — no dedicated timer
Pruned on write (`record`), on load (`list`), on the background control sweep
(`SessionManagers.kt` hook: `{ referralManager.runMaintenance();
groupManager.pruneExpiredScreenshotNotices() }`, first run seconds after unlock), and hidden UI-side
per poll tick by `expiresAt <= now` (no vault read per tick).

### 2.5 Ordering / multiplicity
One key per screenshot; UI loads persisted notices first on open, then the poll loop appends new
ones via the existing drain; dedupe id `ss-<sender>-<receivedAt>`.

### 2.6 Sender symmetry
Android cannot send today (FLAG_SECURE; minSdk 30 < API 34 `ScreenCaptureCallback`); the receiver
is fully symmetric in commonMain. `triggerHardwareScreenshot` stays iOS-only.

### 2.7 Unread — YES, a persisted "unseen" term merged in commonMain
`GroupManager.contactUnreadCounts()` returns `direct + unseenNotices(contactId)`;
`groupUnreadCounts()` adds the group term; `primeUnreadCounts` emits `n + unseen` so a zero peek
with an unseen notice still emits 1. Clearing: `pollDirect(contactId)` / `pollGroup(groupId)` call
`markSeen`. Dot is a presence indicator, so +1 per unseen notice is fine. (Fallback if needed: ship
without it and keep the old test.)

### 2.8 Notifications — unchanged (no push, no banner); document it in the store kdoc.

## 3. UI spec
- Inline at its chronological slot, centered/muted, no bubble — existing style.
- Single `Text`: `"<Alias> may have taken a screenshot · 14:32"` (keep the existing hedged verb);
  if the capture day differs from today render `"Yesterday 14:32"` (tiny `formatNoticeTime` beside
  each `formatTime`).
- On open: Android `LaunchedEffect(contactId)` loads `groupMgr.screenshotNotices(contactId)` on IO
  into `messages`/`knownIds`; group screen mirrors. iOS `startPolling()` awaits
  `appState.loadScreenshotNotices(conversationId:)` once before the loop (`AppState` gains it next
  to `drainScreenshotNotices`, same background hop); `GroupConversationView` mirrors.
- Per tick: drain appends as today; drop rows with `isNotice && expiresAt <= now`
  (`DisplayMessage`/`ChatMessage`/`GroupDisplayMessage`/`GroupChatMessage` gain `expiresAt`).
- Unread: reuse `contact_unread_<id>` / `group_unread_<id>`.
- **a11y ids: reuse `screenshot_notice` / `screenshot_notice_group` on every row; no new ids.**
  Multiple rows counted with `$$`. Update the two doc comments in `AccessibilityIds.ts`.
- iOS: log the result of `sendScreenshotNotice` in `ConversationView.swift` instead of discarding it.

## 4. Wire / compat — keep the kind and the `{}` body; receiver semantics only
Bytes on the wire are identical. New sender → old receiver: burn-on-read as today (graceful).
Old sender → new receiver: full new behaviour (`t` is present). No negotiation, no new kind.
Ratchet / legacy-envelope rules untouched.

## 5. Purge / expiry hooks
- `MessageManager.kt` beside `GroupMetaKeys`: `ScreenshotNoticeMetaKeys { PREFIX = "ssn:" }`,
  `isScreenshotNoticeResidueForContact(key, contactId)` (conversation segment == contactId OR
  sender segment == contactId — covers a deleted contact's notices inside groups),
  `isScreenshotNoticeResidueForGroup(key, groupId)`. Update the classifier-enumerating kdoc. Do NOT
  add to `ratchetMetaKeysForContact` (exact-key list; these have a variable suffix).
- `DatabaseManager.deleteContact` / `deleteGroup` loops, `IosVaultDatabase.deleteContact` /
  `deleteGroup` loops, and commonTest `InMemoryVault`: add the predicate deletes.
- `wipeAllTables` already clears `_meta`; Android real wipe deletes the file. Group leave →
  `vault.deleteGroup` → covered. Blocked senders filtered in `list()` (iOS BlockStore).
- Lock/wipe RAM: existing `scrubInMemory` handling stays; the store holds no cache.

## 6. Implementation plan
Phase A — `ScreenshotNotice.kt` header/model; new
`ScreenshotNoticeStore.kt`; `MessageManager.kt` (timestamp plumbing, meta keys + classifiers,
kdocs); `GroupManager.kt` (own the store; persist in `collectDirectScreenshotNotices` and
`handleScreenshotNotice`; `handleControl(..., timestampMs)`; `screenshotNotices(conversationId)`
non-destructive list with alias resolution; `pruneExpiredScreenshotNotices()`; `markSeen` in
`pollDirect`/`pollGroup`; unseen term in the three unread functions; kdocs); `SessionManagers.kt`
hook; `DatabaseManager`/`IosVaultDatabase`/`InMemoryVault` purge additions; `VaultDatabase.kt`
kdoc; tests (§7).
Phase B (after A compiles): Android `ConversationScreen`,
`GroupConversationScreen`; iOS `ConversationView`, `GroupViews`, `AppState.loadScreenshotNotices`,
the send-result log; e2e `AccessibilityIds.ts` comments, the physical-device helper (not published)
`countScreenshotNotices()`/`waitForScreenshotNotices(n)`, spec step 2c extension; docs
(`HOW_IT_WORKS.md`, `docs/SECURITY_OVERVIEW.md` §8 new residue class, `vault-relay-internals.md` paragraph).
Phase C — compile both platforms, then the maintainer's physical-device suite (not published); optional
security review of the new residue.

## 7. Tests
- commonTest `ScreenshotNoticeStoreTest` over `InMemoryVault` with an injected clock: round trip;
  per-conversation isolation; ordering; cap eviction; expiry boundary (TTL−1 visible, TTL gone, key
  deleted by `list`/`record`/`pruneExpired`); clamp (future → receivedAt, >24 h old → receivedAt,
  in-window preserved minute-rounded); `markSeen` zeros `unseenCounts`; a second store over the
  same vault (restart) sees the same state.
- `MetaResiduePurgeTest`: contact-as-conversation, contact-as-sender-in-group, group predicate;
  negatives (prefix siblings, ratchet keys, `group_admin:`); `InMemoryVault` deletes exactly the
  matching keys.
- `ScreenshotNoticeTest`: round trip persists (`takenAt == roundTimestampToMinute(now)`); replay
  still 1; rewrite `groupNotice_doesNotTouchTheUnreadCounters` →
  `groupNotice_lightsTheUnseenCount_untilTheGroupIsPolled`; add
  `contactUnreadCounts_includesUnseenNotice_whenPeekIsZero`,
  `primeUnreadCounts_emitsUnseenNotice_onZeroPeek`; forward-compat tests unchanged.
- No migration (state it).
- e2e physical-device suite (not published) step 2c: also `toMatch(/\d{2}:\d{2}/)`; fire a second
  screenshot and `android.waitForScreenshotNotices(2)`; after the existing terminate+relaunch
  (~:488-493): `openFirstConversation()`, `waitForScreenshotNotices(2)` + time regex — this is the
  production failure mode (drain → kill → relaunch → open).

## 8. Risks
First persisted conversation-derived residue (ids + timestamps, ≤24 h) — document in
`docs/SECURITY_OVERVIEW.md` §8, rewrite the "no vault row" comments; expiry anchor deviation (sign-off);
unread touches peek/prime (fallback available); downgrade residue invisible to 0.8.179; old
receivers still burn-on-read; display time trusts the peer's clock within the window; persist
outside `bufferLock`, iOS `putMeta` throws → fail-soft; never `list()` per poll tick; copy choice
cosmetic; `GroupManager.kt` contains a non-UTF-8 byte (use `grep -a`).

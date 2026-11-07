# Move to new device — design & implementation plan

Status: IMPLEMENTED + DEVICE-VALIDATED 2026-09-09 (both platforms, 12 locales, 158 unit tests; cross:move-i2a and cross:move-a2i green on physical devices). Q1–Q3 answered with the plan defaults. Internals: `docs/vault-relay-internals.md` §Move to new device. Product decision: explicit in-app move over
the relay; no Apple/Google backup involvement. Read `docs/vault-relay-internals.md` before
touching anything in here.

## Goal

A user with a working Rún on phone A gets the same identity, contacts, groups and live
conversations on phone B — Android→iOS, iOS→Android, or same platform — with two taps on A and
a QR scan on B, and phone A ends up wiped. Nothing about the move weakens the forensic story:
no cloud copy, nothing readable on the relay, nothing left on A after the wipe.

## Why not OS backup (decided 2026-09-09)

- iCloud Backup is Apple-readable without Advanced Data Protection; Google/iCloud cloud
  acquisition is a standard forensic and legal-request path. It would reopen every door the rest of the design closes.
- The emergency wipe, wipe budget and Lever C cannot reach a cloud snapshot from yesterday.
- OS backup is same-platform only; the product needs Android↔iOS.
- The vault key is hardware-bound (CR-1, Lever B) and cannot be in a backup by construction.

## The facts the design rests on (verified against the source 2026-09-09)

1. **Messages are never persisted.** `Messages` is only ever deleted from. What persists is
   `Contacts` (sharedSecret, alias, trust, counters, vouching), `InboxIds` (inbox ids + caps,
   6 directions since the 2026-09-24 group-inbox pair — text + control + group, each
   inbound/outbound), `ContactGroups`/`GroupMembers`, and the `_meta` table (Double Ratchet state,
   `cap-pend`, `grp_*`, `ref_*`, `ssn:*`, UX throttles). Tens of KB for a normal user.
2. **The vault FILE is not portable.** Android keys SQLCipher in passphrase mode (PBKDF2 in the
   file header), iOS in raw-key mode — same 32 bytes, different on-disk key. Unifying was evaluated
   and rejected (bricks every iOS vault). So the bundle is a *logical* export of the records above,
   not the file. All record types are commonMain data models, so the encoding is platform-neutral.
3. **`provisionCredentialAndVault` refuses when a vault file exists** and mints its own random
   dbKey. Any "install a vault before first unlock" path is new brick-prone code. We do not build
   one: phone B provisions a *fresh* vault through the untouched normal path and imports records
   after its first unlock. No `vlt_*` blob is ever copied (they are device-key-AEAD'd and would
   produce the unescapable configured-without-a-database state).
4. **The anti-replay epoch is not a counter** — `sha256(sharedSecret‖"msg-epoch")`. There is
   nothing to bump. The per-contact counters are the knob; peers tolerate gaps, never reuse.
5. **Ratchet state is a fork hazard.** Two devices holding the same `dr/<id>/text` chain: one DH
   step on A orphans B's chain into `onCorruptReinit` (legacy re-bootstrap = forward-secrecy hole).
   Receiving also advances the chain, so A must stop *polling* too, not only sending.
6. **Groups carry no inbox material** (rosters are memberId+tags); a moved admin or member needs
   nothing group-specific. Referral records `ref_p/ref_a/ref_r` embed freshly minted inbox pairs
   that must stay valid until the handshake resolves or TTLs out (7 d idle / 28 d max).
7. **Push is keyed by inboxId** (`PUT/DELETE /inbox/{id}/push`, auth = that inbox's read cap);
   tokens are RAM-only. A must unregister before it wipes; B registers through its normal prompt.
8. **Relay limits:** `maxBlobBytes` 64 KiB, 200 blobs per inbox, TTL 1 s..7 d (`?ttl=`), 24 h
   default; client padding buckets up to 128 KiB; PoW mint ≤ 23 bits; no chunking primitive exists.
9. **Read-cap rotation exists** (`PUT /inbox/{id}/read-capability`, `resetRelayAccess`). Rotating
   the read (owner) cap kills a stale holder's ability to drain, delete or register push on that
   inbox without touching the peer's write cap — no announce, no ratchet step.
10. **QR infra exists** on both platforms (ZXing/CameraX, CoreImage/AVFoundation) with a shared
    `PairingPayload` codec (depth-1 JSON, all strings) and a paste-text fallback tab.
11. **Screenshot protection is window-level** on both platforms; a new screen inherits it.
12. **Provision happens with the running build's Argon2 cost** — a fresh provision on B avoids
    the debug-cost-carried-into-release trap by construction.

## Decisions (locked unless reopened)

- **D1 Logical bundle, fresh provision on B.** Export = records; B provisions normally (PIN or
  passphrase, tier, Lever B later), then imports. Never a file copy, never a `vlt_*` copy.
- **D2 A freezes at export.** Export puts A into a persisted `mig_frozen` state: session torn
  down, no polls, no sends, push unregistered, Tor stopped. A leaves the state only by wiping or
  by an explicit cancel that is refused once B has drained the bundle (detected by `peek` on the
  transfer inbox: drained/404 ⇒ B has it).
- **D3 Counter jump on import.** B adds +10 000 to `outboundCounter`, `outboundCtlCounter` and
  (since 2026-09-24) `outboundGrpCounter` for every contact in the import transaction. Cheap
  insurance against anything A sent between the snapshot and the freeze.
- **D4 Read-cap rotation on B, no re-mint in phase 1.** After import B rotates the read cap of
  every inbox direction it now OWNS — `inbound`, `inbound-ctl` and (since 2026-09-24) `inbound-grp`,
  i.e. every entry in `OWNED_READ_DIRECTIONS` (skipping inboxes referenced by pending `ref_*`
  records). Peers are untouched. A wiped A holds nothing; an unwiped A holds sharedSecrets and
  peer write caps — the same exposure as any unwiped stolen phone today, closed by the wipe step.
  Full re-mint + ratchet-sealed announce + 7-day redrive is a phase-3 hardening, not a blocker.
- **D5 Transport = one dedicated relay inbox, short TTL, one-shot.** A mints a fresh inbox pair
  (only the main inbox is used), uploads fixed-size sealed chunks with `?ttl=1800`, `X-No-Push`.
  B drains with a bare `GET` (destructive) and then `DELETE`s the inbox under the read cap.
- **D6 Sealing.** `code` = 20 CSPRNG bytes (Base32, 32 symbols, same shape as the recovery
  code, no stretching — 160 bits is the floor).
  `k = HKDF-SHA256(ikm=code, salt=inboxIdBytes, info="run:migrate:v1", 32)`.
  Per chunk: AES-256-GCM, AAD = `inboxId ‖ bundleId ‖ index ‖ count ‖ "run:migrate:chunk:v1"`.
  Every chunk the same padded size (only the count leaks). Distinct labels from
  `LABEL_RECOVERY_KEK` / `CTX_RECOVERY` so a captured bundle can never be confused with a `vlt_rc`.
- **D7 QR carries the whole handle:** `{"v":"1","inbox":<id>,"rcap":<read cap>,"code":<base32>,
  "bid":<bundleId>}` — same depth-1 all-string JSON discipline as `PairingPayload`. The same text
  is available behind a "Show as text" toggle for the paste path. Known limitation: a screenshot of A's
  screen is the secret, exactly as for the pairing QR; FLAG_SECURE/ScreenshotProtection apply.
- **D8 Recovery code and Lever B do not move.** B has no recovery code until the user enables
  the Secure tier there; the flow says so. On A, `vlt_rc`/`vlt_rp` are left untouched (deleting
  mid-export re-enters the silent-write copy-then-remove brick window) and die with the wipe.
- **D9 The wipe of A is local and user-confirmed.** Never relay-triggered (a hostile relay would
  own a remote-wipe button). B must be fully usable without A's wipe ever happening.
- **D10 UX throttles reset.** `onboard_push_prompt_v1`, `update_nudge_v1`, `review_prompt_v1`,
  clean-leave, locale, inactivity anchors, PIN-attempt state: none of it travels.

## What is in the bundle (`MigrationBundle`, commonMain)

```
{ "v":1, "schema":10, "from":"android|ios", "created":<epochMs>,
  "contacts":[ContactRecord…],           // sharedSecret base64, counters as stored
  "inboxes":[InboxIdRecord…],            // all six directions (since 2026-09-24), caps verbatim
  "groups":[GroupRecord…], "members":[GroupMemberRecord…],
  "meta":{ key: value … } }              // ALLOWLISTED prefixes only
```

`_meta` allowlist: `dr/`, `dr-rxc/`, `dr-on`, `dr-intent`, `dr-rxseen`, `dr-rxlock`,
`dr-legacyfb`, `m2-chseen`, `ib-bound-seen/`, `cap-pend/`, `grp_` (incl. `grp_ctl_pend:`),
`grp-ann/` (the group-inbox backfill throttle, since 2026-09-24), `ref_`, `ssn:`. Everything else
is dropped. `ratchetMetaKeysForContact` is the source of truth for the `dr*` set — extend the
allowlist from it, do not duplicate the list.

Denylist that must be asserted by a test: no `vlt_*`, no `pin_*`, no `inactivity_*`,
no `vlt_txn_journal`, no `run.crypto.provider.key`, no KDF params, no verifier.

Chunking: serialize → pad to a multiple of `CHUNK_PLAINTEXT_BYTES` (60 000; padded envelope
lands in the 64 KiB bucket, under `maxBlobBytes`) → seal each chunk → `POST`. Cap: 200 chunks
= 12 MB; refuse above that with an honest error (unreachable for a real vault).

## Protocol

Phone A (unlocked, in Settings → Move to new device):
1. Explain screen (what moves, what does not: recovery code, Lever B, notifications need to be
   turned on again; A will stop working now).
2. Confirm ⇒ `MoveManager.beginExport()`:
   a. `unregisterPushBestEffort()` over `allPushableInboxes` (existing opt-out path), wait ≤ 30 s.
   b. Persist `mig_frozen=1` in `_meta` **before** anything else, then tear the session down
      (stop polling, drop MessageManager). From here A never polls or sends again.
   c. Mint the transfer inbox (`mintInbox`, existing PoW path, budget as today).
   d. Build the bundle from the open vault, seal, upload chunks (`?ttl=1800`, `X-No-Push`).
      Persist `mig_handle` (inbox id + read cap + bundleId + chunk count) in the vault `_meta`
      table (encrypted, wiped with the vault) so A can resume after process death; the code
      itself is RAM-only (secureWipe on exit), so after a process death A can only re-issue
      (fresh bundle + fresh code) or wipe.
   e. Show the QR screen. Poll `peek` every 10 s: pending>0 ⇒ "waiting"; 404 or drained ⇒
      "Moved" state.
3. "Moved" ⇒ offer **Wipe this phone** (calls `performEmergencyWipe(deniable=false)` /
   `emergencyWipe(deniable: false)` — crypto-erase-first, lands on setup) or **Keep it off** (A
   stays frozen; every launch shows the frozen screen with the same two choices).
4. Cancel (before B drains): `DELETE /inbox/{id}` under the read cap, clear `mig_frozen` and
   `mig_handle`, restart the session. Refused with a clear message if `peek` says drained/404.
5. Stop Tor when leaving the QR screen; no network after the wipe.

Phone B (fresh install):
1. Setup chooser: **Set up as new** / **Move from another phone**.
2. Move ⇒ scan QR (or paste text) ⇒ parse `MoveHandle` into RAM only. No persistence: process
   death means rescan; the bundle waits on the relay for its TTL.
3. Normal onboarding continues unchanged: PIN/passphrase, tier, provision, first unlock.
4. First post-unlock action with a handle in RAM: progress screen "Fetching → Importing →
   Securing".
   a. Tor up, `GET /inbox/{id}` (drain) under `rcap`; verify count/AAD/all indices; reassemble;
      decrypt; parse; reject on any failure with the bundle still on the relay if not yet
      drained... (drain is destructive — see "Failure handling").
   b. Import transaction: upsert contacts (+10 000 to both outbound counters), inboxes, groups,
      members, allowlisted meta; write `mig_imported=<bundleId>` last.
   c. `DELETE /inbox/{id}` under `rcap`.
   d. Rotate read caps of all inbound + inbound-ctl + inbound-grp inboxes (skip inboxes
      referenced by pending `ref_*` records). The full to-rotate list is written to
      `mig_rotate_pending` right after the import commits, before the first rotation, and each
      entry is pruned when its rotation lands, so a failed referral scan, a lock mid-pass or a
      process death leaves the remainder for the control sweep (which re-applies the referral
      filter and rotates nothing when that scan fails); never fatal.
   e. Route to the contact list; the normal push prompt follows.

### Failure handling

- Drain is destructive, so B **assembles and decrypts in RAM before the import transaction** and
  keeps the drained chunks in RAM until `mig_imported` is written. If B dies between drain and
  commit, the bundle is gone: A is still frozen with the handle, so the user re-runs step 2 on A
  ("Show again" re-uploads a fresh bundle under a fresh code; A's vault is unchanged because A
  never wrote anything since the freeze). This is why A keeps the vault until the user wipes.
- Wrong code / tampered chunk ⇒ AEAD failure ⇒ "Could not read the transfer" and the same
  re-run path. No retry counter needed: 160-bit code, and the relay holds only ciphertext.
- Bundle `schema` newer than B's `DATABASE_VERSION` ⇒ refuse with "update Rún on the new phone".
  Older ⇒ import runs the same column defaults the DB migration would.
- Import is idempotent (upserts keyed by contactId/inboxId/groupId/meta key), so a partial
  import followed by a re-run converges.

## Threat review (to be adversarially verified before shipping)

- **Relay:** sees a fresh inbox, N identical-size blobs, a drain, a delete. Learns bundle size
  bucket and timing. Cannot read, reorder, truncate or splice (AAD binds index/count/bundleId).
- **Shoulder surfer / screenshot of A:** owns the handle = can drain the bundle first. B then
  fails to drain (404), the user sees it, A is still intact and frozen; re-run with a new code
  and the attacker's copy is a snapshot whose ratchets B will outrun. Rotation (D4) kills the
  attacker's read caps. Same class as a photographed pairing QR; accepted.
- **Forensics on A after wipe:** nothing new — the frozen state and handle are `_meta` rows
  inside the vault, gone with the crypto-erase. Add them to the residue tests.
- **Forensics on A before wipe (frozen):** the vault is intact until the user wipes; this is
  the same exposure as an unlocked phone today and is why the flow pushes hard to wipe.
- **Forensics on B:** a normally provisioned vault; the handle never touched disk; drained
  chunks lived in RAM only.
- **Unlocked-session holder (2026-10-21):** exporting used to need only an open vault, so
  anyone holding an unlocked session could ship the whole vault to their own phone and receive
  every future message, defeating MAXIMUM's forced re-auth. The export now requires re-entering
  the current PIN/passphrase (and, on a Lever B vault, a fresh strong biometric) before anything
  is frozen or uploaded. `MoveManager.beginExport` refuses without a single-use, 5-minute
  verification token (`MoveExportAuthGate`), so a UI bypass cannot skip it; a wrong entry counts
  against the daily change-PIN budget and the cap wipes, exactly like change-PIN. Re-issue
  ("Show again" on the frozen page, Retry on the failed page) is gated the same way: it mints a
  new transfer inbox, uploads a new full-vault bundle and shows a fresh code, so an exemption
  would let whoever holds the unlocked frozen phone export the vault without the credential.
  Every `runExport` consumes the token; both UIs run the credential prompt before re-issuing.
- **Two live copies:** prevented by D2 (freeze before upload) and made recoverable by D3.

## Files to touch

commonMain (`shared/src/commonMain/kotlin/com/vg/run/`)
- `MigrationBundle.kt` (new): codec, allowlist/denylist, chunking, sealing (HKDF + AES-GCM,
  fixed-size chunks), `MoveHandle` QR codec.
- `MoveManager.kt` (new): `beginExport`, `pollTransferState`, `cancelExport`, `importBundle`,
  `rotateOwnedReadCaps`, frozen-state accessors; meta keys `mig_frozen`, `mig_imported`.
- `MessageManager.kt`: expose mint/POST/drain/DELETE/read-cap-rotate for a non-contact inbox
  (small wrappers around existing functions; no protocol change).
- `VaultDatabase.kt` (+ Android/iOS impls): `exportAllForMigration()` /
  `importFromMigration(...)` inside one transaction; bulk meta read by prefix.
- `SessionManagers.kt`: control sweep retries read-cap rotation and `mig_frozen` guard (no
  polling while frozen).
- Wipe residue: every `mig_*` key lives in `_meta` (inside the vault, wiped with it);
  `MetaResiduePurgeTest` gains the `mig_*` keys. The shared contract is
  `shared/src/commonMain/kotlin/com/vg/run/MoveContracts.kt` (types, meta-key policy, the
  transport and session-control seams, `MoveManagerApi`).

androidApp
- `MainActivity.kt` routing: setup chooser before `"setup"`; frozen screen before `"pin"` when
  `mig_frozen`. `RunViewModel`: `MoveManager` wiring, post-unlock import trigger.
- `MoveToNewDeviceScreen.kt` (new): explain → QR/text → waiting → moved/wipe.
- `MoveFromDeviceScreen.kt` (new): chooser entry, scanner (reuse `ScanCodeTab` internals),
  progress. `ContactListScreen.kt`: menu item `move_to_new_device_button`.
- `strings_move.xml` (new area).

iosApp
- `ContentView.swift` routing mirror; `AppState.swift` wiring; `MoveToNewDeviceView.swift`,
  `MoveFromDeviceView.swift` (reuse `QRScannerView`, `generateQRCode`); `ContactListView.swift`
  settings row `move_to_new_device_button`; `.background` clears the QR and the code.

a11y ids (both platforms, identical): `move_to_new_device_button`, `move_explain_continue`,
`move_qr_image`, `move_show_text_toggle`, `move_handle_text`, `move_waiting_status`,
`move_done_wipe_button`, `move_done_keep_button`, `move_cancel_button`, `setup_choose_new`,
`setup_choose_move`, `move_scan_view`, `move_paste_field`, `move_paste_submit`,
`move_progress_status`, `move_error_text`, `move_error_retry`.

Relay: no change required. Optional later: a dedicated `/transfer` inbox class with a 30-minute
hard TTL so transfer inboxes never linger at the 30-day bootstrap TTL when B never comes.

## Testing

commonTest
- Bundle round-trip on synthetic vault state (contacts with ratchets, groups, pending referral),
  cross-"platform" tag, schema older/newer.
- Allowlist/denylist assertion (no `vlt_*`, no `pin_*`, no inactivity, no journal).
- Sealing: wrong code fails; swapped chunk index fails; truncated count fails; every chunk equal
  size; relay-side 64 KiB limit respected for 200 chunks.
- Import idempotency; counter jump; partial import re-run converges; `mig_imported` last.
- Freeze semantics: no send/poll while `mig_frozen`; cancel refused after drain.
- Read-cap rotation skips inboxes referenced by pending `ref_*`.
- Residue: `mig_*` keys in the purge lists (extend `MetaResiduePurgeTest`).

Instrumented / platform
- Android `WipeRoutine` clears `mig_handle`; iOS `IosUserDefaultsKeys.all` contains it.

Physical e2e (two new device jobs, three devices each so message continuity is proven)
- `cross:move-a2i`: old = an Android phone, new = an iPhone, peer = a second iPhone. Pair peer↔old, exchange a
  ratcheted message, move, then peer→new and new→peer both deliver (relay log `POST blob` +
  `GET retrieve` on the new-owned inbox), old shows the frozen screen, wipe lands on setup.
- `cross:move-i2a`: old = an iPhone, new = an Android phone, peer = a second iPhone.
- Both are added to the device-suite job list; `cross:move-a2i` shares phones with the push suites, so it runs in the group-suite lane.

## Sequencing

1. commonMain codec + sealing + tests (no UI).
2. `MoveManager` export/import against the vault interface + tests; wipe-residue lists.
3. Android UI end to end; iOS UI end to end (one shared decision sheet = this doc); `/l10n`.
4. Adversarial review of the threat model (three angles: relay-side, old-device residue,
   fork/replay).
5. Physical e2e both directions; device-suite integration; What's New.

Estimate: the referral feature's order of magnitude — roughly 2–3 working days
plus device validation.

## Open questions

- Q1 Should "Keep it off" exist, or is wiping A mandatory once B has imported? (Plan: offer both;
  frozen A is at least as safe as today's unlocked phone.)
- Q2 TTL for the transfer inbox: 30 min (plan) vs longer for users who set up the new phone
  hours later. Longer TTL = longer window for a photographed QR; A can always re-issue.
- Q3 Phase 3 (re-mint + announce to every contact) now or later? Later is the plan.

## Adversarial verification (2026-09-09)

- Relay-side attacker: CONFIRMED safe (AAD binds inbox/bundle/index/count; fresh inbox + code per
  issue; no partial decode reaches the DB; nothing logs the code or cap).
- Fork/replay after import: one gap found and fixed — `ib-bound-seen/` was not in the allowlist;
  `MoveMetaPolicyPinTest` now pins the allowlist to `ratchetMetaKeysForContact`.
- Old-device freeze: REFUTED as first built — the plain 1:1 send path bypassed the provider gate.
  Fixed by gating inside `MessageManager`; 13 tests.
- Known limitations: a MessageManager instance the session does not return
  through `transport()` keeps a stale cached `false` until replaced (durable key wins on any new
  reader); a failed/timed-out push unregister cannot be retried from the frozen phone (the new
  phone's rotation evicts the token instead).

## Device validation (2026-09-09, physical devices)

| Suite | Old | New | Peer | Result |
|---|---|---|---|---|
| cross:move-i2a | iPhone | Android phone | second iPhone | green (11m46s, after one harness-caused retry) |
| cross:move-a2i | Android phone | iPhone | second iPhone | green first attempt (20m41s) |

Proven on device: export + sealed upload, drain + import into a freshly provisioned vault,
message continuity peer→new and new→peer, old phone sees the drain and self-wipes to setup.
The same Android phone served in both directions.
Three harness lessons, all fixed in the suite: a stale device build hides the new UI (uninstall-
first is mandatory); a runtime-permission dialog left over from a scanner screen survives a
force-stop and hides the chooser; the first-unlock push prompt appears right after the import
and occludes the Android a11y tree.

Follow-ups: request CAMERA lazily on the Android move-from screen (the paste path needs no
camera; today the scanner mounts on entry); a full pass of all physical-device suites, because the setup chooser
touches every onboarding path; phase 3 (re-mint + announce).

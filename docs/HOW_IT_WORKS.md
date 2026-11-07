# How Rún works

A privacy-first messenger built with Kotlin Multiplatform
(shared core) + native UIs (Android Compose, iOS SwiftUI). This document
summarises the architecture and subsystems, then walks every user journey as a
flow diagram annotated with the network calls and payloads.

> Scope: behaviour as implemented at the time of writing. File references are
> pointers, not contracts — verify against current code before relying on a line
> number.

---

## 1. The one-paragraph model

A single PIN opens one **SQLCipher-encrypted** vault, with the database key
bound to **both** the PIN and a device key (CR-1) — extracting either one alone
cannot open it. The device-key factor is **hardware-*rooted at rest*** (not
hardware-*backed* by default — see §3.2); the opt-in **Lever B** makes it
hardware auth-bound. All relay traffic goes **over Tor** to a custom `.onion`
relay using a **capability-based inbox protocol** — there is no account, no
phone number, no central group object. Messages are **end-to-end encrypted**,
**length-padded**, **never written to disk**, and **wiped from RAM** the instant
the app backgrounds. Creating an inbox costs **proof-of-work** (anti-spam).
Groups are pure client-side fan-out over 1:1 inboxes.

---

## 2. Architecture

| Module | Role |
|--------|------|
| `shared/commonMain` | Protocol, crypto interfaces, `VaultSelector`, `MessageManager`, `GroupManager`, `PowSolver`, data models. Platform-agnostic. |
| `shared/androidMain` | `actual` impls: Tink + Android Keystore, OkHttp, SQLCipher, Tor via `ProcessBuilder`. |
| `shared/iosMain` | `actual` impls bridged to Swift via `*BridgeHolder`s; `IosAppController`; `runcrypto` cinterop. |
| `androidApp` | Single-activity Compose UI + device-hardening utilities. |
| `iosApp` | SwiftUI UI, `TorManager.swift`, `SwiftTorHttp.swift`, Swift bridge impls. |

**expect/actual** keeps platform-specific crypto/transport/storage out of common
code. On iOS, `AppState.init` must register every bridge holder
(`AesGcmBridgeHolder`, `KeychainBridgeHolder`, `DatabaseBridgeHolder`,
`HttpBridgeHolder`) **before** constructing `IosAppController` — common code
calls them synchronously during construction.

---

## 3. Subsystems

### 3.1 Encrypted vault
- `VaultSelector` gates the entered PIN: it derives a verifier (**Argon2id**,
  memory-hard — the current KDF; legacy PBKDF2 vaults still verify with the KDF
  they were written with) and constant-time-compares it; on a match it unwraps
  the SQLCipher passphrase and opens the vault. A wrong PIN matches nothing and
  opens nothing.
- One SQLCipher DB: `run.db`. Storage-key names are opaque (`vlt_a`…) rather than
  descriptive. (Historical note: Rún previously shipped a second "decoy" vault
  for plausible deniability; that feature was removed. `VaultSelector` carries a
  one-time purge of leftover decoy credential/DB-key blobs, and the wipe paths
  still delete a stale `run_b.db`, so installs provisioned before the removal are
  cleaned up.)

### 3.2 Crypto & keys (CR-1: PIN **and** device key both required)
```
PIN ─Argon2id(salt,64MiB,t=3)→ stretched ─┬─SHA256(‖"vault:cred-verifier")→ verifier
                                          └─SHA256(‖"vault:dbkey-kek")    → KEK
verifier, AES-GCM(dbKey, KEK)  ── wrapped again by the DEVICE KEY (AEAD) ──► stored
```
- KDF: **Argon2id, 64 MiB × 3 passes** (`KDF_VERSION_3`, the current KDF). Legacy
  vaults verify with the KDF they were written with (v2 PBKDF2-600k / v1
  PBKDF2-210k) — upgrade-only, no downgrade.
- Device key: Android Keystore (`setUnlockedDeviceRequired`, StrongBox-preferred)
  wrapping a Tink AEAD keyset; iOS Keychain (`WhenPasscodeSetThisDeviceOnly`,
  keybag/UID-bound). This is **hardware-*rooted at rest*** — extracting the
  stored blob alone can't open a vault (the PIN is still needed). But by default
  (Lever B off) the device-key half is *not* Secure-Enclave-resident: the Tink
  keyset is software once unwrapped in RAM (iOS is keybag-bound), so on a **live,
  unlocked** device the default device-key factor is software-reachable and
  at-rest security leans on the PIN at the memory-hard KDF above. Opt-in **Lever
  B** binds the DB key to a hardware auth key (Android `BiometricPrompt`-gated
  Keystore RSA / iOS Secure Enclave ECIES) — that path is genuinely
  hardware-*backed*. Domain separation means a leaked verifier never yields the KEK.
- Primitives (`PlatformCrypto`): AES-256-GCM (12-byte random IV ‖ ct ‖ 16-byte
  tag), Argon2id (current KDF), PBKDF2-SHA256 (legacy-vault verify), HMAC-SHA256,
  constant-time compare, power-of-two padding.
  Android = `java.security`/Tink; iOS = CryptoKit/CommonCrypto via bridge.

### 3.3 Tor & transport
- **Android**: spawns the Tor binary via `ProcessBuilder` (avoids the API-34
  `TorService` bug), watches stderr for bootstrap % and `SOCKS opened on …:NNNN`,
  90 s timeout. torrc: `SafeSocks 1`, `SafeLogging 1`, `AvoidDiskWrites 1`,
  per-session dirs, log deleted after bootstrap.
- **iOS**: Tor.framework thread + `TorController`; `SwiftTorHttp` does a manual
  **SOCKS5h** handshake (remote DNS) + raw HTTP/1.1 over `NWConnection`, because
  `NSURLSession` resolves DNS locally and can't reach `.onion`. Directory
  bootstrap is stock (Tor's compiled-in fallback list), same as Android — the
  old curated `FallbackDir` override was removed 2026-09-15.
- **`PlatformHttpClient`**: `direct()` vs `torProxy(port)`. A `transportGuard`
  **fails closed** on every request: `.onion` is refused on the direct path
  (DNS-leak guard) and non-`.onion` is refused on the SOCKS path. Redirects off,
  default User-Agent/Accept-Encoding stripped (anti-fingerprint), 16 MiB response
  cap. Release builds **refuse a clearnet relay**; only dev/emulator/simulator
  override to `10.0.2.2`/`localhost:8080`.
- **Android lifecycle**: `RunViewModel` owns one in-process `TorManager`; its
  `Connected` state carries the SOCKS port, which (re)creates `MessageManager`
  via `torProxy(port)`. Tor only starts when the relay URL is `.onion`.

### 3.4 Relay protocol & messaging (`MessageManager`)
Custom, capability-authenticated, non-REST API (all over Tor):

| Method + path | Auth header | Purpose |
|---|---|---|
| `POST /inbox` | `X-PoW-Token`,`X-PoW-Counter` | **Mint** an inbox (PoW handshake) |
| `POST /inbox/{id}` | `X-Write-Capability` | Append an encrypted blob |
| `GET /inbox/{id}` | `X-Read-Capability` | Drain pending blobs |
| `GET /inbox/{id}/peek` | `X-Read-Capability` | Non-destructive pending **count** |
| `DELETE /inbox/{id}` | `X-Read-Capability` | Delete inbox |
| `PUT /inbox/{id}/{read,write}-capability` | `X-Read-Capability` + new cap | Rotate caps |

- **Errors**: `404 "request rejected"` collapses *gone / wrong-cap / locked* into
  one indistinguishable response — a persistent 404 **streak (4)** flags the contact
  for **re-pair** (self-heal); `429` is **retried with backoff** (6–12 s, not
  terminal); `400` during mint = PoW challenge.
- **Wire blob** = `AES-256-GCM( key = sha256(sharedSecret), aad =
  sha256(key ‖ "message-aead"), plaintext = pad(envelope) )`. Output is
  `IV(12) ‖ ciphertext ‖ tag(16)`, base64 on the wire.
- **Envelope** (inside the AEAD): `{"e":epoch,"c":counter,"t":millis,"m":"text"}`
  (+ group fields `g,h,k,b`). Messages **without** both `e` and `c` are dropped
  (no plaintext/legacy downgrade).
- **Padding**: power-of-two buckets 256 B → 128 KB (`len32 ‖ payload ‖ random`),
  hiding plaintext length from the relay and any observer.
- **Anti-replay**: epoch-scoped, strict-monotonic per-contact counters; the
  bumped counter is **persisted before send**; receiver sorts a drain by counter
  and drops `≤ last`; a forward jump sets a `sequenceGap` flag. Text and control
  channels have independent counter spaces.
- **Two inboxes per pairing** (inbound = we poll, outbound = we send) avoid echo
  loops. Inbound/outbound caps never overlap; our read cap is never shared.

### 3.5 Proof-of-work minting (`PowSolver`)
SHA-256 over `"<nonce>:<counter>"`; find a counter whose hash has ≥ `difficulty`
leading zero bits. Difficulty ceiling **23 bits** (matches relay cap; honest
solves ≤ 22). Solved in parallel across all cores (Android threads, iOS Kotlin/
Native `Worker`s) with a monotonic-clock deadline. Budgets: **8 s per solve**,
**20 s aggregate** across re-solves + transient retries per mint. Transient Tor
drops retry (1.5–5 s backoff); a `400` re-challenge re-solves (≤3); `429` is retried
with backoff; difficulty-too-high / timeout / abort are terminal. A pair (text +
control) is
minted **sequentially** so two grinds don't oversubscribe cores.

### 3.6 Contacts & groups
- A contact = `{contactId, sharedSecret(32B), alias, mnemonic, counters}` plus
  `InboxIdRecord`s (`inbound`/`outbound`/`inbound-ctl`/`outbound-ctl`, each with a
  43-char capability). States: **stale** (re-pair), **pending** (awaiting peer's
  inbox announce), **fully paired**.
- **Groups are client-side only** — the relay never sees a group *object*, and
  never learns the group name, membership or content. A group message is fanned
  out as individual 1:1 sends. Note this is not invisible to the relay: the
  fan-out is k POSTs into k distinct inboxes in one window (plus an
  equal-cardinality control burst), and opening a group re-drains those same k
  inboxes, so group **existence and size** are observable — a known limitation of
  client-side fan-out. Members are admin-assigned random IDs; a receiver maps an ID to
  a contact via a **pairwise HMAC tag** `HMAC(sharedSecret,"grp-tag:"+groupId)`.
  Control messages (`invite`/`join`/`roster`/`leave`) over the control channel
  manage membership; a 12-char `membershipHash` detects roster splits.

### 3.7 Device hardening
- **Screenshots/recording**: Android `FLAG_SECURE`; iOS `isSecureTextEntry`
  blanking + `UIScreen.isCaptured` cover + a synchronous black cover on
  resign-active (app-switcher snapshot). A single iOS still-screenshot can't be
  blocked (known limitation).
- **Lock on background**: Android finishes the activity → ViewModel cleared →
  vault/MessageManager nulled, Tor stopped, key wiped; iOS `lock()` clears nav +
  sheets + in-RAM key. PIN required on every return. Conversations hold messages
  in RAM only and purge on close/background.
- **Throttle/wipe**: consecutive wrong PINs **or** 30 wrong/24 h (rolling,
  clock-rewind-proof) → emergency wipe; change-PIN flow has its own daily cap;
  inactivity auto-wipes (checked before UI renders, deferred while device
  locked). The consecutive-wrong budget and the inactivity window are
  **per protection level** (`ProtectionLevel.kt:52-64` — Decent 10 / 180 d,
  Secure 8 / 90 d, Maximum 5 / 7 d); only the 30-per-24 h backstop is a
  universal constant. Wipe is **erase-first**: destroy the Keystore/Keychain master key
  (crypto-erase) *then* delete DBs/prefs/Tor dirs — irreversible even if killed
  mid-wipe.
- **Root/jailbreak**: detected at launch → "Device Compromised" screen, all
  access blocked (simulator bypass for tests).

---

## 4. User journeys — flow diagrams with network + payload

Legend: `═══►` over-Tor HTTP (to the `.onion` relay) · `───►` local/UI · `�llll`
local CPU work · `{…}` JSON · all blobs are base64 of `AES-GCM(IV‖ct‖tag)`.

### 4.1 First run — PIN setup (LOCAL ONLY, no network)
```
User                         App (VaultSelector / CryptoProvider)
 │  choose pin   ───────────► 
 │  confirm pin  ───────────►  �llll provision vault:
 │                            Argon2id(pin,64MiB×3) → verifier+KEK; random 32B dbKey;
 │                            wrap(dbKey,KEK); device-key AEAD; create run.db (SQLCipher)
 │                            ▟ auto-unlock with the saved pin → contact list
 ▼
No bytes leave the device. The vault file exists before setup completes.
```

### 4.2 Unlock (LOCAL ONLY, no network)
```
User                         App
 │ enter 6-digit pin ──────► durably ++ wrong-counter BEFORE eval (force-quit safe)
 │                           evalCredential(pin)     (Argon2id v3 — or the legacy KDF for v1/v2 — constant-time)
 │                           ├─ match → reset counter → unwrap dbKey → open vault → contacts
 │                           ├─ no match → shake; exp-backoff 1/2/4/8s;
 │                           │            5 consecutive OR 30/24h → EMERGENCY WIPE
 │                           └─ correct-but-IO-error → roll counter back, retry
 ▼
```
After a successful unlock the app starts Tor (if relay is `.onion`) and the
background pollers (§4.6).

### 4.3 Add contact / pairing  — mint (PoW) + QR + in-band announce
**Step A — mint my inbox pair (PoW), runs as soon as Add-Contact opens.**
The "Add contact" button is disabled until the relay is reachable.
```
App A ═══ POST /inbox  (empty body, no PoW headers) ══════════════►  Relay
App A ◄═ 400 {"nonce","token","difficulty":D≤23,"ttlSeconds":120,"algorithm":"sha256"} ═
App A ▟▟▟▟ grind all cores: find k where sha256("nonce:k") has ≥D leading-0 bits
          (≤8s/solve, ≤20s aggregate, ≤23 bits)
App A ═══ POST /inbox  X-PoW-Token: token   X-PoW-Counter: k ══════►  Relay
App A ◄═ 201 {"inboxId","readCapability","writeCapability","expiresAt"} ═
          … repeated SEQUENTIALLY for the CONTROL inbox (second pair member) …
```
**Step B — exchange via QR (no network).** A's QR encodes A's freshly-minted
coordinates + a secret half:
```
QR_A = {"inbox":<A textInbox>,"wcap":<A text WRITE cap>,
        "cib":<A ctrlInbox>,"cwcap":<A ctrl WRITE cap>,"secret":<A secret>}
A ──show QR──► B scans (camera, no frames buffered)
B: sharedSecret = sha256( sort(secret_A, secret_B) )
B records: INBOUND = B's own inbox (B polls it) ; OUTBOUND = A's inbox+wcap (B→A)
```
**Step C — close the loop with an encrypted in-band "inbox announce"** so the
reverse direction (A→B) is populated without A having to scan. This is a normal
control-channel message (counter-protected, replay-safe):
```
B ═══ POST /inbox/<A ctrlInbox>   X-Write-Capability: <A ctrl wcap>   ═══►  Relay
      body = AES-GCM blob of envelope:
        { "e":epoch,"c":1,"t":t, "k":"inbox",
          "b":"{ib:<B inbox>, wc:<B write cap>, cib:<B ctrlInbox>, cwc:<B ctrl wcap>}" }
A (next control poll) drains it → upserts OUTBOUND(B) → both sides fully paired.
```
Until the announce lands, the contact shows **pending** ("waiting for their
inbox") and can receive but not send. `announceInbox` is retried with jitter and
survives screen dismissal; applying it is idempotent.

### 4.4 Send a 1:1 message
```
User types "hi" ─►  App builds envelope, bumps & PERSISTS counter, pads, encrypts:
   env = {"e":epoch,"c":n,"t":nowMs,"m":"hi"}
   blob = AES-GCM( key=sha256(sharedSecret), aad=sha256(key‖"message-aead"),
                   pad2pow(env) )          // 256B..128KB bucket
App ═══ POST /inbox/<peer OUTBOUND inbox>   X-Write-Capability: <peer write cap> ═══► Relay
App ◄═ 2xx ═  → bubble shown (right-aligned). On code≤0 (Tor drop): surfaced as unsent.
```
Send is gated on relay reachability. No read receipts / typing indicators exist.

### 4.5 Receive / poll a conversation
```
Conversation open: loop every 2–6s (jittered):
App ═══ GET /inbox/<my INBOUND inbox>   X-Read-Capability: <my read cap> ═══►  Relay
App ◄═ 200 {"blobs":["b64…","b64…", …]}  (≤2048 blobs/poll) ═
For each blob:  base64-decode → AES-GCM-decrypt → unpad → parse envelope
  drop if: bad b64 / auth fail / no {e,c} / wrong epoch / counter ≤ last  (replay guard)
  accept (sorted by counter); counter > last+1 ⇒ sequenceGap flag
  → 1:1 text surfaced as a left bubble; control msgs applied silently
Drain is NON-destructive (relay retains until TTL), so unread survives app close.
```
Unread **badges** come from the non-destructive `GET …/peek → {"pending":N}` run
by the background poller (§4.6), so counting never consumes unseen texts.

### 4.6 Background pollers (started after unlock)
```
Relay-reachability probe   every 8–12s  → drives runestone "lit/dim" + UI gating
Control-channel poll       every 25–45s  → GET each contact's INBOUND-CTL inbox:
   ═══ GET /inbox/<inbound-ctl> X-Read-Capability:… ═══► Relay ◄═ {"blobs":[…]} ═
   applies: inbox-announce / group invite / roster / leave  (never shown as bubbles)
   + peek sweep for unread badges
```
This is why group invites and membership changes appear on every member's device
without opening any conversation.

### 4.7 Create a group & send (client-side fan-out, relay sees only 1:1)
```
Admin picks name + members (all must already be paired) ─► local GroupRecord,
  assigns each a random memberId; computes pairwise HMAC tags.
For each member M:
  Admin ═══ POST /inbox/<M outbound-ctl> X-Write-Capability:… ═══► Relay
        blob env: { "k":"invite", "g":groupId, "h":membershipHash,
                    "b":"{n:name, ep:1, adm:<adminId>, you:<M's id>, mem:[ids…]}" }
Member ── on control poll ──► auto-joins, replies with a tag list (padded to hide
        its contact count) via "join"; admin re-rosters everyone via "roster".

Group text "yo":  fanned out as N independent 1:1 sends, each:
  ═══ POST /inbox/<member outbound> X-Write-Capability:… ═══► Relay
      env = {"e":…, "c":…, "t":…, "g":groupId, "h":membershipHash, "m":"yo"}
Receiver maps sender's pairwise tag → contact; checks membershipHash (split detect).
```
No central group object exists on the relay; leaving/removing is best-effort
pairwise notices + local state.

### 4.8 Emergency wipe (LOCAL ONLY)
```
Trigger: N consecutive wrong PINs | 30 wrong/24h | change-PIN abuse cap | idle past window | tamper
        (N and the idle window are PER LEVEL — Decent 10/180d, Secure 8/90d, Maximum 5/7d)
 ▟ erase Keystore/Keychain MASTER KEY first  → every encrypted blob now unrecoverable
 ▟ delete run.db (+ -wal/-shm; also a stale run_b.db from old installs), all prefs, Tor dirs; clear RAM log buffer
 ▟ stop Tor; null vault/messageManager
Result: blank screen, indistinguishable from a fresh install; next launch = first-run.
```

---

## 5. Reference — key constants

| Constant | Value | Meaning |
|---|---|---|
| KDF (current, v3) | Argon2id 64 MiB × 3 | PIN stretching (once per unlock) |
| legacy KDF (v2 / v1) | PBKDF2-600k / 210k | verify-only, upgrade path (no downgrade) |
| `MAX_POW_DIFFICULTY_BITS` | 23 | PoW ceiling (matches relay cap) |
| `POW_MAX_SOLVE_MILLIS` | 8,000 | per-solve wall-clock budget |
| `MINT_TOTAL_POW_BUDGET_MS` | 20,000 | aggregate grind budget per mint |
| transient mint retries | 5 | on Tor transport drops (1.5–5 s backoff) |
| `400` re-solve attempts | 3 | on challenge expiry/skew |
| `MAX_BLOBS_PER_POLL` | 2,048 | blobs decrypted per drain |
| padding buckets | 256 B → 128 KB | power-of-two length hiding |
| inbox id / capability | 32 / 43 chars | base64url (24 B / 32 B) |
| consecutive-wrong wipe | 10 / 8 / 5 *(Decent / Secure / Maximum)* | emergency wipe threshold, **per level** |
| rolling-window wipe | 30 / 24 h | brute-force backstop (universal) |
| inactivity wipe | 180 / 90 / 7 days *(Decent / Secure / Maximum)* | auto-destruct, **per level** |
| response cap | 16 MiB | per HTTP response (anti-OOM) |

---

## 6. Security properties at a glance
1. **At-rest encryption** — single SQLCipher vault; the DB key is never stored
   directly, only as a PIN-wrapped, device-key-AEAD'd blob.
2. **CR-1** — PIN *and* device key both required to open the vault. The device
   key is **hardware-rooted at rest**; by default (Lever B off) it is
   software-reachable on a live/unlocked device, so at-rest security leans on the
   PIN at the Argon2id KDF. Opt-in **Lever B** makes the DB key hardware auth-bound.
3. **Metadata minimisation** — Tor-only, length-padded, no UA/account, fail-closed
   transport guards, no clearnet in release.
4. **Forward/replay safety** — epoch-scoped monotonic counters persisted before
   send; strict-monotonic receive; AEAD with domain-separated context.
5. **Ephemerality** — messages live in RAM only, purged on background; relay
   retains only padded ciphertext under a TTL. Carve-out: a received
   "screenshot taken" notice is now a bounded, self-expiring **exception** —
   persisted for 24 h in the vault's `_meta` store (`ssn:` keys; ids +
   timestamps only, no alias/text) so it survives a background/relaunch
   instead of being lost the moment the recipient's conversation isn't open at
   drain time. See `docs/screenshot-notice-persistence-design.md` and
   `docs/SECURITY_OVERVIEW.md` §8.
6. **Anti-abuse** — PoW-minted inboxes; bounded retries; `429` backed off (retried).
7. **Tamper response** — erase-first crypto-wipe on coercion/inactivity/tamper.

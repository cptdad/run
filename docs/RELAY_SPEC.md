# Rún relay: behaviour specification

This document describes what the Rún message relay does. The relay's source code is not yet
published, so this specification takes its place. It covers every endpoint the relay answers: what
each one accepts, what it returns, what it stores, where and for how long, what it writes to its log,
and which limits apply. It is written for security reviewers and for anyone reimplementing a client.

Unless a value is marked as a production setting, every number below is the relay software's
built-in default. Section 10 says which relay build this document describes.

Contents

1. Overview
2. Conventions
3. Endpoints
4. Inbox lifecycle
5. Push delivery
6. What the relay can and cannot see
7. Logging and off-box telemetry
8. Known oracles and limits
9. Operator procedures that affect users
10. Versioning of this specification

---

## 1. Overview

- **One relay, reached only as a Tor onion service.** The relay process listens on loopback only.
  A local reverse proxy sits in front of it, and the host's Tor daemon publishes that proxy as an
  onion service. There is no clearnet listener. Production clients refuse every other transport.
- **Several onion addresses can front one relay.** Up to three onion addresses may lead to the same
  relay process. They share all state: an inbox minted through one address works through any of
  the others. The relay ignores the `Host` header. Clients may race the addresses and use
  whichever answers first.
- **HTTP/1.1 over Tor.** Clients open one Tor stream per request and send `Connection: close`.
- **No accounts.** The relay knows nothing about users or devices. Its only unit of state is an
  *inbox*: a queue of opaque blobs with a random identifier and two independent bearer
  capabilities:
  - the **read capability** belongs to the inbox owner. It drains, peeks, acknowledges, deletes,
    rotates both capabilities, and manages push registration;
  - the **write capability** lets the holder append blobs and do nothing else.
- **Proof of work gates minting.** The only way to get an inbox is `POST /inbox`. The relay
  generates the identifier and both capabilities itself, and requires a solved, single-use,
  server-issued proof-of-work challenge first. No other request creates an inbox or sets a
  capability.
- **Blobs are opaque.** Everything in an inbox is ciphertext produced by the clients. The relay
  never parses, decrypts or inspects a blob. The message format, padding, anti-replay and ratchet
  are client concerns, documented in the client repository (`docs/vault-relay-internals.md`).
- **Blobs live in memory only.** No message blob is ever written to persistent storage. Section 4
  covers the one exception, a hand-off file in RAM-backed storage used during a graceful restart.

## 2. Conventions

### Base URL and transport

- Base URL: `http://<onion-address>.onion`. Paths below are relative to it. There is no TLS
  inside the onion; Tor's onion-service encryption covers the hop.
- The reverse proxy caps every request body at **128 KiB** (131 072 bytes) and answers `413`
  above that, whatever the endpoint's own limit. Where an endpoint's limit is higher (only
  `POST /ack`), the proxy's 128 KiB is the one that applies.
- The proxy forwards bodies with a `Content-Length`. Requests that reach the relay directly must
  include one wherever this document says it is required.
- Server timeouts: 30 s to read a request, 30 s to write a response. The proxy waits up to 30 s for
  the relay.
- At most **1024** concurrent connections reach the relay. Connections beyond that are closed.
- Every request appears to the relay to come from `127.0.0.1`. The relay has no client address
  to record, and every limit described as "per source address" is in practice one global limit.

### Headers

| Header | Direction | Use |
|---|---|---|
| `X-Read-Capability` | request | Read (owner) capability, 43 base64url characters |
| `X-Write-Capability` | request | Write capability, 43 base64url characters |
| `X-New-Read-Capability` / `X-New-Write-Capability` | request | New value for a capability rotation |
| `X-PoW-Token` / `X-PoW-Counter` | request | Proof-of-work answer on `POST /inbox` |
| `X-No-Push: 1` | request | On an append: do not send a push wake for this blob. Only the literal value `1` counts; any other value is ignored |
| `ios-version` / `android-version` | response | Latest published client version (see below) |

Clients send no `User-Agent`.

### Identifier formats

- **Inbox id:** 24 random bytes, base64url without padding, exactly 32 characters.
- **Capability:** 32 random bytes, base64url without padding, exactly 43 characters.
- **Blob id and lease token:** 16 random bytes, base64url without padding, exactly 22 characters.
- **Timestamps** in relay responses (`expiresAt`) are milliseconds since the Unix epoch, on the
  relay's clock.

### Content types and bodies

- JSON request bodies use `application/json`. On `/peek`, `/ack`, `/telemetry/connect` and
  `/debuglog`, a request with *no* `Content-Type` is accepted and a request with a different one
  gets `400`. `/bugreport` requires `application/json` and answers `415` otherwise.
- JSON bodies that carry a `"v"` field require the JSON number `1`. The string `"1"` is rejected.
- Blob bodies (`POST /inbox/{id}`) are raw bytes. Blobs in responses are standard base64 with
  padding.
- Error bodies are `{"error":"<fixed string>"}`, except where an endpoint returns an empty
  error body (noted per endpoint).

### Status codes and the generic rejection

- **The generic rejection.** An unknown inbox, a wrong capability, a capability under lockout, an
  expired inbox, and a malformed inbox id or capability all get the same response:
  `404 {"error":"request rejected"}`. A dummy hash runs on the paths that would otherwise skip
  hashing, so these cases also take about the same time. A client cannot tell from the response
  whether an inbox exists.
- `429 {"error":"rate limited"}`: the relay-wide limit for unauthenticated or failed requests is
  spent (section 3.0).
- `429 {"error":"cap rate limited"}`: this inbox's own request budget for this direction is spent.
  Only an authenticated caller can receive it.
- `429 {"error":"inbox full"}`: the target inbox is at its blob-count or byte limit. Only a
  writer holding a valid write capability can receive it.
- `507`: a relay-wide capacity limit was hit. The body says which: `"server inbox limit reached"`,
  `"storage quota exceeded"`, `"bug report storage full"` or `"debug log storage full"`.
- `500 {"error":"request rejected"}`: an unhandled server error. The response never includes
  exception text.
- Any path or method not listed here gets the server's built-in `404` with an empty body. Clients
  use `GET /` for this as a reachability probe: it names no inbox and carries no capability.

### Version headers (update notice)

Every response from the relay's public port carries two optional headers, including rejections,
`500`s and the built-in `404` for `GET /`:

- `ios-version: MAJOR.MINOR.PATCH` and `android-version: MAJOR.MINOR.PATCH`, header names in
  lowercase. Each component is 1 to 4 ASCII digits, and each value is at most 14 characters.
- Each header is either present with a valid value or absent. It is never sent empty. The relay
  re-reads the values from a local file every 60 s, which an operator-side poller updates from the
  app stores (the poller works over Tor; the relay itself makes no request for this). An operator
  can also pin either value in configuration. A pinned value that does not fit the grammar stops
  the relay from starting.
- The headers flow from relay to client only. Clients never send their own version. They compare
  the header with their own build locally and show a fixed "new version available" notice.
- The admin port (section 3.14) never sends these headers.

---

## 3. Endpoints

### 3.0 Shared rules for the inbox endpoints

These apply to every endpoint whose path contains `{id}`, and to each item of `POST /peek` and
`POST /ack`.

**Order of checks.** The relay checks the format of the inbox id and capability first. If either
is malformed, it gives the generic rejection and charges the probe budget (below). The relay then
locks the inbox and verifies the capability, and if it is correct, applies the operation. The lock
is held from verification through the change, so the two steps cannot be split.

**Capability verification.** Each capability is stored as `SHA-256(salt ‖ capability)` with its own
16-byte random salt, and compared in constant time. The plaintext capability is held only for the
duration of the request and is never stored.

**Lockout.** Each direction (read, write) keeps its own failure counter. Five wrong but well-formed
capabilities in a row lock that direction for 5 minutes. Each further lockout without a correct
capability in between doubles the window, up to 1 hour. A lockout rejects wrong capabilities only.
A correct capability is always accepted, and it resets that direction's counter, lockout and
backoff. A wrong capability that arrives during a lockout gets the generic rejection and does not
advance the counter. Malformed capabilities never count toward a lockout.

**Rate limits.**

| Budget | Default | Charged by | Over budget |
|---|---|---|---|
| Probe budget | 300 requests per 60 s window, per source address (in practice relay-wide) | Only failed requests: unknown inbox, wrong or locked capability, malformed id or capability. Charged before any lockout state changes | `429 "rate limited"`; nothing about the inbox changes |
| Read budget | 120 requests per 60 s window, per inbox | Retrieve, peek, delete, both rotations, push register and deregister. Acknowledge is **not** charged | `429 "cap rate limited"` |
| Write budget | 120 requests per 60 s window, per inbox | Append | `429 "cap rate limited"` |

Valid capability operations never touch the probe budget. A flood of bad requests can therefore
deny other bad requests, but it cannot stop an inbox owner or writer who holds valid capabilities.

**Lifetime renewal.** Every successful authenticated operation extends the inbox's expiry (section
4). A failed operation never does.

**Logging.** No line at INFO or above contains an inbox id, a capability, a blob id, a lease token,
a push token, a push endpoint or key, or any blob content. The only per-request INFO line is the
access line described in section 7, with the inbox id replaced by `***`.

---

### 3.1 `POST /inbox`: mint an inbox

- **Auth:** proof-of-work token. No capability.
- **Request:** no body is needed (any body is ignored). Headers `X-PoW-Token` and `X-PoW-Counter`
  are required on the second step.
- **Flow:**
  1. A request without a valid proof of work gets
     `400 {"error":"proof of work required","nonce":"<b64url>","token":"<b64url>","difficulty":<int>,"ttlSeconds":120,"algorithm":"sha256","preimage":"nonce:counter"}`.
  2. The client finds a decimal integer `counter` such that
     `SHA-256(ASCII(nonce) ‖ ":" ‖ ASCII(decimal counter))` begins with at least `difficulty` zero
     bits. `nonce` is hashed as the base64url **string** exactly as received, not as decoded bytes.
  3. The client repeats `POST /inbox` with `X-PoW-Token: <token, verbatim>` and
     `X-PoW-Counter: <counter>`.
- **The token** is opaque to clients: base64url of 57 bytes,
  `nonce(16) ‖ issuedAt(8, milliseconds, big-endian) ‖ difficulty(1) ‖ HMAC-SHA256(key, first 25 bytes)(32)`.
  The HMAC key is random, held in memory, and replaced at each process start, so a restart
  invalidates every outstanding challenge. When verifying, the relay checks the MAC first (in
  constant time), then that the difficulty is within the allowed range, then that the token is
  fresh (`0 ≤ now − issuedAt ≤ 120 s`), then the proof-of-work bits. Last, it marks the nonce as
  spent. A nonce is accepted once. It stays spent even if minting then fails. Any verification
  failure gets a fresh challenge (`400`).
- **Difficulty:** 20 bits by default. It is fixed by configuration (allowed range 16 to 22) and
  never changes with load. Clients refuse any challenge above their own ceiling of 24 bits.
- **Response:** `201 {"inboxId":"<32>","readCapability":"<43>","writeCapability":"<43>","expiresAt":<ms>}`.
  `expiresAt` is the end of the bootstrap window (section 4).
- **Stored:** inbox id; the salt and hash of each capability; expiry; zeroed lockout counters.
  The plaintext capabilities exist only in this response.
- **Where:** memory. The inbox shell is copied into the snapshot file at the next snapshot (section 4).
- **How long:** 90 days unless renewed (section 4).
- **Spent-nonce record:** each accepted nonce is kept in memory until its challenge would have
  expired (120 s), then removed on the 60 s maintenance tick. At most 100 000 spent nonces are held;
  at that ceiling minting is refused until old entries are removed.
- **Logged at INFO:** the access line only.
- **Limits:**
  - Requests that **would issue a challenge** (no valid proof) share a budget of 120 per 60 s per
    source address (in practice relay-wide). Over it: `429 "rate limited"`. A request carrying a
    valid proof is not subject to this budget.
  - At most **15 000** inboxes can exist on the relay. Over it: `507 "server inbox limit reached"`.
  - If the server fails to generate a unique id: `500 {"error":"inbox id allocation failed"}`.

### 3.2 `POST /inbox/{id}`: append a blob

- **Auth:** write capability (`X-Write-Capability`).
- **Request:** raw body, 1 to 65 536 bytes. `Content-Length` is required. Optional query
  `?ttl=<seconds>`: blob lifetime, clamped to the range 1 to 604 800 (7 days). A missing or
  non-integer value means 86 400 (24 h). Optional `X-No-Push: 1`.
  Current clients send no `ttl` on text messages, so those get 24 h, and send `ttl=604800` on every
  control message.
- **Response:** `202 {"stored":true}`.
- **Stored:** the blob bytes, a relay-generated blob id, and the blob's expiry. The blob expiry is
  the earlier of `now + ttl` and the inbox's own expiry.
- **Where:** memory only.
- **How long:** until it is acknowledged (3.4), drained by a plain retrieve (3.3), expired (at most
  7 days), evicted by the fairness reclaim (below), or removed with its inbox.
- **Push:** if the inbox has a push registration and `X-No-Push: 1` is absent, the relay sends one
  content-free wake after accepting the blob (section 5). The wake is sent in the background and
  never delays or changes the response.
- **Logged at INFO:** the access line only.
- **Limits and their meaning:**
  - No `Content-Length`: `411 {"error":"length required"}`. The relay checks this before reading
    the body.
  - Body over 65 536 bytes: `413 {"error":"payload too large"}`. Empty body:
    `400 {"error":"empty body"}`.
  - Write budget spent: `429 "cap rate limited"`.
  - At most **200 blobs** and **2 MiB** (2 097 152 bytes) queued per inbox. Over either:
    `429 "inbox full"`. This concerns the target inbox only.
  - All blobs on the relay together are capped at **1 GiB** (the production instance runs at
    **256 MiB**). If an append would exceed the cap, the relay first frees space fairly: it drops
    blobs that have already expired, then evicts blobs (oldest first) from the inboxes with the
    largest unread backlogs that have waited at least 60 s. A backlog dates from the moment a blob
    arrived in an empty queue; it resets whenever the queue is read empty. Recently delivered
    blobs are never evicted. Only if this frees too little does the append get
    `507 "storage quota exceeded"`. Both the reclaim and the 507 can happen only after the write
    capability has been verified. An unauthenticated caller gets the generic `404` whether the
    relay is full or empty.

### 3.3 `GET /inbox/{id}`: retrieve

- **Auth:** read capability (`X-Read-Capability`).
- **Two modes**, chosen by the exact query string:
  - **Leasing retrieve, `?lease=1`.** This is the mode current clients use for all normal message
    traffic. Response: `200 {"blobs":["<b64>",…],"ids":["<22>",…],"token":"<22>"}`. `ids` lists
    each blob's id in the same order as `blobs`. Nothing is deleted. The returned blobs are leased
    for **60 s** (configurable from 1 to 3 600 s): while leased, they are hidden from every retrieve
    and every peek. `POST /ack` (3.4) deletes the blobs the client processed and returns the rest
    to the queue. If the lease expires without an acknowledgement, the blobs become visible again
    and the client's anti-replay layer drops the repeat delivery. An empty inbox answers
    `{"blobs":[],"ids":[],"token":""}`.
  - **Plain retrieve, no query.** Response: `200 {"blobs":["<b64>",…]}`. The relay returns every
    visible blob and deletes it, together with any expired blobs. Blobs under another live lease
    are neither returned nor deleted. Current clients use this mode only for the single-use
    transfer inbox of the "move to a new device" feature.
- **Retrieve never deletes the inbox.** The inbox, its capabilities and its lockout counters stay.
- **Stored:** in lease mode, each returned blob gets a lease deadline and the lease token, both in
  memory. A restart drops every lease, so leased blobs become visible again.
- **Side effects:** extends the inbox's lifetime. A retrieve that returns at least one blob
  *promotes* a new inbox to the long idle window (section 4). A retrieve also resets the push
  check-in counter (section 5).
- **Logged at INFO:** the access line only.
- **Limits:** read budget; `429` as in 3.0.

### 3.4 `POST /ack`: settle leasing retrieves (batch)

- **Auth:** each item carries its own read capability **in the body**. The request has no
  capability header.
- **Request:**
  `{"v":1,"items":[{"id":"<inbox id>","rc":"<read cap>","token":"<lease token or empty>","delete":["<blob id>",…]},…]}`.
  1 to 64 items; at most 256 blob ids per item. The relay itself accepts bodies up to 256 KiB, but
  the reverse proxy's 128 KiB limit is the one that applies (section 2).
- **Per item:** if the inbox and capability are valid, the relay deletes every blob in that inbox
  whose id is listed in `delete`, whatever lease it is under, and releases every other blob still
  holding `token`. Unknown, expired or malformed blob ids match nothing. Sending the same
  acknowledgement twice deletes nothing the second time.
- **Response:** always `200 {"v":1,"results":[…]}`, with one result per item, in request order:
  `{"id":"…","deleted":<n>,"released":<n>}` on success, otherwise `{"id":"…","status":<n>}`, where
  `n` is the HTTP status a single-inbox request would have received (404 or 429). A bad item never
  causes the whole batch to be rejected. A malformed id or capability inside an item is answered
  exactly like an unknown inbox.
- **Whole-request errors:** `400 {"error":"request rejected"}` for a body that cannot be read as a
  batch (bad JSON, wrong shape, `v` not the number 1, zero items, wrong `Content-Type`).
  `413 {"error":"payload too large"}` for more than 64 items, more than 256 ids in one item, or an
  oversized body.
- **Stored:** nothing new. Deleted blobs leave memory at once.
- **Side effects:** extends each authenticated inbox's lifetime. Does not use the read budget.
- **Logged at INFO:** the access line only.
- **Limits:** at most 8 failing items per request are checked and charged to the probe budget.
  Every failing item after the eighth gets `status: 429` without a charge. A batch of garbage
  therefore cannot drain the relay-wide probe budget.

### 3.5 `GET /inbox/{id}/peek`: pending count

- **Auth:** read capability.
- **Response:** `200 {"pending":<n>}`, where `n` is the number of visible blobs: not expired and
  not under a lease. Peek deletes nothing.
- **Side effects:** extends the inbox's lifetime (it never promotes it) and resets the push
  check-in counter.
- **Stored / logged at INFO:** nothing / the access line only.
- **Limits:** read budget.

### 3.6 `POST /peek`: pending counts for many inboxes (batch)

- **Auth:** each item carries its own read capability in the body.
- **Request:** `{"v":1,"items":[{"id":"<inbox id>","rc":"<read cap>"},…]}`, with 1 to 64 items
  and a body of at most 16 384 bytes. Clients split larger sets across several requests.
- **Per item:** the same check, charges and side effects as `GET /inbox/{id}/peek`, including the
  per-inbox read budget and the lockout counter.
- **Response:** always `200 {"v":1,"results":[…]}`, with one result per item, in request order
  (duplicates are answered separately): `{"id":"…","pending":<n>}` or `{"id":"…","status":<n>}`.
  Exactly one of the two fields is present. `pending: 0` means the inbox is known to be empty.
- **Whole-request errors:** `400 {"error":"request rejected"}` or `413 {"error":"payload too large"}`,
  on the same terms as `POST /ack`.
- **Stored / logged at INFO:** nothing / the access line only. Item counts go to the debug-level
  log only.
- **Limits:** the same 8-failing-items cap as `POST /ack`.
- **Note:** this request shows the relay, in a single request, every inbox a device holds. Clients
  send it once per connection, for the initial unread counts only. After that they peek one inbox
  per request.

### 3.7 `DELETE /inbox/{id}`: delete an inbox

- **Auth:** read capability.
- **Response:** `204`.
- **Effect:** the inbox, its queued blobs, its capability hashes, its lockout counters and its push
  registration are removed from memory at once. They stay in the snapshot file until the next
  snapshot write, and in the one kept previous generation until the write after that (section 4).
- **Logged at INFO:** the access line only.
- **Limits:** read budget.

### 3.8 `PUT /inbox/{id}/read-capability`: rotate the read capability

- **Auth:** current read capability (`X-Read-Capability`).
- **Request:** `X-New-Read-Capability: <43 base64url characters>`. The client chooses the new
  value.
- **Response:** `200 {"rotated":true}`.
- **Stored:** a new salt and hash for the read capability replace the old ones. The old capability
  stops working immediately.
- **Logged at INFO:** the access line and the fixed line `Read cap rotated`.
- **Limits:** read budget.

### 3.9 `PUT /inbox/{id}/write-capability`: rotate the write capability

- **Auth:** current **read** capability. Writers cannot rotate anything, so the owner can always
  revoke a leaked write capability.
- **Request:** `X-New-Write-Capability: <43 base64url characters>`.
- **Response:** `200 {"rotated":true}`.
- **Stored:** a new salt and hash for the write capability. The write-direction failure counter and
  lockout are reset.
- **Logged at INFO:** the access line and the fixed line `Write cap rotated (counter+lockout reset)`.
- **Limits:** read budget.
- Current clients never call this endpoint.

### 3.10 `PUT /inbox/{id}/push` and `DELETE /inbox/{id}/push`: push registration

- **Auth:** read capability. Only the inbox owner can register, because it is the owner's device
  that gets woken.
- **PUT request** (at most 4 096 bytes), one of:
  - APNs: `{"platform":"apns","token":"<device token>","env":"sandbox"|"production","badge":true|false}`.
    `badge` is optional and defaults to false.
  - FCM: `{"platform":"fcm","token":"<registration token>","env":"<string>"}`.
  - UnifiedPush: `{"platform":"unifiedpush","token":"<https endpoint URL>","env":"<string>","p256dh":"<b64url>","auth":"<b64url>"}`.
- **Validation** (otherwise `400 {"error":"invalid push registration body"}`; the offending value
  is never echoed back):
  - apns/fcm `token`: 1 to 256 characters, from `A–Z a–z 0–9 _ . : -` only. These platforms must
    not include `p256dh` or `auth`.
  - apns `env`: exactly `sandbox` or `production`. fcm and unifiedpush `env`: at most 32
    characters from `A–Z a–z 0–9 _ . : -` (may be empty). The relay ignores it when delivering.
  - unifiedpush `token`: an `https` URL of at most 1 024 characters, with no user-info part, a
    non-empty path and a valid port. It must not use an IP-literal host, `localhost`, or a host
    under an internal-use suffix such as `.local`, `.lan`, `.internal`, `.test` or `.invalid`. The
    relay never resolves this name in DNS. `p256dh` must be a 65-byte uncompressed P-256 point and
    `auth` a 16-byte secret, both base64url. An operator may also limit endpoints to a list of
    allowed host names.
  - `badge` is stored only for apns. For the other platforms it is always stored as false.
- **PUT response:** `200 {"ok":true}`. The PUT is an upsert: a new registration replaces the old one
  completely, including platform and keys.
- **DELETE response:** `200 {"ok":true}`, also when no registration existed.
- **Stored** (per inbox): `platform`, `token` (for unifiedpush, the endpoint URL), `env`, and for
  unifiedpush, `p256dh` and `auth`; the `badge` flag. All of these are stored exactly as received,
  without hashing. In memory only, the relay also keeps the registration time and the number of
  wakes sent since the owner last read the inbox.
- **Where:** memory, and the snapshot file (section 4). A push token is therefore on disk on the
  relay's encrypted volume for as long as the registration exists, plus up to two snapshot
  intervals after it is removed.
- **How long:** until `DELETE …/push`, a new PUT, deletion or expiry of the inbox, or a dead-token
  verdict from Apple or Google (section 5).
- **Logged at INFO:** the access line, plus the fixed line `Push registered: platform=<p> env=<e>`
  or `Push deregistered`. Neither includes a token, endpoint, key or inbox id.
- **Limits:** read budget. `413 {"error":"payload too large"}` for a declared body over 4 096
  bytes.
- Clients register the same device token on each of the device's inbound inboxes. Clients send
  `DELETE …/push` when the user turns notifications off and again during a wipe. The wipe request
  is best-effort: an offline device cannot send it.

### 3.11 `POST /bugreport`: user-sent bug report

- **Auth:** none. No capability, no proof of work. The report is not linked to any inbox.
- **Request:** `Content-Type: application/json`, body at most 16 384 bytes:
  `{"v":1,"text":"<free text>","app":"<version>","platform":"android"|"ios"}`.
  `text` may be at most 4 000 characters. Unknown fields are ignored and not stored. The relay
  does not check the values of `app` and `platform`.
- **Response:** `204` with an empty body.
- **Errors:** `415 {"error":"expected application/json"}`; `413 {"error":"payload too large"}`;
  `413 {"error":"text too long"}`; `400 {"error":"invalid bug report body"}`;
  `429 {"error":"rate limited"}`; `507 {"error":"bug report storage full"}`;
  `500 {"error":"request rejected"}` on a write failure.
- **Stored:** one JSON file per report, `{"v","text","app","platform","received_at"}`, where
  `received_at` is epoch seconds. `text` is stored exactly as submitted. The file name is the UTC
  arrival time (sub-second precision, colons removed) plus 8 random hex characters.
- **Where:** a dedicated directory on the relay's encrypted state volume (directory mode 0700,
  files 0600).
- **How long:** **90 days** after arrival (by file modification time). An hourly sweep deletes it
  the first time it runs after that age.
- **Logged at INFO:** the access line and `Bug report stored (<n> bytes)`. The text is never logged.
- **Limits:** one relay-wide token bucket of 30 reports per hour with a burst of 10. At most 1 000
  stored reports; after that, new reports get `507` until old ones expire or are deleted.
- Clients send a report only when the user submits the "Report bug" form.

### 3.12 `POST /telemetry/connect`: connect-time report

- **Auth:** none. The report is not linked to any inbox.
- **Request** (at most 2 048 bytes): `{"v":1,"platform":"android"|"ios","app":"<version>","secs":<int>, "tor":<int>?, "boot":<int>?, "reveal":<int>?, "log":[[<offset>,"<CODE>"],…]?}`.
  The relay re-checks every field independently:

  | Field | Rule |
  |---|---|
  | `v` | the number 1 |
  | `platform` | `android` or `ios` |
  | `app` | digits and dots matching `^[0-9]+(\.[0-9]+){1,3}$`, at most 16 characters |
  | `secs` | integer, 5 to 3 600: seconds from the start of the client's connect to the relay's first answer |
  | `tor` (optional) | integer, 0 to `secs`: the part of `secs` spent waiting for Tor |
  | `boot` (optional) | integer, multiple of 5, 5 to 3 600: seconds from app launch to Tor being ready. Independent of `secs` |
  | `reveal` (optional) | integer, `secs` to 3 600: seconds until the contact list appeared |
  | `log` (optional) | at most 48 entries `[offset, CODE]`. `offset` is an integer, a multiple of 5, from 0 to 3 600, never decreasing. `CODE` is one of a fixed list of 86 upper-case phase codes (for example `TOR_START`, `SOCKS_READY`, `FIRST_ROUNDTRIP`). The list contains no free text |

  Every number is an integer; a quoted number is rejected. Any invalid field rejects the whole
  report.
- **Response:** `204` with an empty body. This includes the case where the rate limit is
  exceeded: such reports are silently dropped, and the response does not reveal that.
- **Errors:** `400` and `413`, both with **empty** bodies. An invalid report never uses up a
  rate-limit token.
- **Stored:**
  - Every accepted report: one observation in in-memory aggregate histograms. These are keyed by
    `platform` and by a three-value `release` label (`latest`, `older` or `unknown`), which the
    relay computes by comparing `app` with the version it currently advertises. The version string
    itself is never used as a label.
  - **Only reports that include `log`:** one JSON file holding the validated fields (rebuilt
    field by field) plus `received_at` (epoch seconds), and one counter increment per entry
    (labels `platform`, `release`, `code`). The file name is the UTC arrival time plus 8 random hex
    characters. Reports without `log` write nothing to disk.
- **Where:** histograms and counters in memory, exposed on the admin metrics endpoint and reset on
  restart. Files on the encrypted state volume (0700 / 0600).
- **How long:** stored files are kept **30 days** after arrival and removed by the hourly sweep.
  At most 5 000 files are kept. Past that limit, timelines are no longer stored, but the report
  still gets `204` and still counts in the aggregates.
- **Logged at INFO:** exactly one line per accepted report:
  `telemetry connect platform=<p> app=<v> secs=<n>`, with ` tor=<t> rdv=<secs−tor>`,
  ` boot=<b>` and ` reveal=<r> gate=<reveal−secs>` appended in that order when those fields are
  present. The `log` timeline never appears in the log. Reports that are stored also produce
  `Connect log stored (<bytes> bytes, <n> entries)`.
- **Limits:** one relay-wide bucket of 60 reports per minute.
- Clients send at most one report per connection, and only while the user has Debug mode switched
  on.

### 3.13 `POST /debuglog`: Debug mode log stream

- **Auth:** none. The upload is not linked to any inbox.
- **Request** (at most 65 536 bytes):
  `{"v":1,"platform":"android"|"ios","app":"<version>","reason":"connect"|"periodic"|"lock","session":"<8 lowercase hex>"?,"t0":<int>?,"lines":["…",…]}`.
  - `session` (optional): exactly 8 lowercase hex characters. The client draws it at random for
    each app process and never stores it.
  - `t0` (optional): epoch seconds, a multiple of 60, within ±48 h of the relay's clock. It is the
    reference point for the relative `+SSSSS.mmm` time prefixes at the start of each line.
  - `lines`: at most 500 strings of at most 512 characters each. No control characters except
    TAB.
  - `platform` and `app` follow the same rules as 3.12.
- **Response:** `204`.
- **Errors:** `400` (empty body) on any validation failure; `413 {"error":"payload too large"}`;
  `429 {"error":"rate limited"}`; `507 {"error":"debug log storage full"}`;
  `500 {"error":"request rejected"}` on a write failure. Here the relay answers `429` rather than
  dropping the batch silently, so the client knows its log has a gap.
- **Stored:** each batch is appended as one JSON line,
  `{"received_at":<epoch s>,"session":…|null,"app":…,"reason":…,"t0":…|null,"lines":[…]}`, to a
  file named `<yyyy-MM-ddTHH>Z-<platform>.jsonl`, one file per UTC hour and platform. Fields are
  rebuilt one by one from the validated batch, so unknown fields are never stored. The lines are
  stored as received. Clients remove names, aliases, message content, addresses, keys, inbox and
  contact identifiers and network identifiers before sending. The relay does not repeat that
  scrubbing.
- **Where:** the encrypted state volume (0700 / 0600). Appends are not fsync'ed.
- **How long:** **14 days** after a file's last write, removed by the hourly sweep.
- **Logged at INFO:** the access line, and one line per closed hourly file:
  `Debug logs: <file name> closed, <n> batches, <m> bytes`. Per-batch lines go to the debug-level
  log only, and log content is never written to the log.
- **Limits:** one relay-wide token bucket of 600 batches per minute with a burst of 300. Each
  hourly file holds at most 64 MiB, at most 16 MiB per `session` per hour, at most 336 files exist
  at once, and all files together hold at most 4 GiB. Exceeding any of these gives `507`.
- Clients send a batch about once a second, and only while the user has Debug mode switched on.
  Turning Debug mode off stops the stream immediately.

### 3.14 Admin port (operator only, not reachable over Tor)

A second HTTP listener, on a separate port, serves operator functions. By default it binds to
loopback. The production instance binds it to an address on the operator's private LAN so a
monitoring host can collect metrics. The onion service forwards only to the reverse proxy, and the
proxy forwards only to the relay's public port, so no onion address can reach the admin port. The
admin port **has no authentication**: anyone with network access to it can use every route below.
It never sends the version headers.

| Route | Purpose |
|---|---|
| `GET /health` | `{"status":"ok","inboxes":<n>,"totalBytes":<n>,"snapshotTainted":<bool>,"snapshotTaintReason":<string or null>}` |
| `GET /metrics` | Request and inbox counters as JSON |
| `GET /prometheus` | Prometheus metrics (section 7) |
| `POST /snapshot/resume` | Re-enables snapshot saving after a failed snapshot load (section 9) |
| `GET /inboxes/stale?expiresAfterMs=&expiresBeforeMs=` | Read-only count of inboxes whose expiry falls in a window |
| `DELETE /inboxes/stale?…` | Removes those inboxes. Limited to a window of at most 48 h that contains only inboxes idle for at least 90 days (section 9) |
| `GET/DELETE /bugreports[/<name>]`, `DELETE /bugreports?olderThanDays=N` | List, read, delete, prune bug reports |
| `GET/DELETE /connectlogs[/<name>]`, `DELETE /connectlogs?olderThanDays=N` | The same for stored connect timelines |
| `GET/DELETE /debuglogs[/<name>]`, `DELETE /debuglogs?olderThanDays=N` | The same for Debug mode log files |

The relay's public port has no health endpoint. Clients check reachability with `GET /` (section 2).

### 3.15 Reverse-proxy routes that are not part of the relay

Besides forwarding to the relay, the reverse proxy on the relay host forwards one path prefix,
`/loki/`, to the operator's log server. Requests to it are refused with `401` unless they carry a
secret header known only to the operator. No released client uses this route.

---

## 4. Inbox lifecycle

**Mint.** `POST /inbox` creates the inbox shell with `expiresAt = now + 90 days` (the bootstrap
window).

**Renewal.** Every successful authenticated operation (append, retrieve, peek, acknowledge,
rotation, push register or deregister) extends the expiry within the inbox's current window:

- a shell that has not yet been promoted: `expiresAt = max(expiresAt, now + 90 days)`;
- a promoted shell: `expiresAt = now + 365 days`.

A failed request never extends the expiry.

**Promotion.** Only a retrieve that actually returns at least one blob moves a shell from the
90-day bootstrap window to the 365-day idle window. Peeks, appends and empty retrieves do not.
Promotions are capped at 1 000 per hour across the relay. When the cap is reached, the retrieve
still succeeds and the shell stays in the bootstrap window until a later retrieve promotes it.
Consequence: an inbox that never receives a message expires 90 days after its owner last used it.

**Blob lifetime.** Each blob expires at `min(now + ttl, inbox expiry)`, with `ttl` set by the writer
between 1 s and 7 days (24 h when absent). Expired blobs are never returned, are not counted by
peek, and are removed by the maintenance tick, by the next plain retrieve, or by the fairness
reclaim.

**Expiry sweep.** Every 60 s the relay removes expired blobs and expired inboxes, including any
blobs still queued in them. An expired inbox that is accessed before the sweep reaches it gets the
generic rejection and is removed on the spot.

**Explicit removal.** `DELETE /inbox/{id}` (3.7). Nothing else removes an inbox before it expires,
except the operator procedure in section 9.

**The shell snapshot.** So that a restart does not cut every user off, the relay writes inbox
*shells*, but never their contents, to one file:

- **Contents per inbox:** inbox id; the read-capability salt and hash; the write-capability salt and
  hash; `expiresAt`; the read and write failure counters and lockout deadlines; and, when one
  exists, the push registration (platform, token or endpoint, env, the two UnifiedPush keys, the
  badge flag).
- **Never in the snapshot:** blobs, blob ids, leases, plaintext capabilities, per-inbox rate
  budgets, lockout backoff steps, push check-in counters, spent proof-of-work nonces, the HMAC key.
- **When:** every 300 s, and once more on a graceful shutdown. Expired shells are left out.
- **Where:** a single file on the relay host's encrypted volume, mode 0600. The relay adds no
  encryption of its own; at-rest protection comes from the volume. Each successful save first
  renames the previous file to a `.prev` copy and keeps that one copy. A file that fails to load
  is kept, renamed to `.corrupt-<timestamp>`, until the operator removes it.
- **Consequence:** a deleted or expired inbox stays on disk for up to one snapshot interval
  (300 s) in the current file and one more interval in the `.prev` copy.
- **On restart:** the relay loads the shells before it accepts any request. A loaded inbox whose
  expiry lies beyond the bootstrap window is treated as promoted.

**Queue hand-off across a graceful restart.** Queued blobs live only in memory. To keep them across
a planned restart, the shutdown routine writes, immediately after the snapshot, a separate file
containing each live inbox's id, its unexpired blobs (bytes, blob id, expiry, in queue order) and
its backlog start time, followed by a SHA-256 checksum.

- **Where:** RAM-backed temporary storage (`/dev/shm`), never a persistent disk; mode 0600. The relay
  warns at startup if this path points anywhere else.
- **When:** only during a graceful shutdown. It is never written periodically and never while
  handling requests.
- **How long:** the next process start deletes the file *before* reading it (if the delete fails,
  the file is not used at all), then attaches each blob to its inbox, provided that inbox's shell
  was loaded and the blob is unexpired and within the per-inbox and relay-wide limits. A file that
  fails its checksum is discarded, and the relay starts with empty queues.
- **Not covered:** a crash, a forced kill or an out-of-memory kill. In those cases every queued blob
  is lost, and so is any shell change made since the last snapshot.

---

## 5. Push delivery

**Trigger.** One wake per successful append to an inbox with a push registration, unless the
writer sent `X-No-Push: 1`. Current clients set `X-No-Push: 1` on control messages that should not
wake the recipient.

**The wake carries no content.** Each wake is one of a few fixed payloads. None contains blob
data, an inbox id, a sender, a count, or any value that varies per message:

| Platform | What the relay sends |
|---|---|
| APNs | Alert push `{"aps":{"alert":{"loc-key":"Notification"},"sound":"default"}}`, or the same with `"badge":1` if the registration opted in. Priority 10, collapse id `wake`, expiry 4 h |
| FCM | Data message `{"type":"wake"}`, priority high, collapse key `wake`, TTL 4 h |
| UnifiedPush | `{"type":"wake"}` encrypted per RFC 8291 (`aes128gcm`) to the subscription's keys. The ciphertext is always the same length. TTL 1 h, urgency high, no `Topic` header, no VAPID identification |

The client fetches the actual messages itself, over Tor, after the user unlocks the app.

**Egress.** The relay sends wakes through the host's Tor daemon (an HTTP CONNECT tunnel). The push
service therefore sees a Tor exit node, not the relay host. Host names are resolved on the Tor
side, never by the relay host's own DNS. Pushes are the only outbound connections the relay
process makes. UnifiedPush can never be sent without the tunnel; if the tunnel is not configured,
UnifiedPush delivery is off. Some UnifiedPush servers are unreachable from many Tor exits. For
those, the relay tries several isolated circuits before the single real send.

**What each push service learns:**

- **Apple (APNs):** the device token, the app's bundle id, the operator's Apple developer
  credentials, the time of each wake, and whether the badge flag is set.
- **Google (FCM):** the registration token, the operator's Firebase project, and the time of each
  wake.
- **The UnifiedPush server** (chosen by the user's distributor app): the endpoint URL, the time of
  each wake, and a fixed-size encrypted body.
- None of them receives message content, the sender, the inbox id or a message count. All of them
  can see how often and when a device is woken.

**Stored by the relay:** the registration fields listed in 3.10, in memory and in the snapshot. One
registration is stored per inbox, and a new PUT replaces it.

**Removal:**

- the owner's `DELETE /inbox/{id}/push` (sent when notifications are turned off, and on wipe);
- deletion or expiry of the inbox;
- a dead-token verdict: APNs `410 Unregistered` or FCM `404 UNREGISTERED` clears the registration,
  but only if it still holds the same token that was sent to. At most 20 such clears are allowed per
  5 minutes; past that the relay keeps the registrations and logs an operator alarm, because a
  burst of verdicts usually means a credential problem, not uninstalled apps. Other APNs and FCM
  errors clear nothing. UnifiedPush `404` and `410` responses also clear nothing, because the user's
  device supplies that server, so its answers are not trusted.

**Logged at INFO or WARN:** the push platform, env, outcome and counters only, for example a
registration cleared after a dead-token verdict, or a run of many wakes without a check-in. No push
log line contains a token, an endpoint, a key or an inbox id.

---

## 6. What the relay can and cannot see

**It cannot see:**

- message content, sender, recipient name, contact names, or group membership. Blobs are
  end-to-end encrypted by the clients and the relay never decrypts them;
- client IP addresses or locations. Every request arrives through Tor and then the local proxy
  from `127.0.0.1`;
- which app version a client runs, except where a Debug mode upload or bug report states it.
  Clients send no `User-Agent` and no version.

**It can see, per request:**

- the time, the endpoint, the inbox id in the path or body, which capability type was presented,
  and the response status;
- the **exact byte length** of every blob. Clients pad plaintext to power-of-two sizes (minimum
  256 bytes) before encrypting, so the length shows the padding size plus a fixed overhead for the
  message format. It does not show the true message length;
- the requested `ttl` and whether `X-No-Push: 1` was set. Current clients send `ttl` only on control
  messages, so the relay can tell control appends from text appends, and also which appends are
  meant to wake the recipient;
- which onion address the client used (from the `Host` header).

**What it can link:**

- **Writer and reader of one inbox.** Appends to an inbox, and the retrievals by its owner, all name
  the same inbox id, so the relay sees when messages arrive and when they are collected.
- **Inboxes of one pairing.** A conversation between two devices uses several inboxes (separate
  text, control and group inboxes in each direction). The ids are unrelated random values, but
  inboxes minted, polled or written close together in time can be matched up by timing.
- **Inboxes of one device.** The batch `POST /peek` (3.6) lists every inbox a device holds in one
  request, once per connection. A device that turned on notifications registers the same push token
  on each of its inbound inboxes, so the relay can group those inboxes by token. The relay's own
  metrics count distinct push tokens.
- **Requests within one session.** Clients open a new Tor stream per request, but streams from one
  session normally share a Tor circuit. The relay process does not record circuits. The host's Tor
  daemon, run by the same operator, could be instrumented to group requests by circuit. Clients
  therefore assume that everything one session sends is linkable.
- **Diagnostics and the session that sent them.** A bug report, connect-time report or Debug mode
  batch travels over the same Tor connection as that session's message traffic, so the relay can
  link the diagnostic to the inboxes that session used. This is why diagnostics carry nothing the
  relay could not already learn from the connection. While Debug mode is on, the `session` value in
  debug log batches lets the operator group batches from one app process.

**What it can do, as an untrusted party:** delay or drop blobs, deliver an old blob again
(clients reject the repeat with their anti-replay checks), refuse service, or send a misleading
version header (clients show only a fixed notice and link only to the official store). It cannot
create a blob that clients accept, since it holds no keys, and it cannot read a blob.

---

## 7. Logging and off-box telemetry

**The relay's log.**

- Production runs at **INFO**. The log goes to the host's system journal, which is forwarded to a
  log server operated by the same operator.
- **No line at INFO or above contains an inbox id, a capability, a blob id, a lease token, a push
  token, endpoint or key, or blob data.** An automated test enforces this for the inbox store's
  log lines.
- What INFO does contain:
  - **one access line per request:** `<METHOD> <path> -> <status>`. Any inbox id in the path is
    replaced, for example `GET /inbox/*** -> 200`. Query strings and headers are never logged;
  - the fixed lines named per endpoint in section 3;
  - the one `telemetry connect …` line per accepted connect-time report (3.12), which includes the
    reported app version;
  - aggregate operational lines with counts only: cleanup runs, fairness reclaims (at most one line
    per 10 s), capacity refusals, snapshot and queue hand-off results, lockout notices, startup
    configuration.
- **Per-inbox detail exists only at DEBUG, which production does not enable.** Even at DEBUG an
  inbox appears only as an 8-character prefix of its id, and blob sizes as their power-of-two
  rounding, never the exact length. The operator's separate test relay runs its inbox log at DEBUG
  for automated tests; it never carries production traffic.
- **Retention (production, read from the running configuration on 2026-11-05).**
  - On the relay host, `systemd-journald` keeps the journal for at most **30 days**
    (`MaxRetentionSec=30day`), within its default size cap of 10 % of the host's 8 GB disk;
    whichever limit is hit first drops the oldest files.
  - The log server keeps every line for **30 days** (`retention_period: 720h`) and its
    compactor deletes expired data within two hours of expiry. Lines older than seven days are
    refused at ingest. The forwarder on the relay host ships only three units — the relay
    service, the Tor daemon and the reverse proxy — and backfills at most 12 hours after a
    restart. Nothing else on the host (ssh, cron, logins, package updates) leaves the host.
  - Both copies contain only what this section describes: no identifier, capability, token or
    blob data at INFO.

**The reverse proxy.** Its access log is switched off, and its error log records only critical
proxy failures. It therefore writes no line per request.

**Metrics.** The admin port's Prometheus endpoint, collected by the operator's monitoring host,
exposes:

- HTTP request counters and timings, labelled with the route *template* (for example
  `/inbox/{inboxId}`), method and status. Requests that match no route are grouped under one label;
- gauges for the number of inboxes and blobs, stored bytes, open connections, and distinct push
  tokens;
- push outcomes by platform (`sent`, `rejected`, `failed`, `dead_token`, `dead_token_suppressed`);
- append counters by push disposition (`no_token`, `suppressed`, `waked`) and by whether a `ttl` was
  given;
- the connect-time histograms and code counters from 3.12;
- queue hand-off counts after a restart, and the host's Tor version.

No metric label contains an inbox id, a token, an app version string, or any other value a client
chooses. The only client-supplied values used as labels come from fixed lists: platform and
phase code.

---

## 8. Known oracles and limits

These are deliberate trade-offs that remain in the current design. Each one lets a caller learn
something.

- **`507` on minting.** When the relay already holds 15 000 inboxes, `POST /inbox` answers
  `507 "server inbox limit reached"` after a valid proof of work. Anyone willing to solve one
  proof of work can therefore find out whether the inbox table is full.
- **Mint-pressure census via `429` and `400`.** A `POST /inbox` without a valid proof of work gets a
  challenge (`400`) while the relay-wide challenge budget (120 per minute) has tokens left, and
  `429` once it is spent. Anonymous callers can therefore watch how many challenges are being
  requested across the relay.
- **Probe-budget state.** Failed inbox requests get `404` while the relay-wide probe budget lasts
  and `429` after it is spent. This shows relay-wide failed-request pressure, but nothing about any
  particular inbox.
- **Writer-visible inbox state.** A writer holding a valid write capability sees `429 "inbox full"`
  when the recipient's queue is at its limit, and `507 "storage quota exceeded"` when the relay-wide
  pool could not be freed. Both reveal state, but only to someone who already holds a capability
  for that inbox.
- **The relay's clock to the millisecond.** The proof-of-work token is authenticated but not
  encrypted, so its `issuedAt` field shows the relay's clock in milliseconds. So does `expiresAt`
  in the mint response. Anyone who can request a challenge can read the relay's clock offset, and
  can use matching offsets to tell that two onion addresses lead to the same host.
- **Version headers.** The `ios-version`/`android-version` headers, and the challenge format, show
  which generation of the relay and client software is running.
- **Batch peek shows a device's inbox set.** See 3.6 and section 6.
- **Diagnostic storage can be filled.** The three diagnostic endpoints have no authentication.
  Anyone can fill their storage limits, after which they answer `507` (bug reports, Debug mode
  logs) or stop storing timelines (connect reports) until old files age out. Message traffic is
  unaffected.
- **A planned restart can repeat or lose a blob.** The relay keeps serving requests while its
  shutdown routine runs. A blob retrieved after the hand-off copy is made can be delivered once
  more after the restart, and the client drops the repeat. A blob appended after the copy is made
  is lost.

---

## 9. Operator procedures that affect users

| What | When | Effect on users |
|---|---|---|
| Expiry sweep (blobs, inboxes, rate-limit state, spent nonces) | every 60 s | Expired data leaves memory within a minute |
| Diagnostic retention sweep (bug reports 90 d, connect timelines 30 d, debug logs 14 d) | hourly, with the first run about a minute after start | A file is deleted within about an hour of reaching its retention age |
| Shell snapshot | every 300 s and on graceful shutdown | See section 4 |
| Queue hand-off | on graceful shutdown only | Queued messages survive a planned restart |

**Restart behaviour.**

- *Graceful restart* (deploys, planned maintenance): shells and push registrations survive; queued
  blobs survive through the hand-off (section 4); leases are released, so blobs that were leased
  become visible again; every outstanding proof-of-work challenge is invalidated (clients request a
  new one); rate budgets and lockout backoff steps start over (lockout counters and deadlines
  themselves survive in the snapshot); metrics and histograms reset.
- *Crash or forced kill:* all queued blobs are lost, along with any shell changes since the last
  snapshot (at most 300 s). An inbox minted in that gap no longer exists. Its owner's client sees
  persistent `404`s and asks the user to pair again.
- *Failed snapshot load:* the relay starts with no inboxes and keeps serving requests. It keeps
  the unreadable file aside and refuses to overwrite it with any further snapshot until the
  operator either restores the previous copy (with a restart) or explicitly accepts the running
  state (`POST /snapshot/resume`). Until then, every client sees `404`s and pairs again if the
  state is not restored.

**Manual stale-inbox removal.** The operator can delete inboxes by expiry window through the admin
port (3.14). The relay refuses any window wider than 48 h, and any window that reaches into the
range where an inbox could still be in its bootstrap window or has had authenticated activity
within the last 90 days. In practice only promoted inboxes with no authenticated use for at least
90 days can be removed this way.

**Diagnostics deletion on request.** The operator can delete any bug report, timeline or debug log
file through the admin port before its retention period ends. Diagnostics carry no identifier, so
a user asking for deletion has to give the approximate time and platform.

---

## 10. Versioning of this specification

- **Spec version 1.2**, published 2026-11-05 (same day): the host journal now has a 30-day
  limit and the forwarder ships only the relay, Tor and proxy units. No wire change.
- **Spec version 1.1**, published 2026-11-05: section 7 first stated the production log
  retention (journal: size-capped, no time limit; log server: 30 days). No wire change.
- **Spec version 1.0**, published 2026-11-04. It describes the relay at source revision `0ab7f56`.
- The request and response bodies that carry `"v":1` (`/peek`, `/ack`, `/bugreport`,
  `/telemetry/connect`, `/debuglog`) are wire contracts. An incompatible change to any of them
  will use a new `v` value and will be listed here.
- Values marked as limits or retention periods are the relay's built-in defaults. Where the
  production instance differs, this document says so. A change to any retention period, any
  stored field, or any logged field gets a new version of this document before it is deployed.
- Section 3.15, and any other route found on the relay host that this document does not list,
  should be reported as a discrepancy.

**Production note (2026-11-04).** This revision introduces the leased fetch (`GET …?lease=1`) and
`POST /ack`, under which a message is deleted when the client acknowledges it. Production runs that
revision only once the client that uses it has shipped; until then the production relay deletes a
message on the plain fetch. Everything else in this document describes both.

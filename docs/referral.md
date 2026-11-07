# Referral-based contact adding — design & implementation plan

## Goal

Today the only way to add a contact in Rún is an **in-person QR exchange**
(`AddContactScreen` / `AddContactView`): each device mints inbox pairs, generates a
random 32-byte secret, and the two secrets are combined into a shared secret via
`deriveSharedSecret` (sort + SHA-256). The QR is the trust anchor — the secrets never
leave the two phones.

This feature adds a second path: **referral / vouching**. An existing contact who is
already paired with two people (Alice ↔ Bob and Alice ↔ Carol) can introduce Bob and
Carol to each other **remotely, over the relay**, so they become direct contacts without
ever meeting in person. "One person vouches for another when contact has been made" — the
referrer (Alice) is asserting that Bob and Carol are real people she has each verified
IRL.

## The one hard problem — read this before designing anything

Rún ships **only symmetric crypto** (`PlatformCrypto.kt`: SHA-256, AES-256-GCM,
PBKDF2-SHA256, HMAC). The current pairing builds the shared secret as:

```
sharedSecret = sha256(sort(secret_bob, secret_carol))
```

If we naively have Alice relay Bob's `secret` to Carol and Carol's to Bob (the QR exchange
but over the wire through Alice), **Alice learns both halves and can compute their shared
secret** — she can then decrypt and MITM every Bob↔Carol message forever. That silently
breaks the app's entire E2E threat model. Any plan that reuses `deriveSharedSecret` over a
relayed exchange is wrong.

The introducer must be able to pass key material **through** without being able to derive
the resulting key. That requires asymmetric key agreement. So the central decision is:

### Decision A — key agreement mechanism (REQUIRED, pick before coding)

- **A1 (recommended): add X25519 ECDH.** Bob and Carol each generate an *ephemeral*
  X25519 keypair, send their **public** key through Alice, and derive
  `sharedSecret = HKDF(ECDH(myPriv, theirPub))`. Alice only ever sees public keys, so she
  cannot derive the secret. This is the only option that preserves the existing security
  guarantee for referred contacts.
  - Cost: a new asymmetric primitive in the `PlatformCrypto` expect/actual set —
    Android via Tink (`com.google.crypto.tink.subtle.X25519`), iOS via the `runcrypto`
    cinterop or CryptoKit (`Curve25519.KeyAgreement`). This is the bulk of the work and
    must land on **both** platforms together (see the KMP expect/actual rule in ARCHITECTURE.md).
- **A2 (not recommended): trust-the-introducer at the crypto layer.** Relay the symmetric
  secrets through Alice and accept she can derive them. Cheap, but lets her read every
  message — strictly worse than A1, which keeps her to public keys only. (Note: Rún does
  trust the introducer at the *policy* layer — no verification step, Decision C — but still
  uses A1 crypto so she only ever sees public keys.)

**Recommendation: A1.** Everything below assumes A1.

## Threat model for the introducer

Even with X25519, the introducer is the routing point, so spell out what she can and
can't do:

- **Can** decline to forward, drop, or replay introduction messages (availability only).
- **Can** attempt a MITM by substituting her *own* ephemeral public key for Bob's/Carol's
  — this is the classic introduction attack. **Trade-off (Decision C):** Rún uses
  **transitive trust** — you only accept introductions from a contact you already trust, so
  there is no out-of-band verification step and a referred contact is usable immediately.
- The referral payload reveals to Alice that Bob and Carol now know each other (social-
  graph leak to the *one* person who introduced them — inherent to vouching, acceptable).

## Decision B — trust level semantics

`ContactRecord.trustLevel` exists and is currently always `VaultSeedDefaults.DEFAULT_TRUST_LEVEL = 0`
for every contact. Use it to distinguish provenance:

- `0` — IRL QR-paired (existing behaviour, unchanged).
- `1` (`TRUST_REFERRED_CONFIRMED`) — added via an introducer. Usable immediately
  (transitive trust). (`-1` "referred, unconfirmed" is a retired legacy value.)

Store **who vouched** so the UI can show "Introduced by <alias>". Add a nullable
`vouchedByContactId: String?` (and optionally `vouchedAt: Long`) to `ContactRecord`. This
needs a schema migration in `DatabaseManager` (Android/SQLCipher) and `IosVaultDatabase`
(iOS), plus the `insertContact`/`getContact`/`getAllContacts` mappers in both.

## Decision C — verification (DECIDED: transitive trust, no verification)

**Shipped decision: no out-of-band verification.** Rún relies on **transitive trust** —
you only accept an introduction from a contact you already trust, so a referred contact is
**usable immediately** with an "Introduced" provenance badge. There is no verification
step. The trade-off (an actively-malicious introducer could MITM undetected) is accepted
in exchange for the convenience that makes remote introductions worthwhile; a verification
step would reintroduce the very out-of-band exchange the feature exists to avoid. (An
earlier draft proposed a mandatory verification step; that was removed.)

## Protocol design (A1 + control channel)

Reuse the existing **control channel** — every pairing already mints a dedicated control
inbox pair (v7), drained by the background poller, carrying `controlKind`/`controlBody`
(see `MessageManager` + `GroupManager`'s invite/join/roster). Referral is a new family of
control messages, modeled closely on the group invite flow.

New `CONTROL_KIND_REFERRAL_*` kinds (direct, non-group, so `groupId == null` — note the
existing receive guard at `MessageManager.kt:991` only allows `null` groupId for
`CONTROL_KIND_INBOX`; that allowlist must be extended for the referral kinds):

1. **`referral-offer`** — Alice → Bob: "Carol (alias she'll see, a freshly minted
   introduction id) wants to connect; she vouches via me." Body carries Carol's display
   alias and an `introId` (random, correlates the two halves). Sent symmetrically to Carol
   about Bob.
2. **`referral-accept`** — Bob → Alice (relayed to Carol): Bob's ephemeral X25519 **public
   key**, plus a fresh inbox-pair offer (inboxId + write-capability) Bob minted for Carol,
   keyed by `introId`. Alice forwards verbatim to Carol; symmetric in reverse.
3. **`referral-finalize`** — once both publics + inbox offers have crossed, each side
   computes `sharedSecret = HKDF(ECDH)`, writes the `ContactRecord` (trustLevel =
   `TRUST_REFERRED_CONFIRMED`, `vouchedByContactId = Alice`) + both inbox records, and the
   new contact appears, usable immediately. Optional ack confirms liveness.

Notes:
- The introducer **forwards opaque blobs** between the two introducees but cannot open the
  resulting channel — she only sees public keys and inbox ids, never the ECDH output.
- Inbox minting reuses `MessageManager.mintInboxPair` (PoW handshake) on the introducees'
  devices, so the relay sees only ordinary inbox creation — no new relay endpoints, **no
  relay changes**. (The `?ttl` above is an already-existing relay query parameter, not a new one.)
- **Referral control traffic can now WAKE a sleeping device.** Inbound CONTROL inboxes joined
  the push-registration surface (`allPushableInboxes`, the text surface plus every
  `DIR_INBOUND_CTL` row), because with the control inbox unregistered an introduction stalled until
  both introducees happened to foreground the app. The relay wakes on any append unless the SENDER
  set `X-No-Push`, so the choice is now per-KIND at the call site: `ref-offer`, `ref-accept` and
  the group `invite` wake; the inbox announce, both screenshot notices, and the group
  `act`/`join`/`roster`/`leave` kinds are suppressed. `GroupManager.fanOutControl` defaults to
  `noPush = true` so a control kind added later is silent until someone deliberately makes it wake.
  The full table lives in `PushRegistration.kt`.
- Bound `introId` lifetime and require both halves within a window; drop unmatched halves.
- Consent: Bob and Carol must each **approve** an incoming `referral-offer` before any key
  material is generated — never auto-pair from a referral (unlike group `handleInvite`
  which auto-joins for already-IRL-verified contacts; a referral is by definition *not*
  yet verified).

## Handshake persistence & ephemerality (SHIPPED — replaces "session-scoped, never persisted")

`ReferralManager` used to keep **all** handshake state in RAM (`pending` / `offers` /
`stashedAccepts` / `introSessions` / `completedIntros`), and its header said "session-scoped
handshake state; never persisted (matches the ephemeral model)". That was **not** an
ephemerality property — it was a data-loss bug, and it is now fixed.

**Why RAM-only failed.** `scrubInMemory()` runs on ORDINARY BACKGROUNDING on both platforms
(iOS `.background` → `IosAppController.lock`; Android `onStop` teardown →
`RunViewModel.onCleared`), and `createSessionManagers` rebuilds an **empty** manager on the
next unlock. The relay's control drain is **destructive**. So an introducee that was killed
or backgrounded after its accept was sent hit the terminal
`"referral accept for unknown introId dropped"` branch and could **never** finalize — while
its peer had already committed a `TRUST_REFERRED_CONFIRMED` contact whose outbound inboxes
routed at inboxes nobody polls. A silent one-way black hole, permanent, with no re-pair UX.
The same teardown stranded an **introducer** mid-introduction (no `introSessions` ⇒ neither
accept can be relayed) and re-raised the consent dialog for an already-settled introduction
(no `completedIntros` ⇒ the documented `cross:multi3` flake).

**Where the state lives now.** The ENCRYPTED VAULT's `_meta` table — the same store the
Double Ratchet's `dr-*` state uses (`VaultDatabase.putMeta`/`getMeta`), **not** the platform
`KeyValueStore`/Keychain. Keys and codecs live in `shared/src/commonMain/.../ReferralStore.kt`:

| key | holds | created | deleted |
| --- | --- | --- | --- |
| `ref_p:<introId>` | our accepted material: introducer id, peer alias, the ephemeral X25519 **keypair**, the minted inbox pair (ids + read/write caps), `st` (send confirmed), attempts | `acceptOffer`, **before** the accept is sent (`st=0`); flipped to `st=1` on confirmed send | inside the finalize `withTransaction`; on the terminal finalize branches; on decline; TTL |
| `ref_o:<introId>` | a received offer awaiting consent | `handleOffer`, at receipt | on confirmed accept; on decline; on completion; TTL |
| `ref_s:<introId>` | introducer session: the two contacts, which side's accept has been relayed, **and which side's OFFER has provably been delivered** (`of` + the bounded `on` attempt counter) | `startReferral`, **before** either offer is sent | when **both** accepts have been relayed; TTL |
| `ref_a:<introId>` | a peer accept relayed to us before our consent | `handleAccept`'s stash branch | when applied on accept-confirm; on decline; on finalize; TTL |
| `ref_r:<introId>:<toContactId>` | an accept the **introducer** could not forward — the redrive obligation | `handleAccept`, when the relay `sendDirectControl` returns false/throws | on a successful redrive; TTL |
| `ref_done2` | bounded (128) list of `doneTokenFor(introId)` **hashes** of finalized/declined introIds (never the raw introId — see below) | `markIntroCompleted` | overwritten in place; never contact-scoped |
| `ref_done` | LEGACY (v1): same list, but held the RAW introId. Read-only; migrated into `ref_done2` and deleted on the next `rehydrate()` | (pre-fix builds only) | migrated away on first rehydrate after upgrade |

**Why the tombstone is hashed, not raw.** `referredContactIdFor(introId)`
(`ReferralManager.kt`) derives the referred contact's id **deterministically and
salt-free** from the introId — `base64url(sha256("referral-contact|"+introId))[0:18]`
— and that id is **identical on the peer's device** (both sides compute the same
finalize). The v1 `ref_done` list stored the raw introId and was deliberately
excluded from the delete-contact purge on the stated grounds that it "references no
contact". That was true of the *list*, but not of what an attacker with vault access
could **compute from** an entry: after the user deletes a referred contact, the raw
introId is still a preimage of that contact's id, so it stayed a computable,
cross-device link to a relationship the user had just erased (find it in device A's
`ref_done`, recompute `referredContactIdFor`, match it against device B's
`contacts.contact_id`). The dedupe guard this list exists for only ever needs
**equality** — "have we already settled this introId?" — never the preimage, so v2
stores `doneTokenFor(introId) = base64url(sha256("referral-done|"+introId))[0:18]`
instead: a **different**, domain-separated hash that cannot be turned back into
`referredContactIdFor`'s output. Dedupe behaves identically; the cross-device
correlator is gone. `rehydrate()` migrates any v1 entries into v2 (hashing each one)
and deletes v1, once, on the next launch after upgrade — no TTL is needed on either
list because hashing alone closes the linkability that mattered.

**TTL (raised to 7 days).** `REFERRAL_RECORD_TTL_MS` (`ReferralManager.RECORD_TTL_MS`,
renamed from the misleading `STASHED_ACCEPT_TTL_MS`) governs *every* record, so a relaunch can
never resurrect a handshake the in-session rules would already have dropped. Rehydration happens
once, in the `ReferralManager` constructor, and GCs anything expired, unparseable or over the
per-namespace cap.

24 h was too short, and the failure it produced is the very half-pair the persistence work exists
to close: the two introducees consent **independently**, so one of them can easily take longer
than a day. Three rules now:

- **7 days idle**, matching the relay's own `maxTtlSeconds` ceiling.
- **Refresh on activity** — the record's `createdAt` is re-stamped (and re-persisted) on a redrive
  attempt for it, on a peer accept landing against a consent we have not answered, and on an
  introducer relaying an accept for its session. Deliberately **NOT** on rehydrate: relaunching
  the app is not activity for any particular introduction, and refreshing there would make the TTL
  meaningless for anyone who opens the app daily.
- **An absolute 28-day ceiling** measured from an immutable `firstSeenAt` (`t0`) that refresh never
  moves — `REFERRAL_RECORD_MAX_LIFETIME_MS`. Without it, refresh-on-activity plus the per-session
  attempt reset below would let a permanently-dead introduction keep an ephemeral X25519 private
  key resident indefinitely, which is exactly the property this doc leans on to justify persisting
  that key at all. Records written before `t0` existed migrate on read (`t0 := ts`) and on write.

**Relay-side TTL.** Every referral control POST now carries `?ttl=604800`
(`REFERRAL_CONTROL_TTL_SECONDS`) — the relay's blob default is 24 h, so without it an offer or a
relayed accept could expire off the inbox a day after posting while both ends of the handshake
stayed live for a week. It is a **URL query parameter only**; the sealed envelope, its AEAD-bound
fields and the counter+epoch anti-replay rules are untouched.

**Why persisting the ephemeral private key is acceptable.** The same vault already holds
strictly more sensitive material — every Double-Ratchet chain key and every inbox **read**
capability (the inbox OWNER capability, which also authorises DELETE and cap rotation). The
referral record is single-introduction, TTL-bounded (7 days idle, 28 days absolute), and is
deleted **inside the very `withTransaction` that commits the contact**, so it never outlives the
key's one job.
`scrubInMemory()` still zeroes the RAM copy on every lock/panic-wipe — that hygiene is
unchanged; the vault copy is only a recovery source. A full wipe crypto-erases it with
everything else (Android deletes `run.db` after erasing the device key; iOS `wipeAllTables`
clears `_meta` wholesale), so the new keys need no wipe-path enumeration of their own.

**Crash-window rule (the ordering that matters).** The accept record is written **before**
`sendDirectControl` with `st=0` and flipped to `st=1` only once the relay accepted the blob.
A rehydrated `st=0` record re-sends **the same** public key and **the same** minted inbox
pair on the next control sweep — never a fresh keypair, because `sendDirectControl == false`
does not prove the blob never landed, and a new key would derive a secret the peer can never
match (the mirror image of the black hole above). For the same reason a user-driven Retry
reuses the staged material instead of re-minting. An entry that is not yet `sent` is **not
finalizable**: a peer accept arriving against it is stashed, so a referred contact is only
ever committed once both sides provably exchanged material.

**Redrives.** THREE obligations — `ref_p` with `st=0`, `ref_r`, and a `ref_s` whose `of` set
does not yet name both parties — are retried **once per control sweep** from
`ReferralManager.runMaintenance()`, wired in `createSessionManagers` to
`GroupManager.onControlSweep`: bounded to 12 attempts, no timer of its own, no tight loop, and
nothing runs without a live transport. This also closes the sibling defect where the introducer's
relay-forward ignored `sendDirectControl`'s return and swallowed a failed forward silently.

**The OFFER leg is durable too.** `startReferral` used to fire both offers and DISCARD both
return values, so one dropped circuit silently swallowed half an introduction: the introducer saw
success, one introducee never saw a consent prompt, and nothing retried. It now records the
session **before** either send (it always did), captures both results (a throw counts as
not-delivered), marks the delivered sides, and returns the introId to mean **durably QUEUED**, not
delivered. A `ref_s` from a build that predates `of` decodes as "nothing delivered" and heals by
re-offering both sides once — which the receiver dedups on `offers`/`pending`/`completedIntros`.

**Attempt budgets are PER SESSION.** Every persisted attempt counter is reset to 0 at
rehydration while the record itself is KEPT. A budget spent against a relay that was down for one
session must not permanently disarm the obligation for the life of the record — that turned a
transport outage into the same silent half-pair the redrives exist to prevent. The overall bound is
the TTL (and the 28-day ceiling), not the counter.

**The stash is consumed by the finalize TRANSACTION, never before it.** `rehydrate` and
`confirmAcceptSent` used to delete `ref_a` (RAM **and** vault) *before* calling
`finalizeFromPeerAccept`. A finalize that then failed — the retryable vault-write branch, a
transient derive failure, process death mid-transaction — destroyed the peer's accept and left this
side permanently unable to complete an introduction the peer had already committed. Both callers
now merely READ it; the finalize's own `withTransaction` deletes it atomically with the contact
commit, and its terminal branches drop it explicitly.

**`ReferralManager.onIntroFinalized`** is a nullable `(() -> Unit)?` fired once per SUCCESSFUL
finalize, outside the lock and after the transaction commits, so the platform can refresh its
contact list without polling. Rejected finalizes never fire it. A finalize that happens during
`rehydrate()` — i.e. inside the constructor, before any platform code could install a hook —
latches a one-shot deferred notice that the property's setter flushes on assignment.

**Delete-a-contact coupling (the cross-file trap).** A referral record is keyed by introId and
names its contact in the **body**, so the purge is a VALUE classifier,
`isReferralMetaResidueForContact(key, value, contactId)` — the referral sibling of
`ratchetMetaKeysForContact` / `isGroupMetaResidueForContact`. Both `VaultDatabase` actuals
(`DatabaseManager.deleteContact`, `IosVaultDatabase.deleteContact`) iterate it identically.
**Any new referral record type MUST be classified there**, or a deleted contact leaves an
ephemeral private key plus live inbox capabilities behind in the vault.

**Brick-safety.** Every decoder returns `null` on anything it cannot fully validate; a
missing/truncated/malformed record is "no record" (skip + GC + log). Rehydration cannot throw
out of the constructor, no referral read is ever an input to a wipe or unlock decision, and a
`_meta` write failure degrades the manager to the old RAM-only behaviour rather than failing
an accept the user just approved.

## Files to touch

**Shared (`shared/src/commonMain`)**
- `PlatformCrypto.kt` — new `expect` X25519 keygen + ECDH + an HKDF-Expand helper.
- `PlatformCrypto.android.kt` / `.ios.kt` — `actual` impls (Tink / CryptoKit-via-bridge).
- `DataModels.kt` — `ContactRecord`: add `vouchedByContactId`, `vouchedAt`; consider a
  `trustLevel` enum/const set in `VaultSeedDefaults`.
- New `ReferralManager.kt` (mirror `GroupManager.kt`): build/handle the three control
  kinds, state machine keyed by `introId`, consent gating, finalize → `insertContact` +
  inbox records.
- `MessageManager.kt` — register `CONTROL_KIND_REFERRAL_*`; extend the `groupId == null`
  receive allowlist; route referral control bodies to `ReferralManager`.
- `VaultDatabase.kt` + `VaultSeedDefaults.kt` — any new query for referral-pending state;
  trust-level constants. (`metaKeys()` is on the interface so commonMain can scan the
  `ref_*` namespace at rehydration.)
- `ReferralStore.kt` — the `_meta` key namespace, the record codecs and the
  `isReferralMetaResidueForContact` purge classifier (see the persistence section above).

**Storage**
- `DatabaseManager.kt` (Android/SQLCipher) + `IosVaultDatabase.kt` — schema migration for
  the new `ContactRecord` columns and their mappers (keep the two in lockstep).

**UI — Android (`androidApp/.../`)**
- `AddContactScreen.kt` — add a "Refer a contact" / "Introduce two contacts" entry point.
- Introduce flow lives in `ContactListScreen.kt` — a multi-select "Introduce … to…"
  picker (long-press a contact → "Introduce to…") + the incoming-offer approval dialog.
- `ContactListScreen.kt` — "Introduced" provenance badge on referred contacts.

**UI — iOS (`iosApp/iosApp/`)**
- `ContactListView.swift` — multi-select introduce picker + offer-approval alert + the
  same "Introduced" provenance badge as Android.
- Bridge holders if X25519 is implemented Swift-side (`runcrypto`/CryptoKit) — register in
  `AppState.init` **before** `IosAppController` (load-bearing order, see ARCHITECTURE.md).

## Testing

- `commonTest` — `ReferralManagerTest`: full handshake produces identical `sharedSecret`
  on both introducees; consent gating blocks auto-pair; an accept that arrives before this
  side consents is stashed and applied on accept (ordering); finalize writes a usable
  referred contact.
- `commonTest` — `ReferralPersistenceTest`: RESTART cases, driven by building a second
  manager over the SAME vault double (restart across an accept; restart before consent;
  introducer restart between the two accepts), plus the failed-relay redrive, the TTL GC,
  and the delete-contact purge on the shared classifier path.
- `commonTest` — X25519/ECDH known-answer vectors (RFC 7748) for both actuals.
- Migration tests on both DBs (old rows load with null vouch fields).
- E2E (the maintainer's physical-device suite, not published) — three-device cross-platform: Alice
  introduces Bob↔Carol; the referred contact finalizes and is usable immediately.

## Rollout / sequencing

1. Land X25519 + HKDF in `PlatformCrypto` (both platforms) with KAT tests — *foundational,
   nothing else compiles without it.*
2. `ContactRecord` fields + DB migrations + trust-level constants.
3. `ReferralManager` + control-kind plumbing in `MessageManager` (pure `commonTest`-driven).
4. Android UI, then iOS UI.
5. E2E + docs.

## Decisions (resolved)

1. **Crypto path**: A1 — X25519 ECDH (introducer relays public keys only).
2. **Verification**: none — **transitive trust**; a referred contact is usable
   immediately with an "Introduced" provenance badge (Decision C).
3. **Consent**: both introducees must approve an incoming offer before any key material
   is generated (no auto-pair).
4. **Provenance**: the "Introduced" badge is shown (referrer not hidden).

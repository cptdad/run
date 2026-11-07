# Vault & relay-protocol internals (authoritative reference)

**This file is the single source of truth** for the encrypted-vault security model and the relay/message protocol. Read it in full before modifying — or making any security claim about — vault/KDF/device-key/wipe code or `MessageManager`/`RatchetManager`/envelope code. ARCHITECTURE.md keeps only pointers here.

## Encrypted vault (core security primitive)

`VaultSelector` gates unlock to the single encrypted vault, implemented per platform behind the `VaultDatabase` interface (`DatabaseManager` on Android / SQLCipher, `IosVaultDatabase` on iOS). The entered PIN is checked with **constant-time comparison** against a stored verifier; on a match the PIN-wrapped SQLCipher passphrase is unwrapped and the DB opened (CR-1: the DB key is bound to **both** the PIN and a device key, so neither alone can open it). Precise limitation: the device-key factor is hardware-*rooted at rest* on both platforms — Android wraps a Tink AEAD keyset with a non-exportable AndroidKeystore key (StrongBox-preferred, `setUnlockedDeviceRequired(true)`); iOS stores the device key under `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` (keybag/UID-bound). By default (Lever B off) it is **not** Secure-Enclave-resident on iOS (no SE-generated key) and the Android Tink keyset is software once unwrapped in RAM, so on a *live, unlocked* device the default device-key half is reachable and security leans on the PIN at the **KDF below**. Don't describe the default device key as "hardware-backed" without this nuance. **The memory-hard KDF and biometric hardening ARE now implemented (do not repeat the old "not yet" wording):** new provisions and change-PIN use **Argon2id — `KDF_VERSION_3` is `CURRENT_KDF_VERSION`** (64 MiB × 3 passes; `PlatformCrypto.argon2id`); legacy `KDF_VERSION_2` (PBKDF2-600k) / v1 vaults still verify with the KDF they were written with (upgrade-only, no downgrade). And **Lever B (opt-in, HW auth-bound DB key) shipped** — Android wraps the DB key with an AndroidKeystore RSA key gated by the platform `BiometricPrompt`; iOS with a **Secure Enclave** ECIES key (`SecureEnclaveHelper.swift`) — via the `DbKeyProtector` seam (`ab:` blobs on both platforms). `VaultFactory` keeps platform-specific instantiation out of `commonMain`.

### The vault schema has NO message table (v9, 2026-09-15)

Messages are never written to disk — the store listing says so, `VaultDatabase` exposes no message method, and nothing has inserted one since 2026-05-24. But that change removed the **writer** and left the **table**, so the claim was true of the code and false of the data: a vault provisioned by a pre-2026-05-24 build and never wiped still held every message row it ever received, encrypted under a key one compelled PIN recovers. Schema **v9** destroys it, on both platforms, on the first open after the update.

- **Android** — `DATABASE_VERSION` 8 → 9. The `oldVersion < 9` step in `DatabaseManager.onUpgrade` turns `secure_delete` ON first (it is consulted at FREE time, so the pages the drop frees are zeroed as they are freed, not merely unlinked) and then runs `DROP TABLE IF EXISTS Messages`. The VACUUM that returns those pages to the OS **cannot** run there — SQLite forbids VACUUM inside a transaction and `SQLiteOpenHelper` wraps `onUpgrade` in one — so the helper records `droppedLegacyMessagesTable` and `init` issues the VACUUM as its very last statement, after the open has committed. `MigrationBundleCodec.CURRENT_SCHEMA` moves with the version (`MigrationSchemaPinTest` fails the build otherwise); the device-move bundle never carried messages, so a v9 bundle is byte-compatible with a v8 importer, which will nevertheless answer the conservative `SCHEMA_TOO_NEW` — non-destructive, and it tells the user to update the new phone.
- **iOS** — there is no `user_version` counter (the schema is idempotent-create), so the DROP *is* the migration and it replaces the `CREATE TABLE IF NOT EXISTS messages` that used to stand there. `createTables` probes `sqlite_master` for the table and only when it is present does it `DROP` + `VACUUM`, outside any transaction (`createTables` is called from `init`, never from `withTransaction`) and before `init`'s second `protectDbFiles`, which re-protects the sidecars the rewrite materialises. Absent ⇒ both are skipped, so a fresh vault never pays for a whole-file rewrite on launch.

Every step of this is wrapped on both platforms: **a vault that opened is a vault that opened.** A failed VACUUM costs unreclaimed free pages, never an unlock; on iOS a drop that did not land simply re-runs at the next open, because the probe — not a stored version — is the gate. Nothing else moved: `_meta`, `wipeAllTables`, `ratchetMetaKeysForContact`/`GroupMetaKeys` and the `VaultDatabase` interface are untouched (the interface never had a message method to remove), and the two per-contact / wipe-all `DELETE FROM messages` statements simply went away with the table. Do not re-add a message table "just for a cache": `LegacyMessageTableRemovalTest` (JVM source guard over BOTH actuals), `LegacyMessagesMigrationTest` (Android instrumented, real v8 → v9 SQLCipher fixture) and `IosLegacyMessagesDropTest` (iosTest, scripted bridge) exist to catch it.

### What can open the vault (the complete list)

Enumerating decrypt paths from the paragraph above alone MISSES one. There are **two independent** ways into the vault:

1. **The credential (PIN / passphrase)** — the CR-1 path described above: verifier match → PIN-wrapped SQLCipher passphrase unwrapped under the device key.
2. **The recovery code** — `VaultStoreKeys.RECOVERY_BLOB` (`vlt_rc`) wraps the *same stable SQLCipher passphrase* under a user-held 160-bit Base32 code, **completely independent of the PIN** (`VaultSelector.enableDbKeyAuthBindingWithRecovery` / `recoverWithCode`). It exists so Lever B cannot brick a vault when the hardware key dies. Consequences: it MUST be crypto-erased by every wipe path (it is — `IosUserDefaultsKeys.all` / `WipeRoutine`), and it is a second credential sink that needs the same rate limiting as unlock (fixed 2026-07-19). `recoverWithCode` deliberately commits the plain (Lever-B-off) blob and deletes the recovery blob **before** the vault open, so a failed open leaves a usable plain vault rather than a brick — do not "fix" that ordering. **After the open, a PRIVATE vault on a device that can still hardware-bind is re-armed at once** (`reconcileTierAfterRecovery` → `tryReEstablishLeverBAfterRecovery`): Lever B goes back on and `vlt_rc` is re-minted under the **same** user-held code, which therefore STAYS a live second decrypt path — the user-facing copy (`protection_recovery_entry_subtitle`, SECURITY_OVERVIEW "Recovery code") must say so, never "the hardware lock stays off". Only when the device can no longer bind (or the re-arm's round trip / read-back fails) does the vault stay plain with `vlt_rc` gone; a later enable then mints a NEW code.

**`vlt_rp` — the recovery-enable pending marker (2026-08-02).** Enabling Lever B is two-phase, and abandoning it between the phases (back press, auto-lock mid-transcription, backgrounding, process death) used to leave `vlt_rc` on disk forever over a still-plain vault: a live second decrypt path the user believes was never created. `VaultStoreKeys.RECOVERY_PENDING` (`vlt_rp`) is a device-key-authenticated marker armed **before** the `vlt_rc` write and cleared by every path that legitimately claims or drops the blob; `unlock()` purges an orphan only when the marker is armed AND the key blob is provably plain. Three rules that are load-bearing and non-obvious:

- **The arm-before-evidence ordering is the deliberate INVERSE of the inactivity/wrong-PIN anchors.** Those markers authorise a *wipe*, so they must never precede their evidence. This one authorises only a `vlt_rc` delete over a proven-plain blob, so the dangerous direction is a *missing* marker. Do not harmonise them.
- **`tryReEstablishLeverBAfterRecovery` clears the marker BEFORE re-minting `vlt_rc`.** That path deliberately re-mints under the *same* user-held code so the code the user already wrote down keeps working; moving the clear after the auth-bound commit re-opens a false fire that silently revokes a code the UI still promises. Two of that path's failure modes (a silent `kvPut` no-op on a locked keybag, and a throw) leave the plain+blob state permanently, so this is not a race that can be ignored.
- **Fail toward NONE on every ambiguous read, and never purge while an iOS write-ahead journal or an in-RAM pending auth-bound blob is live** — deferred journal replay can commit the `ab:` blob at a *later* launch than the one that purged, which would land an auth-bound vault with no recovery path.

The fix is prospective only: vaults that already carry an orphan have no marker and are never purged, because that on-disk state is genuinely ambiguous between an abandoned enable and a post-recovery re-establish.

### `vlt_cn` — the SQLCipher key rotation on a credential TIER UPGRADE (2026-08-02)

The SQLCipher passphrase used to be minted once at provision and never regenerated, so an archived `vlt_c` captured while the vault was weak, plus that old credential, plus the still-current device key, opened **today's** vault: a vault's effective protection was the weakest configuration it had ever had, permanently, for anyone holding a copy from that era. `VaultDatabase.rekey` + `VaultFactory.probeKey` now retire that archived wrap on the one transition where it matters.

**Scope is deliberately narrow.** The rotation fires ONLY inside `changeCredentialInner`, and only when ALL of: it is a credential tier **upgrade** (PIN → passphrase, i.e. CASUAL/PRIVATE → MAXIMUM); `vlt_rc` is **absent**; the current key blob is **plain**, not auth-bound; a live vault handle is available (`vaultProvider`, wired from `RunViewModel.vault` / `IosAppController.vault`); and no rotation is already pending. Never on a same-tier PIN rotation, never on `recoverWithCode`, never on the Lever-B enable. The recovery-blob veto is absolute: `vlt_rc` wraps the *stable* passphrase under a 160-bit code that is displayed once and never persisted, so a re-key would silently kill a code the user has written down.

**The invariant is `union {vlt_c, vlt_cn} always contains the key the file is encrypted with`** — the same shape as the read-capability rotation (below), and the reason no cross-storage-engine 2PC is needed. Batch A (one `putStringsSync`) writes the new verifier, `vlt_c` = the **OLD** key under the NEW KEK, and `vlt_cn` = the **NEW** key under the NEW KEK; only then, gated on `vlt_cn` reading back, does the re-key run. Four rules are load-bearing:

- **Decide from probes, never from `rekey`'s return value.** `sqlite3_rekey_v2` returns `SQLITE_OK` on both its commit and its rollback branch. Exactly one of `probeKey(new)` / `probeKey(old)` answering `true` is the only actionable outcome; **both or neither ⇒ change nothing and keep both records**, because `probeKey` cannot distinguish "wrong key" from "could not tell", and keeping the old key over an already-rotated file is a brick.
- **The promotion's read-back gate is mandatory.** Promotion is a pure byte copy of `vlt_cn` onto `vlt_c`, and `remove(vlt_cn)` may only follow a **proven** write: on iOS `kvPut` no-ops silently on a locked keybag while `remove` succeeds unconditionally, so a dropped copy plus a successful delete leaves `vlt_c` on the old key over a new-key file. Permanent brick.
- **`unlock()` reconciles before `migrateCredentialToCurrentKdf`**, gated on one cheap `contains` so the steady state is untouched. `vlt_c`'s key is tried first; if it opens, the rotation never landed and the record is dropped. Otherwise `vlt_cn`'s key is tried and promoted **strictly after** the confirmed open — the open is the only positive evidence about which key the file holds. Neither opening is the existing neutral `Error`: never `Denied`, never a wipe, and the records are never removed on an ambiguous path.
- **Anything that re-wraps `vlt_c` under a fresh KEK must refuse while a record is pending** — the credential change, the KDF migration and the Lever-B enable all defer benignly, because a new KEK would make `vlt_cn` unreadable and collapse the union to one record.

A change-credential that reports SUCCESS never reports the rotation's outcome: the credential change has landed, and turning a rotation that may well have succeeded into a reported failure sends the user back to re-enter a credential that already works. Concurrency is deliberately not quiesced — Android's pool NPEs when a statement is in flight, which the library turns into a loud, non-destructive `false`, and the probes decide either way.

### Android adopts SQLCipher's raw-key mode WITHOUT a rekey (2026-10-07)

Android created every vault in SQLCipher **passphrase mode**: the 32 random bytes `VaultSelector` unwraps (dbKey, "R") are stretched by SQLCipher with PBKDF2-HMAC-SHA512 × 256 000 and the 16-byte salt at offset 0 of `run.db` — on **every** open. Measured on a Samsung A13 (Dimensity 700), same file: **2090 ms** passphrase open vs **5.7 ms** raw-key open. Stretching a uniformly random 256-bit key buys nothing, so an Android vault now *adopts* raw-key mode. iOS is unchanged — it has always opened in raw-key mode with R itself (`x'<hex R>'`, `SwiftDatabaseBridge`), so it has no stretch to skip and its `VaultFactory` keeps the "unsupported" defaults.

- **No rekey, no page touched.** K' = PBKDF2-HMAC-SHA512(R, file salt, 256 000, 32) is exactly the key SQLCipher derives in passphrase mode; opening with the 67-byte raw keyspec `x'<hex K'>'` reads the salt from the same header and derives the page-HMAC key from (K', salt) exactly as after the stretch, so both modes open the byte-identical file and each reads every page the other writes. `RawKeyAdoptionTest` (androidTest, real device) is the gate and proves: passphrase-created → raw open with `cipher_integrity_check` clean and the file hash unchanged; raw-created (explicit salt) → passphrase open; raw-handle writes → passphrase read; wrong K' → non-destructive failure; a re-key from a raw-opened handle → a passphrase-mode file under the new key that can itself be adopted. If any of that ever stopped holding, adoption stops at the probe and the vault stays in passphrase mode.
- **The mode lives INSIDE the KEK-AEAD'd inner plaintext** of `vlt_c` — the bytes `aesGcmEncrypt(·, kek, VaultCryptoContexts.DBKEY_INNER)` seals, which `vlt_cn` and every `ab:` blob also wrap — never in a separate store key and never outside the KEK layer. `32 B = R` (legacy, untagged ⇒ PASSPHRASE, establish-on-read) · `33 B = R‖0x01` (PASSPHRASE, tagged) · `65 B = R‖0x02‖K'` (RAW) · anything else ⇒ malformed ⇒ the unlock's neutral `Error` (`DbKeyPayloadCodec.decodeDbKeyPayload`). **R is kept in every payload**, so every payload can always be opened in passphrase mode; the unlock tries the tagged mode first and falls back to R (`openModeOrder`). A raw-open failure is never `Denied`, never a wipe.
- **The promotion rule** (`rawKeyAdoptionAllowed` + `rawKeyAdoptionMayCommit`, both pure and pinned by commonTest `RawKeyAdoptionDecisionTest`): only after THIS unlock's vault open succeeded in **passphrase mode** with R; not when the KDF migration or the `vlt_cn` reconcile rewrote the credential blobs in this unlock; `vlt_cn` confirmed absent and no iOS write-ahead journal pending (unknown ⇒ refuse); an `ab:` blob additionally needs a **PROVEN** `vlt_rc`. Then K' is derived from the file's salt, `VaultFactory.probeRawKey(K')` must OPEN the real file, `vlt_c` must still be the blob this unlock unwrapped, and a plain blob must round-trip (unwrap + decrypt back to the exact payload) — then ONE `putStringSync` of `vlt_c`, read back. A torn or dropped write is harmless: old and new blob both carry R. New provisions run the same evidence chain right after the provision's own create, so a new Android vault is raw-key from its first unlock.
- **Lever B (`ab:`) vaults are re-wrapped during unlock, not skipped.** The re-seal is wrapped under the SAME live auth-bound key that unwrapped it seconds earlier — a public-key op with no second biometric prompt, the identical unverified re-wrap change-PIN and the KDF migration already perform — and only behind a PROVEN recovery blob, which wraps R and so stays valid (adoption never changes R). `maybeReconcileLegacyAuthBoundKey`, `setDbKeyAuthBinding`, the enable/finalize pair and `tryReEstablishLeverBAfterRecovery` all re-wrap the inner ciphertext VERBATIM, so they never disagree with the tag.
- **What can never migrate, by design.** `vlt_rc` wraps R only (the code is never persisted, so it can never learn K'): `recoverWithCode` keeps opening in passphrase mode with R, keeps its ordering (plain blob committed + `vlt_rc` deleted BEFORE the open), and commits a PASSPHRASE-tagged payload; the next normal unlock re-adopts. A key rotation pending (`vlt_cn`) blocks adoption; every re-wrap (change-PIN, KDF migration) re-seals the whole payload, so it never drops an adopted vault back to passphrase mode. A re-key's target is always passphrase mode (`rekey` hands SQLCipher the raw new bytes): the new `vlt_cn` record is a PASSPHRASE payload, the rotation probes probe the OLD key in every mode its payload offers, and the vault re-adopts on the unlock after the rotation resolves. Debug and release builds behave identically here (this is not the Argon2 cost gate).
- **Costs and trade-offs.** The adopting unlock pays the passphrase open plus one PBKDF2 (≈2 s each on an A13) once; steady-state unlocks then skip it. K' sits next to R inside the same KEK-AEAD — no new secret, it is a function of R. **Downgrade**: an older build reading a 33/65-byte payload hands it to SQLCipher as a passphrase and gets `NOTADB` ⇒ the neutral, non-counting `Error` on every unlock until the app is upgraded again (no wipe, no data loss; Play/App Store do not offer downgrades).

### A device with no lock screen is FORCED to MAXIMUM (2026-07-21)

`DeviceLockPolicy` (commonMain) holds the rule and both platforms consume it; nothing about it is duplicated per-platform except the probe itself (`KeyguardManager.isDeviceSecure` / `LAContext.canEvaluatePolicy(.deviceOwnerAuthentication)`).

**Why.** Without a lock screen the device-key factor of CR-1 is free to anyone holding the phone: iOS cannot satisfy `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`, so `KeychainHelper` falls back to `AfterFirstUnlockThisDeviceOnly` (readable in any AFU extraction), and on Android `setUnlockedDeviceRequired(true)` is vacuous while Lever B cannot exist at all. CR-1 collapses to ONE factor — the credential, over Argon2id. CASUAL's 6-digit PIN is ~20 bits, i.e. a compute budget rather than an infeasibility; MAXIMUM's ≥70-bit passphrase (`CredentialPolicy.MIN_PASSPHRASE_BITS`) still holds after a full device-key capture.

Three load-bearing details:

- **Only a DEFINITE "no lock" forces.** `DeviceLockState.Unknown` (an ambiguous `LAContext` error) leaves the chosen tier alone — the same fail direction the four existing iOS probe sites use. Forcing an irreversible credential migration on probe noise is worse than missing one launch, and the check re-runs on **every unlock**.
- **The check runs at unlock, not just at onboarding** (`postUnlockRoute` / `ContentView.needsForcedProtection`). Gating the chooser alone misses the phone that HAD a lock at provision time and lost it after: on Android CASUAL nothing else notices (no auth-bound key to invalidate). iOS is partly self-solving — the `WhenPasscodeSet` purge takes the device key *and* the recovery blob with it.
- **The forced route reuses the settings flow** (`ProtectionLevelSettingsScreen`/`View` with `forced = true`), because that is the only path that drives the credential change inline. Persisting the tier alone would claim a passphrase the vault doesn't have — an over-claiming failure. It offers no cancel; the way out is setting a device passcode, which retires the forcing on the next unlock.

The forced tier carries MAXIMUM's **7-day inactivity self-wipe**, which this user never opted into, so applying it requires an explicit acknowledgment naming that consequence (`protection_forced_notice` / `protection_forced_ack`).

### A tier read is only trusted for ENFORCEMENT if it was AUTHENTICATED (2026-07-30)

`vlt_lvl` selects the inactivity-wipe window, the wrong-credential budget and the auto-lock timeout,
so a forged value is a security downgrade. `readSelectorMeta` has always had a legacy-cleartext
fallback: if AEAD decryption fails and the value is not blob-shaped it returns the raw string, so
vaults written before selector metadata was sealed keep working. The hole was that a filesystem-write attacker could plant the six
bytes `casual` — which decodes to 4 bytes, under the 28-byte blob threshold — and have it classed as
legacy cleartext and honoured.

The rule now: **`readSelectorMetaRaw` reports whether the value came from a successful AEAD decrypt,
and `protectionLevelForEnforcement()` fails secure to `Present(MAXIMUM)` for anything
unauthenticated.** The purely display-only reader (`protectionLevelOrNull`) keeps the lenient read,
so a genuine legacy vault still shows its true tier and still migrates on write. **But the
forced-MAXIMUM floor gate reads `protectionLevelForFloorCheck()` (2026-08-26), NOT the
lenient reader**, and `currentProtectionLevel()` resolves through it too — an unauthenticated
(planted cleartext) `vlt_lvl` is treated as "not proven at the floor ⇒ force the migration", never
as a trusted MAXIMUM. The forced flow re-writes an *authenticated* level on completion, so a genuine
legacy vault self-heals on its first tier write rather than looping.

**`isPassphraseMode` is NOT one of them (2026-08-01).** It reads the same
legacy-cleartext-tolerant slot (`vlt_m`) but it picks the ENTRY WIDGET, and on a MAXIMUM vault the
three planted bytes `pin` select the 6-digit keypad — which Lever A's ≥70-bit floor guarantees can
never enter the real credential, so every auto-submitted entry is durably counted and MAXIMUM's
budget of 5 emergency-wipes a vault that has no recovery code (that is tied to Lever B / PRIVATE).
So an unauthenticated `vlt_m` now fails **OPEN to the passphrase field**, the same direction and for
the same reason as the damaged-blob branch: unlock is input-widget-agnostic, so a PIN user can still
type six digits into a text field, while the keypad hard-locks a passphrase user out. Its sibling is
load-bearing and must move with it — `changeCredentialInner` resolves an unauthenticated mode from
the NEW credential's *shape* (`resolveChangeCredentialMode`), never from the stored token, or a
rotation would re-persist the plant AUTHENTICATED over a credential the keypad cannot enter. The
untrusted token still gets one vote, tightening-only: if it claims `phrase`, the Lever A floor is
still applied. Do **not** "fix" this by migrating an unauthenticated `vlt_lvl` to an
authenticated blob on unlock: that blesses an attacker's planted value the first time a coerced user
unlocks, which reopens the planted-cleartext hole in the coercion model. It was considered and rejected.

**…and every TIER-UPGRADE decision asks a different, proof-gated reader (2026-09-22).** The fail-open answer above is right for the widget and for `changeCredentialInner`, but
it is the wrong input for "may this upgrade to MAXIMUM skip the credential rotation?": ≥28 bytes of
base64 garbage planted in `vlt_m` made `isPassphraseMode()` say `true`, so the upgrade became a pure
metadata write — an AUTHENTICATED `vlt_lvl=maximum` over an unchanged 6-digit PIN, permanently
satisfying the lock-less floor. `VaultSelector.credentialKindProven(): Boolean?` is the tri-state
those four sites (both Settings apply paths, both one-time choosers) consume through
`ProtectionUpgradePlan.needsCredentialChange`: `true` only from an AEAD-authenticated `vlt_m ==
phrase`, `false` for an authenticated `pin` or a genuinely absent marker, `null` for anything damaged
or unauthenticated. Only `true` skips the rotation; `false` and `null` both route through it, which
also re-persists `vlt_m` authenticated. The two readers must NOT be merged: the widget must fail open
(a passphrase user behind the keypad is locked out), the upgrade must fail closed (a PIN user labelled
MAXIMUM is over-claimed). Deliberately NO guard at `setProtectionLevel` itself — the one-time
chooser's unproven write is what re-arms the floor rather than escaping it.

`ProtectionLevelRead` is four-state, and the distinction is load-bearing:

- **`Damaged`** — the device key works but this one value failed AEAD, i.e. tamper. Selects
  MAXIMUM's policy window. Previously collapsed into `Unreadable`, which meant one flipped byte
  inside the base64 permanently disarmed the 7-day dead-man's switch.
- **`Unreadable`** — the device key is transiently unavailable. Still defers (`null` threshold),
  because a healthy blob is indistinguishable from a damaged one when the key cannot be used.
- **`Absent`** — establish-on-read, legacy default window. Deleting the value is not tamper.

**`Damaged` selects a policy window; it is never itself a wipe trigger.** A wipe still requires
independent positive evidence (a decryptable timestamp genuinely past the window, or the deletion
anchor below). Keep it that way.

The sealed last-active record is `InactivityPolicy.formatStamp`'s `<wallMs>[|<uptimeMs>]` — the wall
clock plus a kernel-uptime anchor inside the same AEAD blob (2026-08-01). Expiry is the
**disjunction** of a wall-clock term and a monotonic term; the monotonic one must never *veto* the
wall-clock one, because a mono delta that understates real elapsed time (reboot, or iOS `systemUptime`
not advancing in deep sleep) would then be a permanent disarm. A backward wall step needs
`CLOCK_BACK_TOLERANCE_MS` (24 h) of slack before it counts, and is skipped entirely when a same-boot
anchor vouches for the elapsed time — the old zero-tolerance rule crypto-erased the vault, recovery
blob included, on an ordinary NTP correction. Legacy bare-decimal records still parse (wall-clock
rules only, i.e. the old behaviour) and migrate on the next write.

Related, same shape: the Android inactivity timestamp now has a deletion anchor
(`inactivity_armed_v1` in `vault_selector_prefs`, the fate-shared store holding `vlt_c`), mirroring
`PinAttemptsStore`'s deletion anchor — marker armed + timestamp absent + vault configured means
deliberate deletion; marker absent means establish-on-read and never a wipe. **The ordering is the
invariant: the timestamp must be written DURABLY (`commit()`, return value checked) before the marker
is armed.** Arming a durable marker over an `apply()`'d timestamp lets a crash between them wipe a
legitimate vault, and a read-back gate does not substitute — `getString` reads the in-memory map that
`apply()` already updated. iOS keeps both items in the Keychain KV service for the same reason: a
UserDefaults pair is deletable by exactly the adversary this defends against, and
`UserDefaults.set` has the same async-flush hazard as `apply()`.

### Security decisions read SEALED preferences, never plaintext; `vlt_rc` is classified, not presence-checked (2026-09-23)

`SealedPref` (commonMain) is the one primitive for a preference that feeds a security decision: a
device-key AEAD envelope with the SLOT NAME as authenticated context, NUL-padded to a fixed length,
read back as a four-way provenance — `PROVEN` / `ABSENT` / `UNAUTHENTICATED` / `UNREADABLE`. A
consumer honours `PROVEN` only; a planted plaintext, a blob copied from another slot or another
install, and a damaged blob are all "not on". It gives NO freshness: a blob the same device sealed
earlier still decrypts, so any slot where a replay matters must carry its own epoch (below).

- **Debug-log consent** (`debug-mode-consent:v1`, Android — iOS was already Keychain): sealed ON,
  plaintext `"0"` remains the revocation belt (revoking must work exactly when sealing cannot).
  Deliberately NO legacy migration — a plaintext `"1"` is byte-identical to a plant; the user
  re-consents with one tap. Replay of an old sealed ON is accepted (it only re-enables redacted
  uploads this device once consented to).
- **Push consent** (`notif_consent`, both platforms): the ONLY reader a vendor-push registration
  (FCM / APNs / UnifiedPush / `registerRefs`) may use is `NotificationLevelStore.provenLevel`. The
  plaintext `notif_level` is demoted to the locked-screen WAKE GATE the push-wake processes read
  (no device key there) and has no vote on minting. The sealed payload is `"<level>:<epoch>"` and
  the vault `_meta` singleton `notif_consent_v1` holds the current epoch: a blob is proven only at
  `epoch == vault` (or `vault + 1`, the seal-first/latch-last crash window, which heals forward);
  older is `UNAUTHENTICATED`. Every proven write and every opt-out seals at `epoch + 1` first and
  records it second, so a filesystem image restored after an opt-out cannot revive the consent. The
  legacy plaintext is honoured ONCE, at the first vault-open read with no latch (epoch 1); with the
  latch present an absent proof means "removed", not "fresh install". No vault open ⇒ OFF, never a
  migration — which is why the iOS APNs request moved AFTER unlock. The marker is global: not in
  `ratchetMetaKeysForContact`, not in `GroupMetaKeys`, denied by `MoveMetaPolicy`. Known limitation:
  an opt-out taken in a push-wake process with no vault open is invalidated at the next vault-open
  read, so a restored blob wins that one window.
- **`vlt_rc`** is classified by `classifyRecoveryBlob` (decrypt under `VaultCryptoContexts.RECOVERY`), and three
  deliberately non-equal predicates consume it: `recoveryBlobVetoesRotation` and
  `recoveryPathOffered` are true for PROVEN **and UNREADABLE** (a transient device-key outage must
  never enable the `vlt_cn` re-key that would orphan a real blob), `recoveryBlobUsableAsNet` for PROVEN
  only (Lever B never arms over a forged net). `recoverWithCodeInner` splits the device-layer and
  code-layer decrypts so a forged blob answers the neutral `Error`, never `Denied` — the wipe budget
  is spent only on a wrong code against a REAL blob. The `vlt_cn` rotation never touches `vlt_rc`; a
  forged blob is left inert and classifies FORGED on every later read.

### No Android prefs write may use `apply()` (2026-07-31)

Broader than the anchor ordering above, and for a different reason: `apply()` SNAPSHOTS the whole
in-memory map and flushes it later, `Context.deleteSharedPreferences` neither cancels nor awaits that
flush, and `SharedPreferencesImpl.writeToFile` only short-circuits a no-change write **when the file
still exists**. So a write issued moments before a wipe lands *after* it and RE-CREATES the file from
the pre-wipe snapshot — `vlt_a`, `vlt_c` and `vlt_rc` back on disk, dated after the crypto-erase, and
on the next launch that reads as configured-but-unreadable and re-arms the orphan wipe. Every
SharedPreferences write in the Android app now uses `commit()` (`KeyValueStore.putString`/`remove`,
`InactivityWipe.refreshMtimeProbe` were the last `apply()` sites); `PrefsApplySourceGuardTest` pins
that there are no others. `KeyValueStore.remove` additionally returns early when the key is absent —
`edit().remove()` on a missing key still MINTS the file when the file is gone, and `VaultSelector`'s
constructor issues four unconditional removes on every construction, three times per launch.

**This is deliberately NOT a `ProcessWipeLatch` gate.** The latch stops a write *issued* after a wipe;
this one is issued before it and merely *lands* after, so a latch cannot cancel it. Worse, the writes
a latch would block are the load-bearing ones — `provisionCredentialAndVault` persists the verifier
and the wrapped DB key through `putString`, and re-provisioning in the same process after a wipe is a
supported route — so gating them would give Android the silent-write-failure mode iOS's locked-keybag
`kvPut` has: a vault file with no credential behind it. iOS needs no sibling change here; Keychain
writes commit synchronously, and `NSUserDefaults` mutates one shared domain dict (no per-write
snapshot), so a later `removeObject` + `synchronize` always wins.

### Argon2id cost is pinned PER VAULT, not read from the constants

A v3 credential blob stores its own Argon2 cost (`m ‖ t ‖ p`, appended after the verifier — the 58-byte layout) and **re-derives with that pinned cost on every future unlock**. The `ARGON2_*` constants govern what a *new* blob pins, not what an existing vault uses; that is what makes a cost change a per-vault migration instead of a brick-everyone.

Two things follow, both load-bearing:

- **Debug builds provision and unlock at a WEAK cost** — `1 MiB × 1 pass` versus the release `64 MiB × 3` (`runtimeArgon2MemoryKiB` / `runtimeArgon2Iterations`, gated on `isDebugBuild`). A debug vault is self-consistent and is never opened by a release build in normal use.
- **…but data can outlive the build that wrote it.** A vault provisioned by a debug build and carried into a release binary (iOS dev/TestFlight → App Store in-place upgrade preserves app data) keeps its pinned weak cost. `assertKdfBuildIntegrity` checks the cost this build would WRITE, not the cost STORED, so it passes and never notices. Since 2026-07-19, a release build re-pins such a blob to the release cost on the next successful unlock — see `needsCredentialRewrap`, which is the single decision point for both this and the v1/v2 → v3 upgrade.

### Android runs Argon2id natively — same sources as iOS, BouncyCastle only as the link-failure fallback (2026-10-07)

The Android `argon2id` actual (`PlatformCrypto.android.kt`) calls `librunargon2.so` first: the vendored PHC reference C under `iosApp/Argon2/` — the exact files iOS links, compiled in place by `shared/src/androidMain/cpp/CMakeLists.txt` (`-O3`, `ARGON2_NO_THREADS`, only the JNI symbol exported), entered via the same `argon2id_hash_raw` (`NativeArgon2.argon2idRaw`). Same algorithm, same cost, same output: BouncyCastle took 3.79 s at the release cost on a Samsung A13. Rules: (1) BouncyCastle (`argon2idBouncyCastle`) runs ONLY when the library cannot be linked (`UnsatisfiedLinkError` on load or on the JNI symbol, logged once with no inputs); an argon2 error code from the native code is THROWN, never retried on BouncyCastle — the reference C rejects inputs BouncyCastle silently clamps (m < 8·p KiB, salt < 8 B), none of which any provision ever wrote. (2) Every existing Android vault was derived by BouncyCastle, so byte equality is the gate, not a nicety: `Argon2BouncyCastleKatTest` (JVM) pins BouncyCastle to RFC 9106 §5.3, the PHC vectors and the vault release/debug cost vectors (derived from the vendored C), and `Argon2NativeEquivalenceTest` (on device) proves the .so equal to BouncyCastle at those costs plus 20 random pairs. (3) `scripts/verify-argon2-src.sh` now pins the KDF core of BOTH apps; R8 must keep `com.vg.run.NativeArgon2.argon2idRaw` by name (`androidApp/proguard-rules.pro`), or release builds silently drop to the slow path. The .so ships for the same four ABIs as Tor/SQLCipher.

### iOS multi-key writes must be journalled

The Keychain has no multi-item transaction, so coupled writes (verifier + wrapped DB key) go through `putStringsSync` (`KeyValueStore.ios.kt`) — a hand-rolled write-ahead journal under `vlt_txn_journal`, with read-back-gated cleanup and `recoverPendingBatch` on the next construction. Change-PIN, KDF migration, recovery-enable and the legacy key-name migration all depend on it. Never issue sequential `kvPut`s for a coupled pair: `kvPut` **fails silently on a locked keybag**, so any unguarded copy-then-remove on the credential path can destroy the only copy.

That silence propagates upward, and the two fixes for it fail in OPPOSITE directions on purpose (2026-08-01):

- **Deleting the recovery blob needs positive proof** (`plainDbKeyReadBackProves`, used by `recoverWithCode` and `setDbKeyAuthBinding(false)`). `putStringSync` returns `Unit` and may write nothing, while `remove` is a bare `SecItemDelete` that needs no class key and still succeeds — asymmetric failure that leaves an `ab:` blob wrapped by an already-dead hardware key with its only recovery path gone. So the plain blob must READ BACK before the `vlt_rc` delete. Ambiguity keeps the recovery blob (a stale one is a harmless orphan; a missing one is a brick), and `recoverWithCode` then returns the neutral `Error`, which both recovery screens roll back off the wipe budget.
- **Reporting a change-PIN as FAILED needs positive proof** (`credentialWriteRefuted`). Both wrong answers are destructive here — a false SUCCESS leaves the user entering a PIN that was never set, a false FAILURE leaves them entering one that no longer works, and either way those attempts count toward a wipe. So an ambiguous read refutes nothing, and only the credential PAIR (`vlt_a` + `vlt_c`) is verified: a torn write that dropped only the trailing `vlt_m` really did rotate the credential, and the journal replay repairs the marker. On Android the read-back sees the in-memory map `commit()` already updated, so it catches nothing there — accepted, and not a false positive.

Related: `isConfigured()` **fails toward `true`** on any transient store error — deliberately, because a false "not configured" routes a real vault into provision-over-itself. New callers must not treat `configured == true` as proof a vault exists.

### The provision guard: never provision over an existing vault file (2026-07-22)

`isConfigured()`'s fail-toward-true was the *only* thing standing between a bad store read and total data loss, and it is a single point of failure: it can only defend the routes it is on, and on iOS the UserDefaults plist backing it is itself lock-gated (NSFileProtectionComplete), so it reads empty on a locked/prewarm launch. When anything reaches first-run setup on a provisioned install, completing setup is destructive — `provisionCredentialAndVault` opens `run.db` with a NEW db key, the existing file reads as `SQLITE_NOTADB`, and the `isProvision && NOTADB` branch **deletes it**. A live vault and a corrupt header are indistinguishable at that point; both are just `NOTADB`.

The fix is two layers, both keyed on the **filesystem** rather than the credential store — an independent witness that does not share the store's failure mode:

- **Routing (primary).** Never show first-run setup when a vault file exists: `isConfigured() || vaultFileExists()` ⇒ unlock (`MainActivity.startDestination`, `AppState.vaultPresent()` feeding `isConfigured`). On iOS this is scoped to *routing only* — the orphaned-credential and inactivity wipes still read `controller.isConfigured()` directly, because those are questions about credential state and widening them would change which vaults get wiped.
- **Provision guard (backstop).** `provisionCredentialAndVault` throws `ExistingVaultException` before writing anything if `vaultFactory.vaultFileExists()`. `setRealCredential`'s Boolean overload converts it to `false` so it never crosses the non-`@Throws` Swift bridge.

`VaultFactory.vaultFileExists()` is deliberately **not defaulted** — a default would have to be `false`, silently disarming the guard at any call site that forgot it. Build factories via `androidVaultFactory(context)` / `iosVaultFactory()` so the probe and the open can never disagree about which file they mean; on iOS both resolve through `iosVaultBaseDir()` for the same reason (a duplicated Application-Support-else-Caches fallback could have the guard checking one path while the destructive branch deletes another).

**Consequence to know about:** the guard deliberately leaves an unopenable dead end — vault file present, credential confirmed absent — rather than resolving it destructively. `VaultSelector.orphanedVaultFile()` detects exactly that, and the unlock screen offers an explicit, confirmed "Erase and start over" (`erase_orphaned_vault_button`). Two gates keep that offer away from healthy vaults: `orphanedVaultFile()` is `false` whenever the store is merely unreadable (because `isConfigured()` fails toward true), and callers additionally require the device to be unlocked / protected data available. On iOS the erase goes through `AppState.eraseOrphanedVault()` → `emergencyWipe(deniable: false)`: a panic wipe latches a black screen for deniability, but a user who asked to start over must land on setup.

### The provision itself is now ATOMIC and VERIFIED (2026-08-09)

The guard above stops a provision from destroying a vault. It said nothing about a provision that half-succeeds, and that is what reached the App Store: `provisionCredentialAndVault` wrote the credential verifier (`vlt_a`), the wrapped DB key (`vlt_c`), the mode (`vlt_m`) and the tier (`vlt_lvl`) as **four independent, un-journalled, unverified writes**, and `setProtectionLevel` wrote `vlt_lvl` as a fifth. All of them reach iOS `KeychainHelper.kvPut`, which is fire-and-forget **and** fail-closed: when the strict `WhenPasscodeSet` add fails while `deviceHasPasscode()` transiently answers true, the `AfterFirstUnlock` fallback is skipped and the item is **silently dropped**. Nothing upward could tell. Three self-re-arming loops followed, and none of them is a wipe — they are *stuck* states:

- **dropped `vlt_c`** ⇒ next launch reads creds-without-dbkey ⇒ `purgeHalfCredentialPairIfNeeded` clears the whole credential set ⇒ `isConfigured()` false ⇒ first-run setup again — now over the `run.db` the failed provision already materialised, which the guard then (correctly) refuses forever.
- **dropped `vlt_lvl`** ⇒ reads as "no tier ever chosen", exactly what `needsProtectionChoice` / `DeviceLockPolicy.needsForcedMigration` gate on ⇒ the protection chooser on **every** unlock, each pass dropping the write again.
- **dropped `vlt_m`** ⇒ reads as PIN mode ⇒ the 6-digit keypad on a passphrase vault, whose entries Lever A guarantees are wrong, each durably counted, and MAXIMUM's budget of 5 emergency-wipes a vault with no recovery code.

Four rules now, and each is load-bearing:

- **All four values land in ONE `putStringsSync` batch, then READ BACK.** Android becomes atomic (one editor `commit()` instead of four); iOS becomes journalled and replayable. `storeWriteProven` is the gate and is the **deliberate inverse** of `credentialWriteRefuted`: there both wrong answers are destructive so ambiguity refutes nothing, while here nothing depends on the write yet, so ambiguity is **not proof** and the provision fails. Do not harmonise their fail directions. Read its `true` as **iOS-proof / Android-residual**: on iOS it is a real Keychain round-trip, on Android it reads the in-memory map `commit()` already updated, so a failed disk commit still reads back (covered instead by the single atomic commit and the loud `commit() == false` log). `false` is trustworthy on both.
- **A failed provision ROLLS ITSELF BACK, including the `run.db` it just created — but the unlink is CONDITIONAL.** This is the only legal vault-file delete outside a wipe (`VaultFactory.deleteVaultFileAfterFailedProvision`, one caller). It is safe *only* because the guard proved no file existed at the top of the same invocation, so the file is one this call created seconds earlier under a key that never left its locals — zero user data. Order: **journal FIRST**, then the credential pair (crypto-erase before the file), then the metadata (`PROVISION_ROLLBACK_KEYS`, pinned — anything added to the batch must be added to it). The unlink then runs **only if `mayDeleteVaultFileAfterRollback` proves every `PROVISION_FILE_DELETE_BLOCKERS` key (journal, `vlt_a`, `vlt_c`) confirmed absent.** `kvRemove` discards its `OSStatus`, so a silently-failed removal is possible, and the state a wrong bet produces is the **inverse** of the orphan and the one dead end nothing escapes: a surviving credential record — or a surviving journal that `recoverPendingBatch` replays back at the next construction — over a DELETED `run.db` means `isConfigured()` true with no database, i.e. a permanent non-counting `UnlockResult.Error` on every unlock, while `orphanedVaultFile()` (`vaultFileExists && !isConfigured`) is exactly the opposite test and never fires. Keeping the file is always the safe side: it holds nothing, and the state degrades to a working vault (full journal replay) or to `orphanedVaultFile()` and its confirmed erase.
- **This is what keeps honest users off the orphan screen.** Routing is an OR-gate (`isConfigured() || vaultFileExists()`), so a leftover `run.db` with no credential sends the user to an unlock prompt that rejects every entry. `orphanedVaultFile()`'s confirmed "Erase and start over" is the right backstop for a *genuinely ambiguous* file — both torn halves reach it — but landing there because our own write failed was the bug.
- **`setProtectionLevel` returns `false` on an unproven write.** Every shipped caller already aborts its apply on `false`, so nothing changed at the call sites; what changed is that a dropped tier is now reported instead of looping. `writeSelectorMeta` (encrypt-then-`putString`, verify nothing) is **deleted** — no selector value may be persisted again without riding the provision batch or gating on `storeWriteProven`.

`putStringsSync` still returns `Unit` on a torn apply, and deliberately: it keeps its journal, so the write may yet land, and throwing would report change-PIN / the KDF migration / the Lever-B finalize as FAILED over a write that succeeds later — the false-FAILURE hazard. Each caller decides for itself, with the fail direction that suits it; both actuals now log the torn apply loudly (and Android logs `commit() == false`, the only drop signal it has, since `getString` there reads the in-memory map the editor already updated).

> Note: Rún previously shipped a second "decoy" vault for plausible deniability. That feature was **removed**. `VaultSelector` retains a one-time purge of leftover decoy credential/DB-key blobs and the wipe paths still delete a stale `run_b.db`, so installs provisioned before the removal are cleaned up — don't reintroduce decoy code paths.

## Relay & message protocol (`MessageManager`)

Custom **capability-based** HTTP API on the relay (not REST-conventional):

- Inboxes are PoW-minted (`mintInboxPair`, bounded grind budget). Each holds an opaque `inboxId` plus a read and a write **capability** (bearer tokens), not a guessable id+secret.
- `POST /inbox/{id}` — send (requires `X-Write-Capability`). `GET /inbox/{id}?lease=1` — poll (requires `X-Read-Capability`); since 2026-11-03 it LEASES and deletes nothing — `POST /ack` deletes (see "Retrieve-ack" below). The bare `GET /inbox/{id}` still deletes at fetch on the relay (every released client) and is never used by the app any more. `PUT /inbox/{id}/read-capability` / `.../write-capability` — rotation (both require the **read** cap). Caps are validated for control chars + length before they enter any header (CRLF/header-injection guard).
- Wire format (legacy/fallback path): AES-256-GCM with `key = sha256(sharedSecret)` and AEAD context `sha256(key + "message-aead")` as AAD. Layout `IV(12) ‖ ct ‖ tag(16)`. NOTE: this static-key path has NO forward secrecy (compromise of `sharedSecret` decrypts all past + future static-key blobs); the "epoch" (`messageEpoch`) is an anti-replay tag, not a rekey. **BUT the Double Ratchet IS wired for the text channel** (`RatchetManager`, `MessageManager` send/receive) — once engaged (self-describing wire + first-inbound-gated enablement) the text channel has forward secrecy; the static envelope above is the legacy/pre-ratchet fallback, not the whole story. Precisely: a pairing's texts ride the static envelope **until the first inbound text from the peer** — unbounded for a peer that never sends (a one-directional conversation stays on the static envelope for as long as it stays one-directional); the shared secret stays at rest for every pairing regardless, so this adds no forensic exposure beyond what the pairing already carries.
- Anti-replay: a per-contact **monotonic counter + epoch** are sealed inside the AEAD; receive enforces strict-monotonic after an in-drain sort, top-level JSON is parsed depth-1 to block poisoning, and legacy no-counter envelopes are hard-dropped.
- **Two more AEAD-bound fields beyond counter+epoch** (both enforced on receive, not merely parsed — `AntiSpliceReplayTest` covers each end-to-end):
  - `"ch"` — **channel tag** (`"m"` main / `"c"` control / `"g"` group text — see the third-inbox-pair section below). Each of the pairing's inboxes keeps an INDEPENDENT counter space, so without this a relay could move an authentic blob between them and it would pass the replay check. Once a peer has been seen tagging, an untagged blob from it is dropped as a downgrade; a genuinely legacy peer never sets that marker and stays accepted.
  - `"di"` — **destination-inbox id**. Distinguishes DIRECTION within a channel, which `ch` cannot: it defeats a relay reflecting your own outbound blob onto your inbound inbox (both are `"m"`, and the two directions have separate counter baselines). Same capable-peer downgrade rule as `ch`.
- Padding: power-of-two buckets 256 B → 131 KB + random fill, hides plaintext length from the relay and any observer.
- Envelope: richer than `{"t","m"}` — carries epoch/counter/routing fields. Legacy no-counter / plaintext-only envelopes are **hard-dropped** on receive (`parseEnvelope` returns null → the caller `?: continue`s) — consistent with the anti-replay rule above, NOT "still accepted".
- Self-healing: the relay collapses NOT_FOUND/UNAUTHORIZED/LOCKED into a single `404`. A **persistent 404 streak** (relay up, inbox gone — e.g. cap rotated out) flags the contact for re-pair on the control and message channels (the GROUP channel is deliberately excluded — it self-heals in band by re-mint + re-announce; see the third-inbox-pair section below). Relay-loss state is `SyncLock`-guarded since the channels poll on different coroutines. `429` backs off silently. Inbound and outbound use **separate inboxes** (plus a separate control-inbox pair and, since v10, a group-text pair) to avoid echo loops.

### Retrieve-ack: the relay deletes on ACK, not on fetch; the screens persist + ack only once a message is on screen (2026-11-03)

Relay side: the relay's `retrieveCore`, `authenticatedAck` and `post("/ack")` handlers. Delete-on-fetch lost every message whose response died over Tor or whose app was
torn down with a GET in flight — which is why the conversation screens used to require "leave with the back arrow".

- **Wire.** Every client drain is `GET /inbox/{id}?lease=1` (`MessageManager.RETRIEVE_LEASE_QUERY`, set in `prepareDrain`
  — the ONE drain funnel for text, control and group inboxes, so the group fan-out leases too). Answer
  `{"blobs":[b64…],"ids":[…],"token":"…"}`: nothing is deleted; the returned blobs are LEASED (60 s on dev,
  relay-configurable) — invisible to every other retrieve AND peek — until `POST /ack`
  `{"v":1,"items":[{"id","rc","token","delete":[ids]}]}` deletes the listed ids and RELEASES every other blob of that token
  at once. Idempotent; unknown ids ignored; ≤ 64 items, ≤ 256 ids per item, ≤ 256 KiB at the relay endpoint but 128 KiB
  at the reverse proxy in front of it, which is the limit that applies (client byte budget `ACK_BATCH_MAX_BODY_BYTES` =
  100 000 — `chunkAcks` splits). No auth header: the read cap rides the body exactly as in `POST /peek` (owner capability; the same
  `isValidInboxId` / `capValidForHeader` gate runs first). Relay `token`/`ids` are UNTRUSTED input: both must be 22-char
  base64url (`isValidBlobRef`) and `ids` exactly as long as `blobs`, or nothing is acked for that drain (the lease
  expires; a release-only ack would just loop a batch we cannot settle). `token == ""` = empty inbox. An answer with NO
  token is a relay that predates the lease (it ignored the query and deleted at fetch): no ack, and a screen drain commits
  INLINE — byte-for-byte today's semantics, so the client ships safely ahead of the prod relay.
- **Per-blob outcome** (`MessageManager.BlobOutcome`, recorded per blob position in the drain's `BlobLedger` by the phases of `finishDrainCoreHoldingSecret` — `splitDrainBlobs`, `drainRatchetHalf`, `openLegacyBlobs`, `applySortedLegacy` — and turned into the ack by `buildDrainOutcome`):
  `ACCEPTED` (authenticated and taken — surfaced or applied), `REJECTED` (tamper, malformed base64 / too short, replay /
  duplicate / re-delivery, wrong epoch / channel / inbox binding, unknown kind, text-lock / announce-lock / sealed-control-lock drops), `DEFERRED` (sealed
  control parked in `dr/<id>/ctl-deferred` — the vault copy is the one retried) → all ACKED; `NOT_PROCESSED` → never
  acked: the ratchet cutoff tail after `MAX_CONSECUTIVE_FAILURES_PER_BATCH`, a blob refused only by a spent per-drain
  `RatchetWorkBudget` (`refusals()` counter), everything past `MAX_BLOBS_PER_POLL` (2048 — the tail used to be silently
  LOST), a blob held behind an uncommitted screen advance (below), and the legacy batch whose baseline could not be persisted
  (its earlier deliberate drop is now a re-delivery instead of a loss). The default is NOT_PROCESSED, so a path that forgot to
  decide costs a duplicate, never an ack for something unseen. Acking REJECTED blobs is load-bearing: duplicates count as
  ratchet failures, so ≥ 8 unacked duplicates would otherwise sit in front of new messages until their TTL. A stored
  deferral (or forced wire) that a batch did not process is RE-STORED with its original stamp (`keepStored`) — rewriting the
  store without it would lose it.
- **Ack timing, background drains** (control sweep, connect-time pre-drain, group fan-out, every plain `poll*`): state is
  persisted exactly as before (ratchet inside `decryptBatch`, legacy baseline in `persistLegacyBaseline`), THEN the ack.
  `GroupManager.drainControlInboxes`, `pollGroupIntoBuffer` and `drainBothTextInboxes` collect into one
  `MessageManager.AckBatch` and flush in a `finally` AFTER `ingest` applied what came back; a bare `pollMessages` /
  `pollControlMessages` acks at the end of its own drain. Fire-and-forget: `sendAcks` LAUNCHES (`ackLauncher`, an IO
  coroutine; a test seam) and never blocks a poll result or a commit; a failed ack is a re-delivery. Freeze-gated
  (`moveFrozen("retrieve ack")`). Log lines are counts only — no inbox id, blob id, token or cap.
- **Ack timing, the conversation screens** — `MessageManager.pollMessagesPending` / `pollGroupInboxPending`
  (`pollChannelPending`, internal, `Chan.MAIN|GRP` only), `GroupManager.pollDirectPending` / `pollGroupPending` return a
  `PendingDrain<T>` (`messages` + `commit()` + `abandon()`). Decrypt WITHOUT persisting: the ratchet advance stays in RAM
  (`RatchetManager.PendingTicket`, from `decryptBatch(persist = false, drainGroup = …)`), the legacy baseline is not
  written (`PendingPart.legacyBaseline`), the text lock's grace is consumed at commit. The screen shows the messages, THEN calls
  `commit()` off-main: persist (ratchet ticket, legacy baseline under `pendingLock`), then one fire-and-forget ack. No commit
  (home, swipe, app switcher, lock, process death) ⇒ nothing persisted, nothing acked ⇒ the relay re-delivers after its lease
  and the blobs decrypt again. `abandon()` (screen gone mid-poll) discards the advance and RELEASES the lease at once, so
  the next poll shows them. Both are idempotent, thread-safe, never throw; the first to run wins. Items an older path
  parked in the screen buffer (system notices) are returned first and leave the buffer only on commit.
- **THE RULE for a second drain over an uncommitted advance** (`RatchetManager` header, rules 1–6; one ratchet chain per
  contact, `dr/<id>/text`, shared by the text, group and control inboxes):
  1. same drain group (one screen poll — a contact's text inbox then its group inbox) ⇒ BUILDS ON the
     uncommitted head (linear history; committing the head commits its base);
  2. a newer screen poll (another drain group) ⇒ DISCARDS the stale lineage (its lease released via
     `PendingTicket.onDiscarded`) and decrypts from the store; the stale blobs come back on the next poll and open from the
     skipped-key cache;
  3. a persisting drain (the control sweep) ⇒ NEVER builds on or overwrites it: every ratchet wire is NOT_PROCESSED and
     comes back on the next sweep; `drainRatchetHalf` pre-checks `hasUncommittedAdvance` so the stored deferrals are not
     even loaded; decryptBatch enforces it atomically under its lock;
  4. a send (`tryEncrypt`) / single `decrypt` ⇒ DISCARDS it first (persisting on top of an unshown advance would commit
     it); the stale drain's blobs are released and re-delivered — worst case shown twice, never lost;
  5. an advance older than `PENDING_ADVANCE_MAX_AGE_MS` (15 s, ≪ the 60 s lease) is discarded at the next touch — an
     abandoned poll nobody released, rolled back before its re-delivery arrives;
  6. read-only probes (`hasRatchetedPastBootstrap`, `hasSentAtLeast`, `isBootstrapped`) read the STORE, so a lock arms /
     a send-chain probe flips one drain later (the conservative direction).
  **Compare-and-swap commit.** `commitPending` persists only if the store still holds the exact state the lineage was
  built on (SHA-256 `storeFingerprint`); otherwise it discards (false ⇒ not acked ⇒ re-delivered). This closes the one
  cross-instance hole: a Tor restart rebuilds `MessageManager` (a NEW `RatchetManager`) WITHOUT a scrub, and an old
  screen's late commit would otherwise roll back an advance the new instance persisted (a DH fork if a send used it).
  **The legacy half** (`legacyPendingBlocks`, process-wide `PendingLegacyRegistry` for the same reason): the
  strict-monotonic counter cannot take a lower counter once a higher one is persisted, so while a screen's legacy advance
  on (contact, channel) is uncommitted, a persisting drain leaves its legacy blobs NOT_PROCESSED, and a newer screen poll
  discards the stale one, releases it and ALSO holds its own legacy blobs for one round — so the stale and new counters
  meet in ONE sorted drain. Teardown: `MessageManager.scrubInMemory` sets `acksClosed` FIRST (no ack launched or sent,
  no commit writes — `pendingLock` fences a commit inside its persist), and `RatchetManager.scrubInMemory` zeroes every
  uncommitted snapshot without firing release hooks (a lock / wipe causes no network I/O).
  **UI contract:** commit after render and BEFORE the next poll of the same conversation starts; a commit that loses
  that race costs a duplicate on screen, never a lost message.
- **Re-delivery label.** A duplicate within 10 min of an ack this channel sent and never got a 200 for is logged
  "re-delivery after a lost ack" (legacy, instead of "replay/dup") / "likely re-delivery after a lost ack" (ratchet drop
  line). Label only — same blob, same drop; RAM-only `ackUnconfirmed` map (≤ 256, scrubbed). After a lost ack and a DH
  step a duplicate CONTROL blob can be classed `OLD_CHAIN` by `wouldDamageSkippedKeys` and land in the sealed-control deferral
  instead of being rejected — acked, bounded by the store caps / 10 min short age, refused (and advancing nothing) once
  tried. Pinned in `RatchetPendingAdvanceTest`.
- **Known limitations (stated plainly).** (a) A retained copy during the ack window (≤ the lease, ≤ 24 h TTL if every ack is lost)
  is decryptable only where the envelope is static-key: the responder's first text before its first ratchet receive / the
  legacy fallback, and the CONTROL inbox as the normal case — `act` activity notices and screenshot notices are never
  ratcheted. Low-sensitivity, accepted. (b) Burn on read: a message that reached the screen a moment before the home press
  counts as read (committed) — same as before. (c) A pending drain applies what it cannot defer at decrypt time: a legacy
  peer's control on its text inbox, a 1:1 screenshot notice on a pre-v7 text inbox, ratchet UI ids (RAM-only), the `ch` / `di` / `cr`
  latches; a teardown before commit re-applies them on the re-delivery (idempotent upserts; a screenshot notice may show
  twice). (d) A hostile relay can re-serve a blob inside a screen's render window and have it shown twice at most once
  (accepted). (e) A deferral-store write failure after the ack loses that sealed control wire (as before).
  (f) Acks reveal nothing new: the relay already sees retrieve timing, and the ack uses the same capability.
- **Tests.** `RetrieveAckTest` / `RetrieveAckGroupTest` (leasing relay double: exact ack ids incl. rejected, cutoff tail
  and > 2048 tail NOT acked and re-delivered, deferred control acked, PendingDrain no-commit / commit / idempotent /
  abandon, a newer poll over an uncommitted one on both paths, rule 3 for a control sweep, rule 4 for a send, lost-ack
  re-delivery labels on both paths, old relay, malformed lease never echoed, no identifiers in the log, 64 / 256 split,
  one batch per fan-out) and `RatchetPendingAdvanceTest` (rules 1–5, CAS, scrub, abandon, cutoff / budget not-processed,
  the OLD_CHAIN duplicate).

### The READ capability is the inbox OWNER capability — vault-only, no mirrors (2026-07-30)

The name undersells it. `X-Read-Capability` authenticates far more than `GET`: it also authorises
`DELETE /inbox/{id}` (destroy the inbox, severing that contact permanently), **both**
`PUT /inbox/{id}/read-capability` and `PUT /inbox/{id}/write-capability` (rotation authenticates with
the read-cap header *only* — see the unwired, deprecated `MessageManager.rotateWriteCapabilityNonDurable`), and `PUT|DELETE
/inbox/{id}/push`. So the rule is: **read capabilities live in the vault and nowhere else**, and every
`PushRegistration.register/unregister` caller must source `readCap` from an OPEN vault
(`allInboundTextInboxes`).

Android used to break that rule. `NotificationPollStore` mirrored `(inboxId, readCap)` into
`notif_manifest_prefs/manifest_enc`, sealed by `ManifestCrypto` under a Keystore key deliberately
built **without** `setUnlockedDeviceRequired(true)` — the Android equivalent of iOS's
AfterFirstUnlock class — so a locked-device FCM token rotation could re-register without a vault. An
AFU forensic image of a seized, powered, locked phone therefore yielded, per inbound text inbox, a
token to drain it, destroy it, lock the owner out and mint write access. The mirror, its codec and
`ManifestCrypto` are **deleted**; `NotificationPollStore` now holds only the plaintext opt-in
boolean. iOS never had an equivalent (`IosAppController.currentInboundInboxRefs` returns empty
without an open vault; `pushRegisteredInboxIds`/`lastPushDeviceToken` are in-RAM only), so this was
Android-only.

Two consequences to know:

- **Trade-off.** `RunFcmService.onNewToken` is now a no-op — with no mirror it cannot know which
  inboxes to target, and it must not open the vault. After an FCM token rotation **push wakes lapse
  until the next unlock**, when `RunViewModel.refreshVendorPushRegistration` re-registers every
  inbound text inbox. That is unconditional, not a comparison: `vendorPushToken` and
  `vendorPushRegisteredIds` are session-scoped RAM, so a new session always re-registers under
  whatever token FCM currently holds, and nothing persisted can go stale and suppress it. The
  registration usually lands on the first control-poll cycle rather than at unlock itself (Tor is
  still bootstrapping, so there is no transport yet). Two caveats on that recovery, both worth
  knowing before touching it: it is gated on the plaintext opt-in bit
  (`NotificationPollStore.isEnabled`), so anything that makes that bit unreadable at unlock kills
  re-registration too and not merely the notification gate; and because it needs a live transport, a
  session where Tor never reaches `Connected` re-registers nothing. `vendorPushToken` is therefore
  adopted only *after* the transport check — recording it for a pass that registered nothing is the
  shape of a permanent silent skip, benign today only because the set is emptied in the same breath.
  Do not "optimise" by persisting `vendorPushRegisteredIds`/`vendorPushToken`: their RAM scoping is
  exactly what makes a fresh process re-register unconditionally, and
  `PushRegistration.register` is an idempotent relay upsert, so the redundant calls are free.
- **The READ cap is now ROTATABLE, and rotation is crash-safe (2026-08-01).** Vault-only
  storage bounds who can *copy* the cap; it does nothing about a copy already taken — before this,
  caps were minted once at pairing and never rotated, so one compelled unlock (or an imaged vault
  returned to the user) granted an operator INDEFINITE remote ability to drain the inbound inboxes
  ahead of the app, mint themselves a write cap, rotate the user's own cap away, or register their
  own push token. `MessageManager.resetRelayAccess(contactId)` re-keys **both** inbound inboxes
  (text + `inbound-ctl`; the control inbox's read cap is exactly as powerful) and is surfaced
  per-contact as "Reset relay access" on both platforms. The ordering is the whole design:
  a fresh cap is written to a DURABLE `_meta` marker (`cap-pend/{contactId}/{direction}`) **before
  any network I/O**, the `PUT /inbox/{id}/read-capability` response is treated as a HINT only, and
  the decision is made by probing **`GET /inbox/{id}/peek`** — never a bare `GET /inbox/{id}`, which
  DRAINS. New cap 200 ⇒ commit onto the row + drop the marker; new cap 404 **and** the
  re-read-live current cap 200 ⇒ the rotation never landed, drop the marker only; anything else
  ⇒ keep BOTH and change nothing. The invariant that makes every interruption point safe is
  **union {record cap, pending marker} always contains whatever cap the relay holds**, so no
  failure can leave a user without a capability for their own inbox. The whole rotate+reconcile
  runs under a per-(contact, direction) lock — without it a double-tap starts two rotations, the
  loser resolves neither cap, and the surviving marker wedges the contact on `BUSY` forever, which
  is worse than the original problem. Interrupted rotations self-heal from the top of `pollChannel`, gated
  on a cheap marker read (steady state: one vault lookup, zero network calls). Two couplings:
  the marker holds a live capability, so it is in `ratchetMetaKeysForContact` (ContactMetaPurge.kt; the shared purge
  list both actuals iterate); and a committed rotation does NOT evict a push token already
  registered on that inbox, so it issues `DELETE /inbox/{id}/push` with the just-proven cap and
  hands the inbox id to the platform's session-scoped registered set (`drainRotatedPushInboxIds`)
  so the existing re-sync re-registers OUR token. **Write-cap rotation is deliberately NOT wired**
  (our own inbound write cap is never persisted, so an imaged vault never yields it), and there is
  deliberately no periodic schedule and no auto-rotate after a recovery-code unlock — that would
  announce to a possibly-hostile relay exactly when the user believes they were compromised.
  **A fifth consequence of a one-time vault open — forging an inbox ANNOUNCE to the peer with the
  imaged `sharedSecret` + peer write cap — is NOT closed by read-cap rotation; see the 2026-09-08
  section below for the ratchet-sealed announce rule that closes it.**
- **Deleting a contact now destroys its inboxes on the relay** (`deleteContactAndPurgeRelay`,
  commonMain, used by both platforms). Caps are snapshotted BEFORE the rows go; the LOCAL delete is
  the gate (it is atomic on both platforms, so a throw means the contact is still intact and must
  NOT be relay-deleted — deliberately not a `finally`); the `DELETE /inbox/{id}`s then run
  best-effort, CSPRNG-shuffled with 100–400 ms jitter, and never gate the user's delete on Tor.
  `MessageManager.deleteInbox` has no retry loop by design (a lost DELETE costs only the orphan we
  already had). It is called from exactly two places — that path and `mintInboxPair`'s
  partial-failure branch (the minted-but-unshared main inbox when the ctl mint fails). It must
  **never** be called from a BLOCK path (reversible UI must not fire an irreversible action) or a
  WIPE path (crypto-erase-first forbids network I/O there, and a mass-DELETE burst would broadcast
  a deniable wipe).
- **Not every `_meta` purge target fits the exact-key `ratchetMetaKeysForContact` list — some need a
  PREDICATE instead, and the screenshot-notice residue (2026-08-21,
  `docs/screenshot-notice-persistence-design.md`) is the first new class of it since the ratchet
  keys themselves.** A received "screenshot taken" notice persists as one `_meta` row under
  `ssn:<conversationId>:<senderContactId>:<receivedAtMs>` — the trailing `receivedAtMs` is a
  per-notice, unpredictable suffix (collision-bumped by 1 ms), so there is no fixed key string to
  enumerate the way `ratchetMetaKeysForContact` enumerates a fixed set of `dr-*` suffixes for one
  contact. `isScreenshotNoticeResidueForContact(key, contactId)` /
  `…ForGroup(key, groupId)` (`ContactMetaPurge.kt`, beside `GroupMetaKeys` and `ratchetMetaKeysForContact`) instead PARSE the key and
  match on the `conversationId` OR `senderContactId` segment — the `senderContactId` half matters
  because a group notice is keyed by `groupId`, so deleting the *sender's* 1:1 contact would
  otherwise leave that sender's rows behind inside every group they were ever in. Both
  `DatabaseManager.deleteContact`/`deleteGroup` and `IosVaultDatabase.deleteContact`/`deleteGroup`
  iterate the FULL `_meta` key set through this predicate (not a targeted lookup — the loop both
  actuals already run for the group-meta classifiers, extended one more predicate), and the
  commonTest `InMemoryVault` mirrors the same predicate so `MetaResiduePurgeTest` can pin it without
  a real SQLCipher/Keychain backend. Deliberately NOT added to `ratchetMetaKeysForContact`: mixing a
  variable-suffix predicate into an exact-key list would either miss every row (exact match never
  hits) or require enumerating the vault twice for one contact — one classifier per residue SHAPE,
  not one list for all of them.
- **The data outlives the code.** `NotificationPollStore.purgeLegacyCapabilityMirror`, called
  synchronously from `RunApplication.onCreate`, destroys the Keystore alias `run_manifest_master_key`
  first, then `run_manifest_keyset_prefs`, then the `manifest_enc` entry — unconditionally,
  regardless of whether push was ever enabled, idempotent, and never throwing. It runs there because
  `Application.onCreate` precedes every wipe trigger in the process, so its one write can never land
  after a wipe. The wipe paths still destroy the same legacy names
  (`eraseLegacyManifestKeySurface` + `LEGACY_KEYSET_PREFS_NAME` in `WipeRoutine.PREFS_FILES`) for an
  install that is wiped before it is ever relaunched.

### The inbox ANNOUNCE rides the text ratchet once it is live; a static-key announce is dropped after dr-rxlock (2026-09-08)

- **The gap.** A control-channel `inbox` announce rewrites the PEER's outbound routing (`applyInboxAnnounce`), and the
  control channel is keyed by the static `sha256(sharedSecret)` with no post-compromise security. One vault open
  (compelled PIN, offline CASUAL grind, imaged vault) yields `contacts.shared_secret`, the peer's `outbound-ctl` row
  (= the peer's inbound-ctl inbox id **and our write cap for it**) and the persisted `outboundCtlCounter` — everything a
  valid announce needs. `resetRelayAccess` rotates only OUR read caps and never touched this direction; the ownership
  rule "an unknown inbox id is available" is load-bearing for rotation/404 re-announce (`InboxOwnershipTest`) and
  cannot be the guard. `ForgedAnnounceRedirectTest` reproduces the redirect end-to-end against the pre-fix code.
- **The rule.** From `dr-on` onward, `sendInboxAnnounce` is sealed by the **text ratchet** (`announce = true` →
  `sendOverTextRatchet(postTo = <control row>)`) but still POSTed to the control inbox, so the peer's background control
  sweep applies it promptly and no phantom unread dot lands on the text inbox. The receiver's control poll now routes
  ratchet-magic blobs through `receiveOverTextRatchet(controlChannel = true)`, which applies ONLY `inbox` announces (any
  other ratchet blob on the control inbox is a relay splice and is dropped — the message key is consumed, same outcome
  as a relay drop). Once `dr-rxlock` is armed, a **legacy** announce is dropped without advancing the counter (mirrors
  the text receive lock). `maybeArmRecvLock` now runs on both polls, since an announce decrypted on control advances the same
  ratchet.
- **What it does NOT change.** The chatty control kinds (group activity notices, screenshot notices) stay on the static
  envelope — a chatty kind over the text ratchet would burn `MAX_SKIP` across two inboxes drained at different
  cadences; announces are rare. **The referral handshake and group membership control used to be listed here too;
  since the next section's change they ride the ratchet as well, advert-gated.** The bootstrap window is unchanged: the very first announce (pairing
  completion) and a responder's announce before its first ratchet receive are still legacy and still accepted while the
  peer is un-armed — the known `dr-rxlock` arming limitations apply verbatim. The residual under a vault
  image is therefore the same as for text: usable until the next DH round-trip, not forever.
- **Version skew.** A pre-fix peer receiving a ratchet-sealed announce on its control inbox fails AEAD and drops it.
  The only production announce callers are the pairing-time `announceInbox` on both platforms (dr-on is never set
  yet, so they stay legacy); rotation re-announces to a stale peer are the one path that needs both sides updated.

### The integrity-critical control kinds ride the ratchet too — advert-gated both ways (2026-10-21)

- **The gap.** Every control kind except the announce rode the static
  `sha256(sharedSecret)` envelope and was never receive-locked. With one vault image (sharedSecret, inbox rows +
  write caps, counters, epoch) plus a hostile relay an attacker could forge a `ref-offer` from introducer I to V (V
  sees a consent prompt), READ V's `ref-accept` (static key), forge I's relayed `ref-accept` carrying the attacker's
  X25519 key so V commits contact Z at `TRUST_REFERRED_CONFIRMED`, and — if I administers a group V is in — forge a
  `roster` (authenticated by channel only, epoch jump ≤ `MAX_GROUP_EPOCH_ADVANCE`) binding a slot to Z, so V fans group
  plaintext to Z. A forged huge control counter additionally dropped every genuine control blob forever.
- **The kinds (`MessageManager.isRatchetSealedControlKind` — the ONE predicate both the sender and the receiver
  use).** Direct: `ref-offer`, `ref-accept` (which is also the introducer-relayed accept). Group-scoped (`"g"`
  present): `invite`, `join`, `roster` (which also carries admin transfer — there is no separate kind), `leave`. These
  are every kind that changes WHO receives our messages or who is in our contact list. **Stay legacy, by design:**
  `act` (one per group text a member sends — the chatty one), group and 1:1 `screenshot` notices (frequent,
  integrity-irrelevant). The `inbox` announce keeps its own, older, unconditional rule (previous section).
- **Wire (no new message, no version number).** Every envelope this build sends — legacy and ratchet, text and
  control — carries `"cr":"1"` ("my control inbox accepts sealed integrity kinds"). Every RATCHET envelope sent to a
  peer whose `cr` we hold also carries `"crw":"<n>"`: our outbound CONTROL counter at that send, a commitment that no
  legacy copy of a sealed kind above `n` will ever come from us (we hold `dr-on` and a sending chain — that is what
  produced the blob — and both persist). JSON strings, appended after `di`/before the group fields (legacy) or after
  `t` (ratchet); older parsers read fields by name and ignore them. The size probe includes `cr`; the ratchet envelope
  (which may add the ≤ 27-byte `crw`) drops `e`/`c`/`ch`/`di`, so the legacy probe stays a strict upper bound.
- **Send gate.** `sendGroupControl` / `sendDirectControl` pass `sealedControl = isRatchetSealedControlKind(kind, …)`;
  `sendEnvelopeSerialized` takes the ratchet branch for them iff `dr-on` AND the peer's `cr` is latched
  (`dr-rxseen-ctlcap/<id>`), posting to the control row exactly like the announce. Without the advert the send is the
  plain legacy send, byte-for-byte apart from `cr` — an old peer drops every non-announce ratchet blob on its
  control inbox, so this is what keeps a mixed-version population working. A ratchet `null` (no sending chain) falls through to
  legacy and is deliberately NOT counted in `dr-legacyfb` (that counter arms the TEXT refusal). A landed sealed send
  now arms `armControlConvergence(progress = true)` like the legacy path always did (the ratchet-sealed announce did not —
  it does now too), or a sealed roster/invite would drop the loop to the 60–90 s idle cadence mid-handshake.
- **Receive.** `receiveOverTextRatchet(chan = CTL)` now surfaces sealed kinds (with no UI id); anything else ratchet-sealed
  on the control inbox is still a splice and dropped. (Ratchet UI ids no longer come from a persisted counter at all:
  the per-contact `dr-rxc` lifetime receive count was retired 2026-11-06 — it was exact message volume in an opened vault
  image. `RatchetReceiveIds` is process-wide RAM, so ids never repeat across a rebuilt `MessageManager`; `dr-rxc` is
  never written, a legacy value is deleted on the contact's next ratchet text drain, and the key stays in
  `ratchetMetaKeysForContact` for vaults that never drain again.) The
  legacy loop gains two drops, both WITHOUT advancing the counter (the same shape as the text and announce receive locks):
  1. **The lock**: a legacy sealed kind with `counter > W` is dropped iff `dr-rxlock` is armed AND
     `W = dr-rxlock-ctlwm/<id>` is present. `W` is recorded only from `crw` inside a RATCHET blob decrypted while
     `dr-rxlock` was ALREADY armed at drain start (a bootstrap-window ratchet blob is forgeable from sharedSecret alone,
     and a forged `W` would make us drop a genuinely old peer); the LOWEST value ever proven is kept. A `crw` in a
     legacy envelope is ignored. A genuine pre-commit legacy copy still queued on the relay has `counter ≤ W` and lands.
  2. **The forward-jump cap**: on the CONTROL inbox a counter above `drainStartBaseline + CTL_COUNTER_MAX_FORWARD_JUMP`
     (1 000 000 = 100 × `MoveConstants.COUNTER_JUMP`, saturating) is dropped. Measured from the baseline the drain
     STARTED at, so a stack of blobs in one drain cannot walk it up either. Sized so an honest peer cannot reach it:
     a hundred back-to-back device moves, or ~2 700 control appends to us per day for the 365 idle days after which the
     relay reaps our inbox anyway. A device move's +10 000 passes; text inboxes are not capped (the text receive lock locks them once the
     ratchet matures, and a 1:1 backlog has no comparable bound to size a cap from).
- **Arming, i.e. the compatibility argument.** Both gates need POSITIVE evidence and every ambiguity fails open (a
  missing/unreadable/malformed marker is "no lock" / "send legacy"): a peer that never advertised is never sent a
  sealed blob and never has a legacy blob dropped; a peer that advertised but whose `crw` we have not seen post-maturity
  is sent sealed blobs (it accepts them) but its legacy ones still land. The two levels exist because a peer only
  seals to us once it has seen OUR `cr`; arming our lock on its `cr` alone would drop its legacy `ref-accept` sent before
  it saw ours. Trace on a fresh new↔new pairing (ids as in `SealedControlRatchetTest`): a0 legacy → Bob latches `cr`;
  b0 ratchet with `crw` (Alice not mature, ignored); Alice's lock arms after b1 (2nd receiving DH step); b2's `crw` is
  honoured. Both latch keys (and the three further keys of this change listed below — five in all) are in
  `ratchetMetaKeysForContact` and travel with a move through the existing `dr-rxseen`/`dr-rxlock`/`dr/`
  `MoveMetaPolicy` prefixes (deliberately named under them; `MoveMetaPolicyPinTest` pins it):
  a new phone that lost `dr-rxseen-ctlcap` would send legacy above a watermark the peer holds, and be dropped.
  `onCorruptReinit` clears `dr-rxlock`, which disarms this lock with it.
- **MAX_SKIP / skipped-key impact, verified against `DoubleRatchet` — and what closes each case.** Sealed kinds share
  the ONE `dr/<id>/text` chain but land on the control inbox, which the BACKGROUND sweep drains (60–90 s idle) whatever
  the text inboxes hold, while an open conversation drains text every 1–2 s. Three hazards, none of them acceptable
  as-is (this is NOT the same exposure as the text-then-group drain interleave: that one only arises inside a user-opened conversation poll):
  1. **Control decrypted AHEAD of an undrained text backlog** (the sweep runs in the background): skipping k > 128
     (`MAX_SKIPPED_STORE`) evicts the oldest text keys — those texts are lost; k > 256 (`MAX_SKIP`) refuses the sealed
     blob itself, and its redrives too; and control-only round trips (invite→join→roster, a referral) can drive TWO
     receiving DH steps, whose old-chain flush deletes the skipped keys of undrained 1:1 texts. **Closed by DEFERRAL:**
     `RatchetManager.decryptBatch(deferDamaging = true)` asks the read-only `DoubleRatchet.wouldDamageSkippedKeys(header)`
     before each control-inbox wire and DEFERS it if decrypting would exceed `MAX_SKIP`, push the skipped cache past
     `MAX_SKIPPED_STORE`, or DH-step while skipped keys from a chain older than the current remote one exist. The raw
     wire goes to `dr/<id>/ctl-deferred` (`<stampMs>:<base64>` entries — ratchet ciphertext only; the state that opens it
     is in the same vault; ≤ 32 stored, the newest 16 retried under the guard, older ones and any older than 24 h —
     `CTL_DEFER_MAX_AGE_MS` = the skipped-key / text retention, by which time the texts it protected have expired off
     the relay — processed unconditionally). **Dead keys never park control:** before storing, the text and group
     inboxes are PEEKED (never drained); both positively empty ⇒ the cached keys belong to messages that will never
     arrive (a Tor-dropped send, an expired text) ⇒ decrypt now. The 24 h force age is kept only for a BACKLOG skip
     with unread texts positively waiting; an old-chain flush or an unknown peek is held at most
     `CTL_DEFER_SHORT_AGE_MS` (10 min). **Only sealed-control-sized wires are deferred:** ≤
     `MAX_DEFERRABLE_CTL_WIRE_BYTES` (the 32 KiB padding bucket + overhead — every referral leg, invite, leave, the
     roster of a fully paired 64-member group and the join of a user with several hundred contacts), ≤ 64 KiB stored per contact; anything larger takes the ordinary decrypt-or-reject path,
     so a relay cannot bloat the store or a move bundle with junk (an outsized genuine roster/join ahead of a
     backlog therefore still evicts — known limitation). The control sweep drains a contact whose control inbox peeked
     empty ONLY when a deferral is DUE — a hold expired, or a text drain asked for a retry (it read texts the
     deferral protected) — never merely because one is held, and the "texts waiting" peek answer is cached in RAM
     for 3 min (dropped by any text drain of that contact, scrubbed with the session), so a held deferral adds no
     steady per-sweep request pattern. Known limitation: inside that 3 min a cached "0" can force a decrypt that skips
     past a text which arrived after the peek. **Deliberate trade:** an OLD_CHAIN deferral is held only 10 min even
     when the peek shows unread texts — forcing it then can flush those texts' skipped keys; a day-long delay of a
     passive member's invite/roster/referral was judged worse. Every control drain retries first; a text drain that decrypted
     anything for a contact with deferrals schedules a prompt retry (below). In `ratchetMetaKeysForContact` and, via
     the `dr/` prefix, in a move bundle. A wire that would never decrypt (out-of-range `n` on a new key) is not parked.
  2. **Text decrypted AHEAD of a queued sealed blob**: the blob's key becomes a skipped key and two further reply
     round trips flush it — an ordinary lively chat inside one idle sweep interval. **Closed by the catch-up WAKE:**
     `decryptBatch` reports the skipped-cache size before/after; a TEXT drain that left MORE skipped keys than it
     found, for a peer whose `cr` we hold, marks the contact (RAM, bounded 256, scrubbed with the session); one that
     emptied the cache unmarks it (so the text-then-group drain interleave, consumed within the same conversation poll, wakes
     nothing). A pending mark makes `controlPollIdleWaitShouldEnd` end the platform loop's IDLE wait at the next 1 s
     slice, ONCE per new mark (same IDLE-only rule as the other arms; a FAST wait is never cut), and the ordinary
     background sweep drains the control inbox from the skipped key. Nothing runs in the UI-awaited conversation poll
     and nothing holds the sweep admission; iOS needs no change (its loop already asks the same method each slice).
     Known limitation: if that sweep is itself skipped (another sweep or the connect-time pre-drain in flight), the next
     regular sweep (≤ 90 s) is the fallback.
  3. A forged wire with a "damaging" header can sit in the deferral store until its bound — junk the cap bounds.
  `SealedControlRatchetTest` holds an oracle proving hazard 2 is real on the bare transport, and pins every closure.
- **Fail closed on an unreadable capability marker.** `peerCtlRatchetCapability` is tri-state; a read that THROWS
  fails a sealed send (`false`, before any counter bump) instead of sending legacy above a watermark the peer may
  already hold (where it would be dropped). Every sealed kind has a retry path (roster/leave obligations, the `ref_*`
  offer/accept/relay redrives). Chatty kinds read it as "no" — they are legacy for every peer anyway.
- **A control-armed text lock keeps the text lock's grace.** `maybeArmRecvLock` runs on the control poll too (since the ratchet-sealed announce), and since
  sealed control drives the ratchet, the lock now often arms THERE — which robbed the text channels of the text lock's one-drain
  grace (that grace exists only because a TEXT drain reads the lock at its start). An arm from a control drain now
  first writes `dr-rxlock-grace/<id>` = `m,g` (no grace recorded ⇒ no arm from there); each text channel's next drain
  accepts legacy once and removes its tag. In `ratchetMetaKeysForContact`, cleared by `onCorruptReinit`. Known limitation,
  stated precisely: the grace is ONE DRAIN per text channel, not one blob. In the drain that consumes it the receive
  lock is off for the WHOLE drain, so every legacy blob a sharedSecret + write-cap holder has stacked on that inbox by
  then is accepted (up to `MAX_BLOBS_PER_POLL`), as long as each passes the ordinary epoch / strict-monotonic counter /
  `ch` / `di` checks. On the TEXT (MAIN) inbox that includes legacy CONTROL kinds — referral, roster, invite, leave — which
  is where a pairing without a control inbox legitimately carries them, and the sealed-control watermark (`dr-rxlock-ctlwm`)
  never applies there (it gates the CONTROL inbox only). On the GROUP inbox only group text is accepted. Exactly the same
  window the text lock's own arming drain has always had. Deliberately NOT tightened: a per-drain count cap, or dropping
  legacy control kinds on MAIN when we hold an inbound-ctl row, can both drop genuine mail — a pre-flip legacy backlog is
  exactly what this grace exists to deliver, and our own ctl row does not prove the peer ever learned it. Needs the lock to
  arm AFTER the vault image was taken (new pairing, or `onCorruptReinit`) and a hostile relay or write-cap holder ready at
  that one drain.
- **A vault moved onto an OLDER build (store skew).** The bundle carries both latches, but an older build neither
  seals nor accepts sealed control. Mitigation (no bundle-schema bump, which would block moves during skew): a
  cap-less RATCHET envelope withdraws both latches (`recordPeerCtlAdverts(withdraw = true)`) — but ONLY when it is
  PROVABLY NEWER than the last advert-bearing one: decrypted on the in-order path (never from a cached skipped key —
  a relay can withhold a genuine pre-upgrade blob and serve it alone, and stale pre-upgrade texts legitimately sit
  on the relay for up to 24 h / announces 7 d) AND on a receiving DH step strictly AFTER the newest step at which an
  advert-bearing envelope was decrypted in order. `decryptBatch` reports each decrypted wire's origin
  (`WireOrigin(fromSkippedKey, receivingStep)`, the step being `DoubleRatchet`'s serialized `dhRecvSteps` ordinal);
  the newest advert step is persisted in `dr-rxseen-ctlstep/<id>`. With no recorded step (the advert was only seen in
  legacy envelopes) nothing is provable and nothing is withdrawn; a local `onCorruptReinit` resets the ordinal, which
  clears the step key so detection restarts with the fresh ratchet. The genuine peer's next envelope re-latches.
  Known limitation: if that peer then UPDATES again, its vault still holds the watermark it imported, so until we re-latch its
  `cr` from its next envelope our legacy rosters/referrals above that watermark are dropped there — a short window
  that needs the rare downgrade first. Known limitation: control the older build sent
  before its first new-chain ratchet envelope reached us is dropped if above our watermark — recovered by the roster
  redrive once the pairing reverts, or by updating the app.
- **Five new `_meta` keys, all in `ratchetMetaKeysForContact` and all carried by a move through existing
  `MoveMetaPolicy` prefixes:** `dr-rxseen-ctlcap/<id>` (send gate), `dr-rxlock-ctlwm/<id>` (receive commitment),
  `dr-rxseen-ctlstep/<id>` (downgrade proof), `dr-rxlock-grace/<id>` (text-lock grace after a control-armed lock),
  `dr/<id>/ctl-deferred` (deferred sealed-control wires). Stored deferred wires have the same vault-image exposure as
  cached skipped keys — the ratchet state in the same vault opens them — bounded by their force age (≤ 24 h, ≤ 10 min
  for the short case), 32 entries and 64 KiB per contact.
- **Known limitations (also in `docs/SECURITY_OVERVIEW.md` §8).** Before `dr-rxlock` arms, or against a peer that never advertised,
  legacy sealed kinds are accepted exactly as before (the `dr-rxlock` bootstrap-window limitation applies verbatim). A relay that
  withheld k genuine pre-commit legacy control blobs can substitute ≤ k forgeries in `(baseline, W]`. A vault image also
  holds the current ratchet state, so — as for text — a forger is good until the next DH round trip, not forever. A
  forged legacy CHATTY kind still lands: a fake `act` lights a dot, a fake `screenshot` notice shows, and a forged
  matching `membershipHash` can clear an admin's ack obligation (end-to-end delivery section below) for that member (bounded by the re-roster on the
  member's own next traffic). The forward-jump cap bounds a single forged control blob to ≤ 1 000 000 counters of
  genuine traffic, not to zero, and a control baseline ALREADY pushed near `Long.MAX_VALUE` by a forgery from before this change stays
  stuck until a re-pair (resetting a baseline downward would re-open replay of everything still on the relay).
  A static-key forger who plants `cr` for a peer that has NOT upgraded makes us seal integrity control that peer
  drops — a LOSS/DoS until it upgrades, never an exposure (everything sent that way is ratchet-sealed).
- **Tests.** `SealedControlRatchetTest` (commonTest, 30): capability/commitment exchange by ordinary traffic; honest
  roster / referral accept are ratchet wire and land; `act` stays legacy; every sealed kind forged from a vault image is
  dropped post-commit without burning the counter; a queued genuine pre-commit roster lands; an un-upgraded peer is
  never dropped and never sent sealed control; a legacy-envelope `crw` and a bootstrap-window `crw` never arm; the
  counter cap (incl. `Long.MAX_VALUE`) and the +10 000 move; the catch-up oracle, the one-shot wake and "no mark
  without a skipped key"; a throwing capability read fails the send; deferral ahead of a >128-text backlog; control-
  only round trips never flush undrained text keys; a control-armed lock keeps the text lock's grace; a pairing with no control
  inbox carries sealed control on the text inbox; dead skipped keys (empty inbox peeks) never defer; an oversize
  wire is never deferred; stale and relay-withheld cap-less blobs never withdraw, a cap-less envelope on a NEW chain
  does; the sweep retries a deferral with an empty control inbox; purge + move coupling.

### Group membership control is durable: 7-day TTL + redrive of refused rosters/leaves (2026-09-08)

- **The gap.** A roster (member removed/added/admin transferred) and a leave were fire-and-forget: `fanOutControl`
  discarded per-target results, the blob carried no `?ttl=` (relay default **24 h**, ceiling 7 d — `docs/RELAY_SPEC.md`),
  it was `noPush` (deliberately — it fans to every member on every epoch change), and nothing ever re-sent it. Because
  the app tears its session down on every background, "did not open the app for a day" is ordinary; and a hostile
  relay could veto a removal deterministically by returning a real 4xx/5xx for ONE append (`postWithTransientRetry`
  treats any real HTTP response as terminal). Either way the un-converged member kept the removed member in its own
  fan-out and kept sending them group plaintext, indefinitely. `removeMember` reported success throughout.
- **The rule.** `KIND_ROSTER` / `KIND_LEAVE` / `KIND_INVITE` now carry `ttlSeconds = 604_800` (`sendGroupControl`
  grew the same `ttlSeconds` affordance `sendDirectControl` already had for referrals). `fanOutControl` returns the
  targets that did NOT get the message — **all of them when there is no transport** — and `broadcastRoster` /
  `leaveGroup` persist one obligation per (group, contact) under `grp_ctl_pend:<groupId>:<contactId>` =
  `<kind>|<epoch>|<hash>|<attempts>|<firstSeenMs>`. `redriveUndeliveredMembershipControl()` rides the control sweep
  (`SessionManagers.onControlSweep`, next to the referral redrives): a roster is re-derived from CURRENT vault state
  (full state, so the latest roster subsumes the missed one; a delivered roster also clears an older miss for that
  target); a leave re-sends the stored hash because the group is already gone locally (its obligation is written AFTER
  `deleteGroup`, so the group-residue purge does not sweep it). Bounds: 12 attempts, 7-day absolute ceiling, 256
  records (oldest evicted); an obligation whose contact is gone, or whose group/admin role is gone (rosters), is
  dropped. The prefix is in both residue classifiers (`isGroupMetaResidueForGroup` / `ForContact`), so contact and
  group deletes purge it on both platforms. `GroupMembershipRedriveTest` covers refused-one-member, Tor-down,
  leave-after-local-delete, the two bounds, and residue classification.
- **What it does NOT change.** `removeMember` still returns true once the LOCAL removal commits (the obligation is
  durable, so the UI is not lying); nothing revokes what a removed member already received; the removed member's own
  device still only stops polling once its final roster lands — which is exactly the copy the redrive now guarantees.
  A 7-day blob on an archiving relay is the same static-envelope exposure the referral path already accepts.

### Delivery is confirmed END TO END, not by the HTTP status; and the `?ttl` is uniform (2026-09-16)

- **The gap.** The section above redrives an append the relay REFUSED. An append the relay ACCEPTS with `201`
  and then discards was recorded as delivered: `fanOutControl` derives one boolean from `HttpResult.isSuccess`
  (`code in 200..299`), the obligation recorder (today `MembershipControlRedrive.record`) DELETED any obligation for those targets, and
  `redriveUndeliveredMembershipControl` therefore had nothing to iterate. A hostile relay could veto one removal —
  permanently, silently, and more cheaply than the 4xx/5xx path the previous section closed — while `removeMember` reported success and
  every un-converged member kept sending the removed member group plaintext. It was also SURGICAL, because `?ttl=604800`
  + `X-No-Push: 1` identified a ROSTER or LEAVE on the wire with no decryption.
- **The rule — two INDEPENDENT mechanisms, either of which converges on its own.** The protocol already carries the
  acknowledgement: every group text and every group control ships the sender's `membershipHash`.
  1. **Ack-gated obligations (ROSTERS).** For a roster, `grp_ctl_pend:<groupId>:<contactId>` is now written on SUCCESS
     too, in state `a` (AWAITING-ACK), and is cleared ONLY by positive evidence — `GroupManager.noteMembershipView`
     seeing a message from that member whose `membershipHash` equals ours. The redrive re-sends an awaiting-ack record
     on a SLOW cadence (`MembershipControlRedrive.CTL_ACK_RESEND_INTERVAL_MS`, 30 min) bounded by
     `MembershipControlRedrive.MAX_CTL_ACK_RESENDS` (4). **A LEAVE is not ack-gated:** `leaveGroup` records ONLY the
     targets the relay refused (or that had no transport), and a redriven leave the relay accepts is closed at once —
     an acknowledgement is impossible once the group is gone locally, so an AWAITING-ACK leave record could only sit in
     `_meta` holding the left group's roster residue. Consequence, accepted: a relay that `2xx`-and-discards a LEAVE is
     not countered (recorded in the maintainer's residuals list). An UNDELIVERED record keeps the previous section's
     every-sweep cadence and its 12-attempt bound. Both keep the 7-day absolute ceiling, measured from the FIRST miss
     (a delivered target inherits the prior record's `firstSeenMs`, so membership churn cannot re-arm the ceiling).
  2. **Hash-mismatch re-roster.** A message whose `membershipHash` is NOT ours is positive evidence that member has not
     converged, whatever the relay claimed about our appends. `GroupManager.rerosterUnconvergedMembers()` (wired into
     the control sweep beside the redrive) re-sends the CURRENT roster to that member ALONE — never a fan-out — at most
     once per `REROSTER_MIN_INTERVAL_MS` (10 min) per member and at most `UnconvergedMembers.MAX_REROSTERS_PER_SWEEP` (4) per sweep. This
     is the half that survives a relay which 2xx-and-discards EVERY copy, because it is driven by the member's own
     inbound traffic. Admin-only: receivers honour a roster only from the admin's channel.
- **Record format + migration.** `<kind>|<epoch>|<hash>|<attempts>|<firstSeenMs>|<state u|a>|<lastSentMs>|<leaverMemberId>`.
  The original five-field record is still READ (state `u`, `lastSentMs = firstSeenMs`, no leaver id) and is migrated on the
  next write; anything else fails toward "no obligation", never toward a send loop. `attempts` counts attempts IN THE
  CURRENT STATE, so `u → a` resets it. `leaverMemberId` exists because a LEAVE obligation outlives the local group row,
  so a redrive cannot re-derive the `"you"` field it needs.
- **Anti-replay is untouched.** Every re-send is an ORDINARY append — a fresh envelope with a new outbound control
  counter — so nothing is ever "held then released" and the strict-monotonic rule is unchanged.
- **One `?ttl` for every control append.** `MessageManager.CONTROL_APPEND_TTL_SECONDS` (7 d) is now passed by
  `GroupManager.membershipControlTtl` (all kinds), `sendInboxAnnounce`, `sendScreenshotNotice` and the referral path
  alike, and it is threaded through the ratchet branch too (the ratchet-sealed announce takes it). The ttl therefore no longer
  classifies the kind. TEXT appends still carry NO ttl, so they are byte-identical to before. Two consequences of the
  longer retention are handled where they land: an activity notice older than `GroupManager.MAX_ACTIVITY_NOTICE_AGE_MS`
  (48 h) is IGNORED, because a group TEXT still expires on the relay's 24 h default and a week-old `act` would light a
  group dot with nothing behind it; a screenshot notice expires on the RECEIVER's clock, so retention cannot resurrect
  one that already aged out.
- **Known limitations, stated plainly.**
  - **A member that never speaks never acks.** Mechanism 1 gives it 4 slow copies and then stops; after that only its
    own traffic (mechanism 2) or the next membership change converges it. There is deliberately no ack control KIND: it
    would be a new relay-visible per-member response to every roster, and a hostile relay could drop it just as easily.
  - **The REMOVED member can never ack** — it is no longer a member, so its `membershipHash` is not compared, and a
    device that correctly applied the final roster goes silent, which is unobservable. Its final copy gets the bounded
    ack-resends plus the 7-day relay retention, and nothing more.
  - **`X-No-Push` remains a cleartext per-kind bit.** It cannot be removed without losing the wake feature. The uniform ttl only
    removes the `?ttl` half of the classifier; the relay still sees which appends are meant to wake a device.
  - **`membershipHash` is sender-controlled.** A malicious member can forge a matching hash to suppress its own
    obligation — it is an honest-drift signal, exactly as the `GroupManager` header already says, and a member that
    wants to stop receiving rosters can simply ignore them.

### The control-poll fast cadence is armed only by traffic that can converge something (2026-09-16)

`lastControlActivityAtMs` used to be re-armed by `controlPollDelayMs(convergingNow)`, and both platforms pass
`received || hasUnresolvedMembers()` where `received` is true for ANY drained blob — including a control kind that was
dropped as unknown. One paired contact posting one blob a minute therefore held the device in 2.5–5 s sweeps for the
whole foreground session AND kept `isControlConverging()` true, which disables the peek-before-drain for EVERY contact
and turns every sweep into an unconditional drain (multiplying the chance of permanently destroying a third
party's invite/roster/offer on a cold circuit). Three changes, all in `commonMain` so both platforms move together and
neither platform file had to change:

- `controlPollDelayMs(convergingNow)` no longer arms anything. It still returns FAST for that one cycle, which is all
  the window-bounded `hasUnresolvedMembers()` ever needed.
- The persistent window is armed by exactly two things: a successful control SEND (`sendEnvelopeSerialized`, always
  counted as PROGRESS — the bound exists to stop a remote pin, not to throttle work this device started) and
  `GroupManager.ingest` seeing a MEMBERSHIP kind (`roster`/`leave`/`invite`/`join`) from a contact that is a member of
  at least one group this device knows. Direct referral kinds deliberately do not arm it (their handshake is durable,
  redriven on this same sweep, and preceded by a send on one side).
- `CONTROL_FAST_EPISODE_MAX_MS` (10 min, the sibling of `UNRESOLVED_MEMBER_FAST_WINDOW_MS`) is an ABSOLUTE
  ceiling on one fast episode, *regardless of re-arms* — "bounded by a window any arm re-opens" is not a bound. Only a
  genuinely quiet gap (no arm for `CONTROL_CONVERGENCE_WINDOW_MS`) or an arm carrying PROGRESS restarts the episode.
  PROGRESS is decided by a cheap before/after fingerprint of the group row (epoch, admin, member count, resolved-member
  count), so every hop of a real join→roster→resolve chain re-anchors it and only traffic that converges nothing runs
  the clock out. A backward clock step fails toward FAST (the pre-fix behaviour).
- **Fourth arming condition (2026-10-01, deliberate privacy trade-off): a group conversation on screen.**
  `GroupManager.setGroupConversationForeground` (RAM-only, keyed per screen, cleared by `scrubInMemory`) is OR-ed into
  the per-cycle `convergingNow` at both platform loops and passed as `fastWantedNow` to `controlPollIdleWaitShouldEnd`,
  so an idle sleep ends within one 1 s slice of the screen opening — it never arms the persistent window, so
  `isControlConverging()` and the peek-before-drain are untouched, and it ends with the screen (the text channel
  already polls every 1–2 s there). Measured motivation: a passive member saw a kick/handoff only on its next idle
  sweep (device-suite `waitForAdminAffordance` 210 s, `waitForGroupInfoMemberCount` 81 s).

### The steady-state control sweep: 60–90 s, and a bounded-parallel PEEK phase (2026-09-16)

Measured on a real device via a debug-mode upload: `RELAY control poll done: 6-20 contacts in 13.9 / 15.6 / 15.3 /
15.5 s` on a ~34 s cadence — ≈45 % of the foreground session spent inside a sweep — against `1-5 contacts in 0.7 s`
on a phone with fewer contacts. `GroupManager.drainControlInboxes` peeked each contact's control inbox SERIALLY over
Tor (~0.9 s each) with a 100–400 ms jitter sleep between contacts.

- **IDLE cadence 25–45 s → 60–90 s** (`MessageManager.CONTROL_POLL_IDLE_BASE_MS` / `_JITTER_MS`, so both platforms
  move together; each platform's no-transport fallback literal moved with them). The control channel's common case is
  an empty inbox and its payloads tolerate latency — every control append carries `CONTROL_APPEND_TTL_SECONDS` (7 d)
  and membership control is redriven on this same sweep. **The FAST window is untouched**, so a join→roster→resolve
  chain still settles in seconds.
- **Only the PEEK fans out** (`CONTROL_PEEK_CONCURRENCY` = 3, `CONTROL_PEEK_JITTER_MS` = 400). The DRAIN stays strictly
  sequential: `pollControlMessages` reads rows, persists anti-replay counters, applies inbox announces and steps the
  ratchet, and `DatabaseManager`/`IosVaultDatabase` thread-safety under genuinely concurrent access is unproven on both
  platforms. The peek phase is where essentially all of the latency lives, because the common case is an empty inbox.
- **Snapshot-then-fan-out, the same rule the unread prime follows.** `MessageManager.inboundControlPeekTargets` does
  every vault touch of the phase — contact row, the read-cap `maybeReconcileReadCap`, the inbound-ctl row, the cap/inbox-id
  shape checks — on ONE thread before any worker exists; the workers run `peekControlRef`, which is pure HTTP plus the
  two RAM-only side effects the control peek owns (`noteRelayHealthy`, the `hasCompletedRelayRoundTrip` latch) and
  still records NO 404 of its own.
- **Gated to steady state.** Concurrency is 1 while CONVERGING (the peek is skipped entirely then), with fewer than two
  contacts, and until `hasCompletedRelayRoundTrip()` — and the connect-time pre-drain
  (`drainGroupMemberControlsForPrime`) passes `allowConcurrency = false` unconditionally, because that pass shares a
  COLD circuit with the health probe and the 2026-09-11 connect-UX work depends on it staying sequential.
- **Unchanged:** the secure shuffle, the one-`converging`-decision-per-sweep rule, "UNKNOWN (null) DRAINS" (a contact
  simply missing from the answered map drains), the 404 bookkeeping inside `pollControlMessages`, exactly ONE
  `control poll done: N contacts in S s` panel line per pass, and the blocked-contact filter. The
  inter-request jitter is preserved on both paths: in the fan-out each peek starts at a CSPRNG offset, and on the
  serial path only a contact that actually makes a DRAIN request pays the 100–400 ms sleep.
- A relay-side BATCH peek was considered and rejected here without a privacy review. **That decision was reversed for
  the CONNECT-TIME prime only (2026-09-20) — see the next section.** The STEADY-STATE control sweep is
  untouched: it still peeks one inbox per request, three at a time.

### The connect-time prime is ONE round trip: `POST /peek` (2026-09-20)

The connect-time unread prime used to cost one sequential control round trip per group member
(`GroupManager.drainGroupMemberControlsForPrime`) plus a 3-wide `GET /inbox/{id}/peek` fan-out over every contact — all
on the coldest circuit of the session, all inside the wait the user actually sees (the contact list is hidden until the
prime settles; see the `ConnectReveal` paragraph above). `MessageManager.peekInboxesBatch` asks for every one of those
depths in a single request. It supersedes an earlier proposal to make only the pre-drain concurrent.

- **The route.** `POST {relay}/peek`, `Content-Type: application/json`, body `{"v":1,"items":[{"id":…,"rc":…},…]}`,
  at most `BATCH_PEEK_MAX_ITEMS` (64) per body — more inboxes are CHUNKED, never truncated. Answer:
  `{"v":1,"results":[{"id":…,"pending":<int>} | {"id":…,"status":<int>},…]}`. The read cap rides the BODY here (there
  is one cap per item, so there is no `X-Read-Capability` header to put it in); it is still the inbox OWNER capability,
  and the same `isValidInboxId` / `capValidForHeader` gate runs before either value enters the JSON. `"v"` is the JSON
  NUMBER 1 (the relay 400s a string) and the `Content-Type` must be exactly `application/json` (the relay 400s a wrong
  one; an absent one it accepts).
- **Size, stated rather than padded.** The body is **not padded**, on either side: padding is applied to the plaintext
  inside a CIPHERTEXT envelope (`padMessage`), and the one length-bearing fact here — how many inboxes this device
  holds — is precisely what the request tells the relay outright, so padding would buy nothing from the party that
  reads it. Each item is a fixed 92 B (`{"id":"<32>","rc":"<43>"}`) plus one separator, so a full 64-item body is
  ≈ 5.9 KiB, comfortably under the relay's 16 KiB ceiling (it answers **413** above that, or above 64 items). Relay
  responses are not length-padded either.
- **Never batch a cap you would not single-peek.** A wrong read cap inside a batch feeds the SAME per-inbox
  read-strike lockout on the relay as a wrong cap on `GET /inbox/{id}/peek`. Every ref comes from the caller's
  ordinary snapshots (`inboundTextPeekTargets` / `inboundControlPeekTargets`, the latter running the read-cap
  reconcile first), i.e. exactly the caps the single peeks use — no speculative capability is ever batched.
- **What this hands the relay, stated plainly.** The whole set of a device's inbox ids in ONE request, instead of the
  same ids spread over N requests on one rendezvous circuit within a few seconds. The relay already saw that
  correlation; what it loses is the per-request uniformity of the wire shape at connect time. Accepted as a trade-off for
  the connect-time pass only, which is why the steady-state sweep keeps its one-inbox-per-request shape.
- **Three outcomes, and NONE of them may ever read as "empty".** `Counts` (the relay answered — a per-item `status`
  maps to **null = UNKNOWN**, exactly what a null from `peekInboxRef`/`peekControlPending` has always meant),
  `Unsupported` (400/404/405/415/501 — stop asking this relay) and `Failed` (transport error, timeout, any other
  non-2xx including 429 and 413, unreadable body, or a move-frozen device). `Unsupported` and `Failed` both fall back
  to the pre-batch path **unchanged**; an inbox absent from a `Counts` map is identical to a null.
- **Results are matched BY INDEX** — the relay answers one result per item in request order — with the echoed `id` as
  a CROSS-CHECK: a result whose echo is not this position's id is UNKNOWN, never a count attributed to the wrong
  inbox. A results array LONGER than the request fails the whole batch closed; a SHORTER one leaves its tail absent
  (= unknown).
- **The old-relay cost is ONE round trip per TRANSPORT.** `Unsupported` latches `batchPeekUnsupported`, an instance
  field on `MessageManager` — and a `MessageManager` is rebuilt whenever the transport is (Tor self-heal, new SOCKS
  port, new session), which is exactly when a relay could have been upgraded under us. 404/405 is the OLD-relay
  signal; 400 is a current relay refusing OUR body (malformed JSON / `v` not the number 1 / empty items / wrong
  `Content-Type`) — a client defect that re-sending cannot fix, so latching is the fail-safe direction there too.
  429 (rate-limited) and 413 (over-size) deliberately do NOT latch.
- **Side effects are exactly the two single peeks', and no more.** A control ref carries its contactId
  (`PeekRef.controlContactId`) and gets `noteRelayHealthy` on a positive answer, the way `peekControlRef` does; a TEXT
  ref carries none and gets none, which is `peekInboxRef`'s documented safety property. Any 2xx latches
  `hasCompletedRelayRoundTrip` (a `/peek` that answered IS a completed `.onion` round trip). No 404 bookkeeping, no
  vault read and **no vault write** — every id/cap comes from the caller's snapshot.
- **CONTROL-BEFORE-TEXT is a MECHANISM now, not a correctness dependency (superseded 2026-09-24, see the group-inbox
  section below).** Before the third (GROUP) inbox pair, a group text rode the sender's 1:1 TEXT inbox and `/peek`
  returned only a count, so "this is a group text" was knowable only from the `KIND_ACTIVITY` notice on that member's
  CONTROL inbox — an ordering race across independent Tor round-trips (the 2026-09-05 and 2026-09-24 production
  sightings). `primeUnreadCountsBatched` still drains a positive control inbox before it emits a count, and it still
  batches the GROUP inbox depth alongside the TEXT and CONTROL depths in the SAME `POST /peek` — draining/attributing
  it is what still benefits from the pre-drain landing first (precise per-group attribution on the very first frame).
  But the CONTACT dot no longer needs any of this to be correct: it is `peek(inbound[c])` alone, so a slow or lost
  notice degrades only the GROUP row's precision (a presence bump — see below), never the contact row. A control inbox
  the batch reported as a positive 0 is not drained at all; an unknown one drains, via the `peeked != null` branch the
  parallel-peek change already built. While `isControlConverging()` the control refs are left out of the batch entirely and every
  member's control inbox drains unconditionally, which is the pre-existing rule.
- **The panel line reuses `PRIME_PASS`** (`RELAY unread prime batch: N inboxes in X.X s`, counts and seconds only).
  Deliberately NOT a new `ConnectionLog.Code`: the relay allowlists that enum, and a code shipped before the relay
  deploy makes it reject the WHOLE connect report. The fixed phrase is what tells the rung apart, which is the same rule
  the two `NEWNYM` rungs follow.
- **The relay stays UNTRUSTED.** Nothing destructive rides on the answer: a relay lying `pending:0` costs one delayed
  unread dot or one control drain deferred to the next sweep — exactly what it already buys by simply not returning the
  blobs. `BatchPeekPrimeTest` pins the request count, the request BODY (the exact item set), the fallbacks, the
  unknown≠empty rule, the drain-before-emit ordering and the 64-item chunking.

### A THIRD inbox pair carries GROUP texts; the contact dot is correct BY CONSTRUCTION (2026-09-24)

**The product invariant, restated as the acceptance criterion: a group message must NEVER put the unread bubble on the
contact name.** Before this change that was enforced by subtraction (§ above, "CONTROL-BEFORE-TEXT") — a race across
two independent Tor round-trips. The structural fix gives every pairing a THIRD inbox pair, minted and announced
exactly the way the v7 control pair was, so GROUP texts and 1:1 texts land on DIFFERENT relay inboxes and the contact
dot never has to know anything about groups at all. This section is the load-bearing subset for anyone reviewing
vault/relay code.

- **Wire.** `MessageManager.DIR_OUTBOUND_GRP = "outbound-grp"` / `DIR_INBOUND_GRP = "inbound-grp"`, channel tag
  `CHANNEL_TAG_GRP = "g"`. The internal `Chan` enum (`MAIN`/`CTL`/`GRP`, each carrying its own outbound direction,
  inbound direction and `ch` tag) is the single value every one of `sendEnvelopeSerialized`'s four coupled decisions
  (outbound row, counter field, `ch` tag, receive-side `expectedChannel`) now reads — replacing the old two-valued
  `control: Boolean` axis, which was exactly the shape that could desync a `ch`/counter pair. **No version number rides
  the wire**: the capability signal is the PRESENCE of the `outbound-grp` row (`sendGroupTextRouted`) — a peer that
  never announced a group inbox is, by construction, sent group texts on the TEXT inbox, which is today's pre-change
  behaviour, unchanged. `"di"` (destination-inbox id) is unchanged and still binds the append to the specific inbox it
  landed on.
- **The announce is the existing `CONTROL_KIND_INBOX` announce path, extended — not a new kind.** `sendInboxAnnounce`'s body
  gains an OPTIONAL `{"gib":…,"gwc":…}` pair (`gib` = our inbound-grp id, `gwc` = the write cap the peer uses on it),
  appended after `cib`/`cwc` and before `rv`. Reusing `inbox` inherits the ratchet-sealed announce's post-compromise property for free: the
  receiver's `receiveOverTextRatchet(controlChannel = true)` still applies ONLY `inbox` announces, so a new kind would have
  required widening the exact allowlist that closes the forged-announce redirect. **`applyInboxAnnounce` relaxes `ib`/
  `wc` to OPTIONAL, requiring only "at least one complete pair"** — mandatory, not cosmetic, because our own inbound
  WRITE cap is never persisted (see the read-capability section), so a later group-only announce (the backfill, or a group-inbox 404 re-mint)
  physically cannot re-state `wc` for the text inbox; it CAN state `gwc`, straight out of the mint it just performed.
  The `InboxClaim` batch gains `InboxClaim(gib, contactId, DIR_OUTBOUND_GRP)`, so `gib == ib` / `gib == cib` / a
  third-party `gib` is rejected as ONE batch with nothing written, exactly like `cib` today.
- **QR/paste carries it too, with its OWN field names.** `PairingPayload` gains `"gib"`/`"gwcap"` (note: `wcap`-suffixed
  here, matching `wcap`/`cwcap`, vs. the announce body's `gwc` — the same split the control pair already has between
  its QR and announce field names). Both-or-neither, `gib != inbox && gib != cib`. `ReferralManager.acceptBody` gains
  `gib`/`gwc` from the mint, OPTIONAL on the finalize side, with the pairwise-distinctness check extended to all three
  ids. An old build ignores the unknown keys; a new build reading an old code gets `grpInboxId = null` ⇒ the fallback
  above.
- **Minting: eager pair at every pairing + a throttled backfill for existing pairings.** `mintInboxPair` mints a THIRD
  inbox sequentially (same mint-abort deadline check, same all-or-nothing abandonment if it fails). Every pairing that
  predates this change has no group row, so `maybeBackfillGroupInbox(contactId)` runs on the CONTROL SWEEP — never at
  connect time — gated on: not move-frozen (`mintInbox` is deliberately NOT freeze-gated elsewhere, so this check is
  this feature's own), sharing ≥1 group with the contact (or holding a parked invite from them), and
  `hasCompletedRelayRoundTrip()`. Throttled by `grp-ann/<contactId>` (`"<attempts>|<lastMs>"`, ≥24 h apart, 4 attempts
  then permanently parked until a new membership event re-arms it — the unresolved-member fast window's shape, for the same reason: a permanently
  inert contact must never produce a periodic Tor beacon). **During the backfill window the pairing behaves exactly
  like a legacy pairing** — group texts ride the text inbox and the retained legacy subtraction (below) applies; this
  is the one bounded window where the invariant is not structural.
- **Storage.** DB schema 9 → 10 (`DatabaseManager.DATABASE_VERSION`, `IosVaultDatabase`'s idempotent-ALTER list,
  `MigrationBundle.CURRENT_SCHEMA`), purely additive: `Contacts.outbound_grp_counter` / `inbound_grp_counter`, both
  `DEFAULT 0` — a v9 row reads 0 after the ALTER and establishes on the first group blob, same as the v4/v7 counters.
  A v9 `MigrationBundle` still imports (counters absent ⇒ 0); a v10 bundle into a v9 importer answers `SCHEMA_TOO_NEW`,
  non-destructively. `VaultSnapshotIo.import` applies `COUNTER_JUMP` to `outboundGrpCounter` too — omitting that would
  be silent post-move group-message loss (the new phone reusing counters a peer's strict-monotonic check would then
  reject as replays). **`OWNED_READ_DIRECTIONS` becomes `listOf("inbound", DIR_INBOUND_CTL, DIR_INBOUND_GRP)`** — one
  edit that gives cap-pending purge, the relay `DELETE` on contact delete, `resetRelayAccess`'s read-cap rotation and
  the move's post-import read-cap rotation, all four at once; leaving the group inbox out of ANY of them would make it the
  one drain/delete/rotate capability an imaged vault yields forever. `grp-ann/<contactId>` is the one genuinely new
  `_meta` key (`ratchetMetaKeysForContact`'s trailing `OWNED_READ_DIRECTIONS` map already covers the cap-pending
  marker for free) and it is in `MoveMetaPolicy.allowedPrefixes` alongside it. `dr/<contactId>/text` is unchanged —
  see the shared-chain drain rule below, there is still only ONE ratchet chain.
- **Relay: zero code changes, one ops change.** Raise `ServerConfig.maxInboxes` (a global cap, `+50%` on the whole
  table at 3 mints/pairing instead of 2) before any client ships. Everything else already generalizes: `inbox_ids`'
  `direction` column is untyped `TEXT` so a new direction value is data, not schema; the bootstrap→idle TTL promotion
  and `touchInbox` renewal are per-inbox, not per-pairing; `POST /peek` batching and the steady-state sweep's per-inbox
  read bucket are per-inbox too. The steady-state sweep filters the group peek to contacts sharing ≥1 group, so the
  1:1-only majority pays no extra round trip.
- **404 self-heal has ONE deliberate asymmetry.** Inbound-grp is OUR inbox, so a persistent 404 re-mints + re-announces
  in-band (routed through the same throttled backfill) rather than raising the re-pair badge — the one inbox in the
  vault that can legitimately be replaced without user action. Outbound-grp 404 on a send retries that same send once
  on `Chan.MAIN` and mutates no state. A contact with no group row at all never records a group-channel 404 —
  `pollChannel` returns empty before any HTTP when the row is absent, exactly as for a pre-v7 control row.
- **Push.** `allPushableInboxes` becomes `arrayOf("inbound", DIR_INBOUND_CTL, DIR_INBOUND_GRP)`; registration and
  de-registration surfaces stay the same enumeration (`MoveWiringTest` pins that). `sendGroupText` keeps `noPush =
  false` (the text copy is still the one wake per event); `KIND_ACTIVITY` keeps `noPush = true`. iOS background wake
  must peek the group inbox alongside text+control or a group-only wake produces no banner.
- **The publish rules (`GroupTextNeverOnContactTest` / `GroupTextNeverOnContactSourceGuardTest`
  pin this).** `contactUnreadCounts` is `peek(inbound[c]) − legacyGroupPending(c) + unseenScreenshotNotices(c)`
  — **`groupInboxPendingByContact` is not an input to it at any point**, enforced by a source-guard test that fails if
  the symbol appears in the contact path. `legacyGroupPending` (the old `groupPendingByContact` subtraction) SURVIVES
  but is now written ONLY for a `KIND_ACTIVITY` notice WITHOUT the new optional `"gi":"1"` field — i.e. only for a text
  that really did ride the legacy text-inbox path (an un-upgraded peer, or a pairing still in its backfill window). For
  a converged new↔new pairing it is provably dead weight, kept for exactly the two rollout cells that still need it.
  `groupUnreadCounts` is `max(groupUnread[g], ownUntaken(g)) + unseenScreenshotNotices(g) + presenceBump(g)`
  — `max` not `+` because a buffered text and its own notice describe the SAME message. `ownUntaken(g)` counts only
  the OWN items left in group g's screen buffer (an orphaned poll); PRIVATE / GROUP_ECHO items never count.
  **NO-PARK (2026-10-06):** nothing a poll fetches is held for another conversation any more — a 1:1
  text found by a group poll is shown in that group screen as a PRIVATE item (reply goes over the normal 1:1 send),
  a group text found by a 1:1 poll (or another group's poll) is shown there as a GROUP_ECHO item, and showing an echo
  gives its group's `groupUnread` unit back. The old `pendingGroup`/`pendingDirect` cross-conversation buffers lost
  every parked message on lock/relaunch, the relay having burned it at fetch. `presenceBump(g)` is the
  no-notice fallback: `+1` (never `n`, because the true per-group split off an unattributed group-inbox peek is not
  knowable and a bigger number would be a lie) on every group a sender-with-unattributed-group-pending is a resolved
  member of — exact when the sender shares exactly one group (the common case), a bounded over-light across several
  shared groups otherwise, self-correcting the moment that inbox is drained. **It is never, under any circumstance, a
  contact row** — a contact with unattributed group-pending and no shared group lights nothing (the blob simply
  expires off the relay in 24 h; group-inbox peeks never drain, exactly like text-inbox peeks never drain).
- **The shared-chain drain rule: a conversation poll drains BOTH of that contact's text-bearing inboxes, to keep the ONE ratchet chain
  safe.** Splitting texts across two inboxes makes out-of-order ratchet delivery normal rather than exceptional, so
  `pollGroup(groupId)` additionally drains each resolved member's group inbox, and `pollDirect(contactId)` additionally
  drains the group inbox IFF the two devices share ≥1 group (so a 1:1-only conversation pays no extra round trip).
  There is still only ONE ratchet chain per contact (`dr/<contactId>/text`) — group texts ride it exactly as an
  in-band announce already rides it to the control inbox (the ratchet-sealed announce's precedent) — so `dr-on` / `dr-rxlock` / `dr-legacyfb` /
  `dr-refused` are untouched and `MoveMetaPolicy` keeps its existing `dr/` entries verbatim. Receive-side on the GROUP
  inbox (`Chan.GRP`) drops a blob with no `"g"` and a blob carrying a control kind `"k"` (group control stays on the
  control inbox) — mirroring the control-inbox guard (below). Receive-side on the TEXT inbox is UNCHANGED: a group-tagged
  blob arriving there (a legacy peer, or a message sent during the sender's own backfill window) is still accepted and
  routed to `ingest` — dropping it would lose messages, not just misattribute them.
- **What the relay newly learns, stated honestly (trade-off).** An append to a `-grp` inbox is, by
  definition, a group text — a per-message group-vs-1:1 classifier, plus "this pairing exchanges group texts at all"
  and how often. This sharpens an existing inference (the relay could already infer "probably a group text" from a
  text append immediately followed by an `X-No-Push` control append to the same pairing) from probabilistic to
  definitional; it does not reveal which group, group size beyond the already-visible fan-out, membership or content.
  It is not mitigable within this design — anything the receiver can determine from routing before a decrypt, the
  relay can determine too, and that is the price of making the contact dot correct before a decrypt.

### The two narrowings that turned the slower idle cadence into a convergence stall (2026-09-17)

The slower idle cadence is correct and stays. What it exposed is that **two separate predicates both answer "not converging" in
exactly the state where convergence is pending**, so a group chain that fell out of the fast window then paid the new
60–90 s idle at every remaining hop. Found on a physical `cross:multi3` whose Android seat, after a 3-minute Tor
brownout and the harness's relaunch, ran ≈24 control sweeps in 4.5 min (fast) and then dropped to a single 95 s gap at
exactly `member.addedAt + 10 min`. Both fixes are `commonMain`, so both platforms move; the cadence constants are
untouched.

- **`GroupManager.noteControlConvergence` gated on `isKnownGroupMember(contactId)` alone**, which tests
  `member.contactId == contactId` — **false for the very peer whose member slot is UNRESOLVED** (that slot's
  `contactId` IS `null`), and false for a first group INVITE (parked for consent, so no member row exists yet). A
  device whose whole group was unresolved therefore armed the persistent window on NOTHING. It now also arms on
  `hasUnresolvedMembers()` or a parked invite from that contact. Neither re-opens the remote fast-cadence pin: the first is
  window-bounded and the second is bounded by the user's consent plus the invite caps, so a stranger with no
  group, no unresolved co-member and no parked invite still arms nothing.
- **The unresolved-member fast window was measured from `member.addedAt` alone**, which `handleRoster` deliberately preserves
  (`existing?.addedAt ?: now`) and which is persisted, so it means "how long ago this SLOT was created", not "how long
  this chain has been converging". `hasUnresolvedMembers()` now measures from `max(addedAt, last membership EVENT for
  that group)` via a **RAM-only, session-scoped** `groupId -> clock` map (`noteUnresolvedFastAnchor`, bounded at 64,
  oldest evicted, cleared by `scrubInMemory`), re-anchored when a roster/leave/invite/join is APPLIED and when
  `acceptInvite` commits. The window's bound is untouched and that is why the anchor is per-EVENT and never persisted: a
  never-IRL-paired member produces no membership events, so it never re-anchors, and there is deliberately **no
  session-start anchor** — that would hand every foreground return a fresh 10-minute fast window on a permanently
  inert member, which is the fixed Tor beacon that bound exists to prevent. A fresh session costs at most ONE idle interval
  before the first membership control re-anchors it. **2026-10-17 — the anchor is bounded against a PEER, two
  ways.** `ingest` used to re-anchor on the mere ARRIVAL of a membership kind for a held group, whatever the handler
  did with it, so any paired co-member could hold the device on the 2.5–5 s cadence (and keep an admin's
  `joinPending` (next section) open, vetoing `transferAdmin`) by pinging a no-op roster/invite/join/leave every few minutes — the
  `CONTROL_FAST_EPISODE_MAX_MS` ceiling bounds only the persistent window, not `convergingNow`. Now (1) `ingest`
  re-anchors ONLY when the applied control CHANGED the `convergenceFingerprint` (epoch / admin / member count /
  resolved count — the same before/after probe `noteControlConvergence` already paid for), so a dropped, stale,
  malformed or unchanged re-applied control buys nothing while every applied hop of a real join→roster→resolve chain
  still re-anchors; and (2) anchor-driven fast time is capped per group per episode at
  `GroupManager.UNRESOLVED_FAST_EPISODE_MAX_MS` (= `CONTROL_FAST_EPISODE_MAX_MS`, 10 min) from the episode's FIRST
  anchor — an anchor inside a live episode never extends it, and a new episode needs a genuinely quiet gap of a whole
  `UNRESOLVED_MEMBER_FAST_WINDOW_MS` with no anchor — so an admin flapping the epoch (applied rosters, fingerprint moving
  every time) gets at most 10 min fast per 20 min. Past the cap `GroupFastAnchor.anchor` answers 0 and both predicates
  fall back to the persisted `addedAt` alone (the pre-anchor behaviour); `transferAdmin` reads the same bounded anchor.
  `acceptInvite`'s local anchor is untouched. `GroupFastAnchorPeerBoundTest` pins all of it, including a live oracle
  that pulls the anchor directly to show it is the lever the pings used to reach.

### An admin must not hand the role on while a JOIN is still in flight (2026-09-17)

The 18:24 `cross:multi3` red was root-caused on the dev-relay journal, and it is not a lost drain. Timeline (UTC;
every blob below was appended AND drained with `blobsReturned>0`, so the UNKNOWN-DRAINS path is ruled out here):
`16:49:50` the admin appends the INVITE to the re-added member, `16:49:51/52` its companion rosters; `16:50:52` its
~7 s control drains stop dead — **exactly 60 s after its last control SEND**, i.e. `CONTROL_CONVERGENCE_WINDOW_MS`
expiring — and it drops to the 60–90 s idle cadence; `16:51:12` the member's `KIND_JOIN` lands; `16:51:31/34` the
admin broadcasts the HANDOFF roster *without it*; `16:51:57` it leaves; `16:52:10` it finally drains the join, 38 s
too late, and `handleJoin` dies at `vault.getGroup(groupId) ?: return`. The promoted member was left `members=2/2,
unresolved=1`, permanently.

Two `commonMain` fixes, both bounded by the existing unresolved-member fast window so no new traffic shape is introduced:

- **`GroupManager.joinPending`, folded into `hasUnresolvedMembers`.** A member row that is **resolved but carries no
  tags** on a device that is the group's **ADMIN** is a member we added by contact whose join has not been ingested.
  The old predicate tested `contactId == null` alone, and `addMember` inserts the row WITH a `contactId` — so the
  admin awaiting the join it had just solicited was invisible to its own convergence predicate. It is **admin-gated**
  (a non-admin device stores no tags at all — `GroupMemberRecord.tags` kdoc — so an unguarded "empty tags" test would
  pin every plain member to FAST), never our own row, and expires `UNRESOLVED_MEMBER_FAST_WINDOW_MS` after
  `max(addedAt, last membership event)`. It reads only local state THIS device created, so unlike the remote-traffic arming
  path no peer can reach it.
- **`transferAdmin` REFUSES while any other member's join is pending.** It is the only roster caller whose
  incompleteness is irreversible. `buildRosterBody` redistributes a member's bound tag only when ANOTHER member
  carries the same sym, so one tagless row makes EVERY other entry tagless; every other caller (`addMember`,
  `removeMember`, `handleJoin`, `rerosterUnconvergedMembers`) keeps the admin role here, so the join that lands a
  second later re-rosters with the full set — a HANDOFF moves the only device that can ever redistribute them, and
  `handleRoster`, the single resolution site, never runs on an admin. Returning `false` is safe for both callers: the
  plain "make admin" path is a retryable no-op, and handoff-then-leave is already fail-closed on this boolean
  and does not leave. **Time-bounded on purpose** — an inherited admin's row for its own inviter is also tagless
  (`handleRoster` skips an already-resolved slot), so an unbounded guard would make `transferAdmin` permanently
  impossible for that group; after the window the transfer proceeds with its known incompleteness rather than
  dead-ending the UI. `handleJoin`'s resolved-sender check is **untouched**.

`GroupJoinPendingHandoffTest` pins all of it, including a live oracle that still builds the tagless roster a pre-fix
handoff would have shipped.

`handleJoin`'s resolved-sender check is load-bearing — it is what stops an unresolved/non-member slot from
injecting tags; never loosen it.

### Two smaller group rules that are easy to re-break (2026-09-16)

- **The control-inbox guard drops a bare text whether or not it is GROUP-TAGGED.** It used to require
  `controlKind == null && groupId == null`, so `{"g":…}` with no `"k"` sailed through — and that was the delivery
  vector for a buffer flood: a removed member posting group-tagged, kind-less blobs onto the victim's CONTROL inbox
  reached `GroupManager.acceptGroupText` on the BACKGROUND sweep, with no conversation open, and parked them. Nothing
  legitimate produces one (`sendGroupText` sends with `control = false` and every control sender writes `"k"`), so the
  rule is now simply: **a control-inbox blob with no control kind is dropped.**
- **The unresolved-sender buffer (`ConversationBuffers`) evicts, it does not reject.** It now routes through the same
  `evictForCapacityLocked` every sibling content buffer uses, with a per-(group, sender) sub-cap of 16 inside the global
  64, dropping the OLDEST entry of whichever key holds the most. The old global-only cap REJECTED the incoming message,
  so one flooding sender could hold all 64 slots and every group text from a genuinely not-yet-resolved member was
  dropped off a relay drain and lost for good — the exact loss that buffer exists to prevent. A flooder can now
  only ever destroy its own parked blobs.
- **A LEAVE carries its epoch and the leaver's memberId, and both are OPTIONAL on receive.** A KIND_LEAVE obligation
  can be redriven for up to 7 days, so one recorded before the sender RE-JOINED the same groupId would evict them
  again. Three guards: `acceptInvite` purges every `grp_ctl_pend:<groupId>:*` for the group it just joined; the redrive
  refuses a LEAVE while that group exists locally; and `handleLeave` drops a leave naming a `"you"` memberId the slot no
  longer holds (memberIds are minted per membership instance, so a re-join gets a new one). The `"ep"` field is carried
  and is applied ONLY when `"you"` is absent — **deliberately not on its own.** The epoch advances only at the ADMIN, so
  two members leaving inside one jittered fan-out window make the second leave arrive epoch-stale at an admin that
  already processed the first, and dropping it would strand that member in the roster (and in every later roster)
  forever. The memberId test catches every stale-redrive case the epoch test would, with none of that cost. A peer that
  predates both fields sends `{}` and is accepted exactly as before.

### Skipped ratchet keys expire; the responder's legacy fallback is counted (2026-09-08)

- **Skipped keys expire.** Skipped Double-Ratchet message keys (out-of-order delivery) used to sit in `dr/<id>/text` for the life of
  the pairing, bounded only by a 1024-entry cap — so a relay withholding blob *k* while delivering *k+1* left `mk_k`
  at rest forever, decryptable from a later vault open. Now: `SER_VERSION` 3 stamps each skipped entry with its
  creation time; entries older than `SKIPPED_KEY_TTL_MS` (24 h) are pruned on every load and every decrypt (a future
  stamp is never treated as expired — fails toward keeping a key, never toward message loss); `dhRatchet` flushes the
  skipped keys of any chain two or more DH steps back (the just-retired chain is kept for the in-flight case);
  `MAX_SKIPPED_STORE` is 128 (legacy blobs up to 1024 are still READ, then trimmed and re-persisted — rejecting them
  would have re-bootstrapped the pairing). v1/v2 blobs deserialize with `loadedAt` as the stamp; migrate-on-write.
  Every evicted/expired/consumed key is `secureWipe`d. A load that dropped entries is persisted immediately by
  `RatchetManager` so dead keys leave the VAULT, not just RAM. **Downgrade skew:** an older build reading a v3 blob
  hits `onCorruptReinit` and re-bootstraps over legacy — self-healing, same shape as the v1→v2 bump.
- **The legacy fallback is counted.** A responder with no sending chain falls through to the static envelope silently and without bound, so a
  relay dropping every ratchet blob to it could pin one direction on no-forward-secrecy (cost: a total, permanent
  blackout of the initiator's messages — conspicuous). The fallthrough is now COUNTED:
  `dr-legacyfb/<contactId>` (in `ratchetMetaKeysForContact`) increments per consecutive legacy fallback, clears on the
  first landed ratchet send, and `forwardSecrecyStalled(contactId)` (threshold 8) drives the conversation-screen
  notice on both platforms. A non-constant wire tag was NOT adopted (a per-pairing constant prefix
  is learned from the first repeat and risks a wire-format skew for thin gain).

### The ratchet ROLE is derived from the pairing SECRETS once both sides prove they run the rule (2026-09-18)

- **The gap.** The role-collision latch (next section) detects and refuses a role collision; it does nothing about the peer CHOOSING the
  victim's role, and nothing about the two honest-path hazards in the same mechanism: the role inputs are MUTABLE
  after pairing (an `inbox` announce rewrites the outbound row at any time) and `RatchetManager.loadOrInit`
  recomputes the role whenever no state is persisted — which is exactly what `onCorruptReinit` produces. An
  announce plus an asymmetric re-init could therefore flip one side's role on a perfectly honest pairing.
- **The rule.** When BOTH sides are known to run it, `selfIsBob = parity(HKDF(sharedSecret, info =
  "run-dr-role-v1", 1 byte)) XOR mineSortsFirst` (`DoubleRatchet.ratchetSelfIsBobFromRoleOrder`), where
  `mineSortsFirst` is fixed at pairing and can never move. `MessageManager.ratchetSelfIsBobOverride` resolves it and
  passes it to `loadOrInit` as `selfIsBobOverride`; `null` means the legacy `ratchetSelfIsBob(myInbound,
  myOutbound)` id comparison, **unchanged**. `loadOrInit` still consults the rule ONLY when no state is persisted,
  so no existing pairing is re-roled, there is no blob-format change and nothing migrates.
- **Two per-contact `_meta` rows, no schema change (both `VaultDatabase` actuals untouched).**
  `dr-roleord/<contactId>` = `"1"`/`"0"`, the ordering bit; `dr-rolerv2/<contactId>` = `"1"`/`"0"`, what the peer's
  build was observed to be AT PAIRING. **Both must be present and the second must be `"1"`** or the id rule
  applies. Both are in `ratchetMetaKeysForContact` AND `MoveMetaPolicy.allowedPrefixes` — a re-pair mints new
  pairing secrets, so an inherited order bit would be computed against the wrong pair; and a move that dropped them
  would leave the new phone on the id rule and able to pick the OPPOSITE role at its first re-init.
- **The two secret HALVES are deliberately NOT persisted.** The only fact the rule reads from them is one bit of
  ordering, and that bit is computable at `PairingVault.savePairedContact` time on BOTH devices (the QR exchange is
  mutual — each side must scan the other to derive `sharedSecret = sha256(sort(a,b))` at all). Storing the bit adds
  **no key material at rest**, is exactly as immutable, and lets the value travel in a move bundle without carrying
  pairing secrets off the device. `ratchetRoleOrderBit` orders by the SHA-256 of each input — the same canonical
  ordering `deriveSharedSecret` uses — and returns **null** for identical inputs, whereupon the caller persists
  NOTHING: answering `false` on both devices would hand them the same role, i.e. manufacture the collision.
- **The referral path** has no symmetric halves (X25519 ECDH), so the order bit comes from the two ephemeral
  **public** keys, written inside the same `withTransaction` that commits the referred contact.
- **`rv` rides three carriers, all OPTIONAL, all appended LAST, all JSON STRINGS** (`"rv":"2"` — every parser here
  reads only string values, so a numeric `2` would read as absent): the QR/paste payload
  (`PairingPayload.buildSecretOnly`/`buildFull` → `PairingScan.roleRuleV2`; an unknown, absent or malformed value
  is never a rejection), the `inbox` announce body (`sendInboxAnnounce` → `applyInboxAnnounce`), and the referral
  **accept** body (`ReferralManager.acceptBody`). The referral OFFER deliberately does NOT carry it: an offer is
  composed by the INTRODUCER, whose build says nothing about which rule the two introducees will apply.
- **A `"0"` is a LATCH and it is load-bearing.** The order bit is only ever written by a build that has this change,
  and such a build always learns the peer's version in the same step, so "order bit present, peer was v1" is a
  COMPLETE observation. If a later announce could upgrade it, a mixed-version pairing whose OLD side merely
  UPDATES THE APP would move the new side to v2 while the old side — whose vault has no order bit and never will —
  stayed on the id rule: a collision produced by nothing but an app update. `notePeerRoleRuleV2` therefore fills an
  ABSENT observation only; it never overwrites `"0"`.
- **Every ambiguity fails toward the id rule**, never toward a refusal or a wipe: no marker, a marker that is not
  exactly `"1"`/`"0"`, a throwing `_meta` read. That is both the brick-safe direction and the only CORRECT one — a
  role rule needs AGREEMENT, and a peer we cannot prove otherwise about is using the id rule.
- **What it does NOT do.** A modified client can still regenerate its own secret half (or its ephemeral keypair)
  and grind the parity in ~2 tries, and can still simply act as the wrong role — by design, the role is a
  private choice on each device and the wire carries no role byte. The role-collision latch (next section) is what catches that. And the benefit
  accrues to NEW pairings only: every pairing made before this, and every pairing with an older build, keeps the
  id-order rule for life, deliberately (re-roling an established pairing IS the collision).
  `RatchetRoleBindingTest` (12 hermetic tests) pins all of it, including a control half that proves the id-order
  rule really does flip across an announce + re-init, so the stability assertion is not vacuous.

### The ratchet ROLE COLLISION is detected on both sides and the downgrade is refused (2026-09-18)

- **The gap.** The Alice/Bob role is `ratchetSelfIsBob(myInbound, myOutbound) = myInbound < myOutbound`, and
  `myOutbound` is the id the PEER declared (QR payload or in-band `inbox` announce), so a peer running modified code
  puts both devices in the same role: **both-Bob** (no side ever holds a sending chain ⇒ every send falls through to
  the static envelope, permanently) or **both-Alice** (both hold sending chains ⇒ every blob fails the peer's AEAD, a
  silent permanent blackout). The legacy-fallback counter sees only the first — `tryEncrypt` never returns null in the second.
- **The rule.** Two consecutive-evidence counters, both per-contact `_meta`, both in `ratchetMetaKeysForContact` AND
  `MoveMetaPolicy`: `dr-legacyfb/<id>` (the legacy-fallback counter, both-Bob) and the new `dr-rat-unacked/<id>` (both-Alice — consecutive
  inbound TEXT drains that carried blobs and produced NO decryptable ratchet blob, counted only once ≥ 4 of our own
  ratchet blobs are unanswered, read off the ratchet's own send counter via `RatchetManager.hasSentAtLeast`). Either
  at 8 latches `dr-refused/<id>`, and from then on a 1:1/group TEXT send FAILS (`false`, the existing shape — a
  thrown type would SIGABRT the Swift bridge) instead of shipping on the static envelope. `ratchetRefused(contactId)`
  is the UI reader beside `forwardSecrecyStalled`.
- **Four rules that are load-bearing.** The latch is read ONCE *before* the ratchet attempt and applied *after* it, so
  a successful ratchet send is never blocked and the send that crosses a threshold still goes out (it is the evidence,
  not the verdict). CONTROL traffic is never gated — its static envelope is the designed fallback for every contact
  (the ratchet-sealed integrity kinds included), so there is no downgrade to refuse, and gating it would break group convergence, the referral handshake and the inbox announce a
  recovery needs. A refusal NEVER touches `dr/<id>/text`: it blocks sends, it does not wipe or re-init a ratchet.
  Absence fails toward NOT refused everywhere (fresh/legacy/unreadable vault, empty drain, no ratchet sends
  outstanding) — the same brick-safety direction as every other marker here.
- **Recovery.** One inbound ratchet blob that DECRYPTS — on either channel, since a ratchet-sealed announce on the control inbox
  advances the same text ratchet — clears both counters and the latch immediately; a re-pair clears them with the
  contact; `onCorruptReinit` clears them too, because that path returns the pairing to the legacy bootstrap the latch
  would otherwise refuse forever (the verdict is re-earned in ≤ 8 sends if the roles really did collide).
- **What it does NOT do.** The ≤ 8 sends before the refusal arms still ship at the pairing's bootstrap security
  level. A hostile relay can force a refusal by serving junk blobs — accepted, strictly weaker than blackholing the
  inbox, and inert while the device still holds a working sending chain. (The secret-derived role rule, above, is what stopped the peer
  from choosing the victim's role on an honest pairing; a modified client acting as the wrong role is still this
  latch's case, by construction.)

### The Android crypto-erase is verified and double-killed; the Tink keyset is classified by its bytes (2026-09-08)

- **Keyset classification.** `AndroidKeysetManager.isUsingKeystore()` in tink-android 1.21.0 is `masterAead != null`, and the Builder's
  SECOND cleartext fallback (`parseEncryptedKeyset` throws → `readKeysetInCleartext`) leaves `masterAead` set — so a
  CLEARTEXT keyset on disk with a healthy Keystore reported "wrapped" and was never repaired, and the repair's own
  `verified.isUsingKeystore()` check was vacuous. `KeysetWrapProbe` now decides from the persisted bytes:
  hex-decode the pref, `LegacyKeysetSerialization.parseKeyset(…, InsecureSecretKeyAccess.get())` succeeding ==
  cleartext (an `EncryptedKeyset` provably fails that parse — `KeysetWrapProbeTest` runs it against the real jar).
  The re-wrap is verified the same way in reverse. Absent pref before the write = first provision (never rewrite the
  only copy); absent after = the write did not land → `KeyUnavailableException` (defer). A cleartext-state install
  on a LOCKED device now defers instead of succeeding insecurely; it self-repairs on the next unlocked launch.
- **Verified erase.** `eraseMasterKey` was one unverified `deleteEntry` in a bare `catch {}` plus an unchecked
  `deleteSharedPreferences` — the single irreversible step of the wipe. It now reads back `containsAlias` with
  retries AND, independently, overwrites the wrapped-keyset ciphertext in place with random hex of equal length
  (synchronous `commit()`) before deleting the file, returns whether at least one half is proven, and
  `run_keyset_prefs` is also in `WipeRoutine.PREFS_FILES`. Known limitation, stated honestly: with the master key
  surviving, `vlt_c`'s INNER layer is still the PIN-derived Argon2id KEK, so the exposure is the documented CR-1
  offline grind on a CASUAL PIN (unthrottled, since the counters are wiped), not the vault outright.

### `vlt_abk` reads three ways; the re-harden nudge is wired (2026-09-08)

- `isAuthBoundKeyStrict()` used to `catch (Exception) { true }`, collapsing a transient device-key OUTAGE and a
  blob-shaped AEAD FAILURE into "already strict" — one zero-crypto write of ≥28 base64 bytes into `vlt_abk`
  (prefs XML on Android; the iOS Keychain item is `WhenPasscodeSetThisDeviceOnly` and not forgeable from a locked
  image, so the write primitive is Android-realistic only) permanently suppressed `maybeReconcileLegacyAuthBoundKey`,
  pinning a PRIVATE vault on the legacy device-credential-openable Lever B key. Now: `KeyUnavailableException` → true
  (outage, do not rotate), `SelectorMetaDamagedException` → false (tamper evidence; the reconcile is separately gated
  on `supportsAuthBinding` + a present recovery blob, non-fatal, and rewrites the slot on success, so damage
  self-heals). `needsLeverBReharden()` finally has consumers: both protection-level settings screens show a compact
  notice (`lever_b_reharden_notice`) pointing at the existing disable→enable flow.

### Move to new device: logical bundle, freeze gate, counter jump, read-cap rotation (2026-09-09)

Design: `docs/device-move.md`. Contract: `MoveContracts.kt`. What every future reader must keep true:

- **The vault FILE never moves.** Android created its vaults in SQLCipher passphrase mode (now
  usually opened raw with the ADOPTED K' — see "Android adopts SQLCipher's raw-key mode") and
  iOS keys raw with the dbKey itself, so the file is not portable even with the key. The bundle is a logical export
  (`VaultSnapshotIo.export`): contacts, every inbox row, groups, members, and `_meta` rows that
  pass `MoveMetaPolicy.isAllowedKey`. `MoveMetaPolicyPinTest` fails if any key in
  `ratchetMetaKeysForContact` is not carried (found the hard way: `ib-bound-seen/`). No `vlt_*`,
  KDF params, verifier, attempt counters or inactivity anchors ever travel; the new phone
  provisions a fresh vault through the untouched `provisionCredentialAndVault` and imports after
  its first unlock.
- **`mig_frozen` is the durable authority on the old phone**, written before anything else in
  `beginExport`. It is enforced INSIDE `MessageManager` (`moveFrozen(op)`): every contact-facing
  send/poll/peek/mint-pair/rotate and `allPushableInboxes` refuse with their existing failure
  shape and make zero HTTP calls. The provider gate in `SessionManagers` is belt-and-braces, not
  the guarantee. Only the transfer primitives (`mintInbox`, `postMoveChunk`, `peekMoveInbox`,
  `drainMoveInbox`, `deleteInbox`, `rotateOwnedInboxReadCap`) stay open — a transfer inbox has no
  contact, counter, epoch or chain. `quiesce()` stops loops but keeps Tor and the MessageManager
  alive; a relaunch over a frozen vault is frozen without any MoveManager involvement.
- **There is no epoch to bump.** `messageEpoch` derives from `sharedSecret`. Import adds
  `MoveConstants.COUNTER_JUMP` (10 000) to `outboundCounter` and `outboundCtlCounter` once
  (guarded by `mig_imported == bundleId`, written LAST in the import transaction). Peers accept
  gaps, never reuse.
- **Sealing:** 20-byte CSPRNG code (Base32, never persisted, `scrubInMemory` on background/lock),
  `HKDF(code, salt = inboxId, info = run:migrate:v1)`, AES-GCM per chunk with
  `inboxId‖bundleId‖index‖count‖label` as AAD. Every chunk is exactly 60 028 bytes on the wire
  and is POSTed RAW — never through `padMessage`/the envelope (that lands 28 bytes over the
  relay's 64 KiB `maxBlobBytes`). `?ttl=1800`, `X-No-Push`, drained by a bare `GET`, then
  `DELETE` under the read cap.
- **`Moved` is a hint, not proof**: an expired transfer inbox also answers 404. The UI tells the
  user to confirm the new phone shows contacts before wiping; the keep button never disappears.
  `cancelExport` needs `peek >= chunkCount` and refuses on an unreachable relay (no unfreeze
  without proof: two live copies is the fork hazard).
- **Read-cap rotation on the new phone** goes through the crash-safe `rotateReadCap`/`cap-pend`
  path. The rotation list (`mig_rotate_pending`) is written right after the import commits (before
  any network call), filtered by the referral-protected set (pending `ref_*` inboxes are skipped),
  and shrinks per successful rotation; the control-sweep retry applies the same referral filter, and
  a failed referral scan rotates nothing. Its `onRotationCommitted` also evicts whatever push
  token the old phone left. Full re-mint + announce is deliberately deferred (phase 3).
- **Residue:** every `mig_*` key lives in `_meta`, survives `deleteContact`/`deleteGroup`
  (a contact delete must never unfreeze a mid-move phone) and dies with `wipeAllTables`.
  `mig_handle` holds `inboxId|readCap|bundleId|chunkCount`; the code is RAM-only.

### The connection log is a release-visible surface: fixed phrases only, RAM-only, cleared on lock/wipe (2026-09-11)

`ConnectionLog` (commonMain) feeds the panel behind a triple tap on the connecting caption, in
release builds too. Rules: every `append` builds its text from fixed phrases and numbers — never
an identifier (no inbox id, cap, onion host, URL, contact/group name, token); `redact()` strips
URL/`.onion`/base64url≥32 shapes as defence in depth, not as the guarantee. The phrases are
IDENTICAL word for word on both platforms, and where two rungs share a `Code` the phrase must
still tell them apart with fixed words only — the cold connect-time `NEWNYM` rung renders
`(NEWNYM n/2)` and the stall-watch rung `(NEWNYM n, stall watch)` (2026-09-15; they used to be
byte-identical, and the wire vocabulary is unchanged — the timeline still carries only `NEWNYM`).
**Warm NEWNYM rung (2026-10-07, no new code):** the cold rung retires at the first answer, so a
session that answered and then went dark waited for the heavy ladders — Android's stall watch
starts its 100 s clock only after the 3-miss hysteresis flip (~60–90 s into a warm outage, first
NEWNYM ~140 s in; A13 field timeline), iOS's sustained rung needs 64 s of counted misses (~110 s
in). The shared `MessageManager.shouldFireWarmNewnym` (warm transport only — the exact complement
of the cold rung's `coldTransport`; first fire on ≥ 3 consecutive full-budget probe timeouts
spanning ≥ 28 s, repeat on ≥ 2 fresh ones ≥ 40 s later) with budgets in the shared
`WarmNewnymLedger` (≤ 2 per dark run, ≤ 6 per rolling hour — NEWNYM keeps the guards, but every
fire is one more HSDir fetch, fresh intro/rendezvous circuits and a circuit-build burst at the
guard, so repetition is the anonymity cost) is asked by Android `RunViewModel.maybeFireWarmNewnym`
and iOS `AppState.maybeFireWarmNewnym`; phrase `(NEWNYM n/2, warm)`, code `NEWNYM`. The stall
watch / sustained rung / `.stalled` / `relaunchRequired` backstops are unchanged.
The end of the user's wait is its own code: `REVEAL` (the frame the contact list appears in) and
`PRIME_CAP` (the backstop that reveals without the unread prime).
**The 2026-09-15 change widened the vocabulary from 55 to 69 codes, all produced at the producer:**
the bootstrap ladder is coded by PHASE GROUP (`TOR_BOOT_STARTING` / `_CONN` / `_HANDSHAKE` /
`_ONEHOP` / `_DESCRIPTORS` / `_DIRINFO` / `_AP_CONN` / `_CIRCUIT` / `_DONE`) through the one
shared lookup `TorBootstrapPhase.codeFor` (commonMain — Android reads the tag out of the NOTICE
log line, iOS out of the control port's `STATUS_CLIENT BOOTSTRAP` arguments, and an unrecognised
tag still falls back to `TOR_BOOTSTRAP_TAG`, so a code is never derived from a string); the
consensus-age line splits into the three OUTCOMES `CONSENSUS_FRESH` / `CONSENSUS_STALE` (3 h, a
consensus's own validity window) / `CONSENSUS_UNKNOWN` — the retired `CONSENSUS_AGE` stays on the
RELAY allowlist so older clients are not rejected; HS `CIRC … LAUNCHED` gets
`INTRO_CIRC_LAUNCHED` / `REND_CIRC_LAUNCHED` (LAUNCHED-without-BUILT is the stall signature, the
onion twin of `ORCONN_LAUNCHED`); and the FAST probe failure, previously uncoded, is
`PROBE_FAILED` (sheddable — `PROBE_TIMEOUT` is not). iOS also subscribes ORCONN 0.75 s after the
bootstrap observers are registered instead of only at `.connected`, so the guard-channel phase is
visible during the bootstrap the way it always was on Android.
**CIRC_MINOR (2026-10-06, no new codes):** Tor reports the onion handshake's HS_STATE transitions
ONLY as `CIRC_MINOR … PURPOSE_CHANGED` (`circuit_change_purpose()` never re-emits a plain CIRC), so
until both platforms subscribed to it (Android's event socket `TOR_SETEVENTS_COMMAND`; iOS
`controlEventsFull`, which still carries `STATUS_CLIENT`) `INTRO_SENT` / `INTRO_DONE` /
`REND_JOINED` were never produced (0 of 3677 timelines). Mapping, identical phrases on both:
→`HSCI_INTRO_SENT` "introduction sent" (`INTRO_SENT`); `HSCI_INTRO_SENT`→`HSCI_DONE` "introduction
complete" (`INTRO_DONE`, the ack); `HSCI_INTRO_SENT`→`HSCI_CONNECTING` "introduction refused"
(`INTRO_CIRC_FAILED`, the intro point's NACK); `HSCI_CONNECTING`→`HSCI_DONE` (the give-up after a
NACK) no line; →`HSCR_JOINED` "rendezvous joined" (`REND_JOINED`). Same day: an intro circuit
`CLOSED` with `REASON=FINISHED` or `HS_STATE=HSCI_DONE` is Tor's ordinary post-ack close and no
longer codes `INTRO_CIRC_FAILED` (it did in ~70 % of fast, healthy timelines); `FAILED`, and a
`CLOSED` with any other reason before the ack, still do. Only the event keyword, `PURPOSE`,
`HS_STATE`, `OLD_HS_STATE` and `REASON` are read — never the circuit id, path or `REND_QUERY`.
**Descriptor-fetch re-requests = the earlier bounded HSDir hedge (2026-10-12, no new codes; replaces
the 2026-10-06 4 s watchdog and its per-NEWNYM `DescriptorRefetchLedger`):** a v3 descriptor fetch stuck
on one HSDir is reaped by Tor only after `TestingDirConnectionMaxStall` (5 min) and blocks any second
fetch ("Already a pending directory request"); a control-port `HSFETCH` launches one anyway. Both
platforms parse every event with the shared `RelayDescriptorWatchdog.parseEvent` (compares the
`HS_DESC` HSAddress with the relay's address; only the action leaves it) and feed the SESSION-scoped
shared `DescriptorHedge` (commonMain, lock-guarded, owned by `RunViewModel` / `IosAppController`,
handed to every TorManager). The first `REQUESTED` with no `RECEIVED` (cache miss) opens an episode;
`HSDESC_HEDGE_MS` = 1 s later, if no descriptor yet, ONE BARE `HSFETCH <address>` (no `SERVER=` — Tor
keeps its responsible-HSDir selection and its 15-min recently-asked filter, which `SERVER=` would
bypass) overlaps the pending fetch; `HSDESC_SECOND_HEDGE_MS` = 4 s after that one more re-request may go
out — the only one that uses the `HsDirLedger` pin below. Bounds: ≤ `HSDESC_MAX_IN_FLIGHT` = 2 fetches
in flight, counted from `REQUESTED`-without-outcome EVENTS (a 250 only acknowledges the command) plus
hedges sent < `HSDESC_HEDGE_CONFIRM_MS` = 1 s ago whose REQUESTED has not shown (after that a hedge stops
counting and the panel says "descriptor hedge not started by Tor"); a due hedge blocked by the cap is
deferred until an outcome frees a slot — and since 2026-10-13 (device A/B run: original + 1 s hedge both hung,
the cap held the re-request 24 s) a request older than `HSDESC_PRESUMED_DEAD_MS` = 4 s with no outcome
stops counting toward the cap, so the 4 s re-request always fires when the budget allows;
DESCRIPTOR-STAGE EARLY RECOVERY: an episode still open `HSDESC_STAGE_DEADLINE_MS` = 10 s after its first
request with the budget spent or ≥ 2 requests outcome-less asks the session owner (once per episode) for
ONE NEWNYM through the warm-up rotation's shared gate and budget (`shouldFireWarmupNewnym`, cap 2 shared
with the cold rung; Android `RunViewModel.fireDescriptorStageNewnym`, iOS
`AppState.fireDescriptorStageNewnym`), panel "descriptor stage stalled - requesting fresh circuits" (uncoded)
followed by the usual coded NEWNYM line; it REPLACES the warm-up's own 25 s NEWNYM for that stall (the
warm-up then retries its GET without one); the control arm suppresses it too; ≤ `HSDESC_FETCH_BUDGET` = 4 hedge `HSFETCH`es per SESSION,
charged for every one handed to the control channel (incl. the plain retry after a rejected pin and one
Tor never started), NEVER replenished by an accepted NEWNYM or a Tor restart within the session (a
renewable bound is not a bound; the old "descriptor refetch budget reset after NEWNYM" line is gone) —
only a new session starts a new budget; only before the session's first relay answer. NEWNYM / a new Tor
process reset the in-flight count and the episode (Tor purged its HS state), not the budget. Late
losers: once one fetch is `RECEIVED`, later RECEIVED/FAILED only decrement the count — nothing fires,
and nothing anywhere reacts to `HS_DESC FAILED` but the panel line, so no NEWNYM can retire the winner's
circuits. A REQUESTED matching a hedge we sent never opens a new episode. Android's pre-unlock warm-up
`HSFETCH` is the PRIMARY fetch, not a hedge, and is not charged (its REQUESTED does count in flight).
Commands go out on the COMMAND connection (Android `TorManager.requestHsDescriptorFetchCode` — the event
socket stays events-only; iOS `TorManager.requestHsDescriptorFetch`, whose observer passes `650`s
through to the persistent tap). Panel lines (uncoded, platform log + ConnectionLog, identical text from
`DescriptorHedge.Companion`): "descriptor fetch hedged after 1s (n/4)", "descriptor fetch re-requested
after 4s more (n/4)", "descriptor hedge not started by Tor", "descriptor hedge budget spent" (once per
session), "descriptor hedge off (control arm)" (once per session). The coded trace is Tor's own extra
`HSDESC_REQUESTED`. NO-HEDGE CONTROL (device A/B run, debug builds only — `setNoHedgeControl` refuses in
release): `WDIO_DESCRIPTOR_HEDGE=off` makes the multi-device harness pass iOS `--test-descriptor-hedge-off`
/ Android `--ez TEST_DESCRIPTOR_HEDGE_OFF true` (persisted by the debug TestHooks until the next TEST_WIPE
launch without it). Tests: `DescriptorHedgeTest`.
**HSDir pin for descriptor re-fetches (2026-10-08, no new codes):** the two worst prod connects
(Android 110 s, iOS 215 s) both had an `HS_DESC RECEIVED` from a healthy HSDir before a NEWNYM; the
post-NEWNYM re-fetch then hung on a dead HSDir again, because NEWNYM purges Tor's recently-asked-HSDir
memory (`hs_client_purge_state`). Measured from a desktop client: of the onion's 6 HSDirs that period 3
dead / NOT_FOUND, 1 slow, 2 answering in ~0.5 s — stable for the whole HS time period. The shared
`RelayDescriptorWatchdog.parseEvent` now also reduces the `HS_DESC` HsDir token (`$FP~nick` /
`$FP=nick` / `$FP`) to its strict 40-hex fingerprint plus the allowlisted `REASON=` of a FAILED, and
the per-Tor-process `HsDirLedger` (commonMain, lock-guarded, RAM only) keeps `goodHsDir` = the HSDir of
the latest RECEIVED (unless already bad) and `badHsDirs` = every FAILED HSDir (any reason) plus every
HSDir whose REQUESTED was unanswered when the hedge's SECOND re-request fired. That re-request (never
the 1 s bare hedge) first books the stall, then goes out as `HSFETCH <addr> SERVER=$<good>` when a good,
non-bad HSDir is known, else plain; a `551`/`552` to the pinned form drops the pin and retries plain at
once, charged as one more hedge `HSFETCH` (skipped if the session budget is spent). NEWNYM does NOT clear the ledger (only its pending REQUESTEDs, which Tor
cancelled); a new Tor process does (Android: per `startAttempt`; iOS: a process-wide static, tor_main
runs once). Feeds: Android's event socket (`TorControlEventReader` → `TorManager.onRelayDescriptorEvent`);
iOS's raw-650 tap feeds the ledger on Tor's queue, so the fingerprint never becomes a Swift value. The
fingerprint is SENSITIVE: written into the `SERVER=` argument only (validated `SERVER=\$[0-9A-F]{40}` on
both platforms before it reaches the authenticated socket), never logged; the only lines are the fixed,
uncoded "descriptor refetch pinned to the last good directory" / "descriptor directory pin dropped"
(`HsDirPinParitySourceTest` scans every log call site for fingerprint-bearing interpolations). First-fetch
capture: Android holds `Connected` until the event socket's SETEVENTS is live (≤ 1.5 s,
`EVENTS_SUBSCRIBE_HOLD_MS`; normally already true — it subscribes right after SOCKS detection); iOS now
carries `HS_DESC` in its FIRST SETEVENTS (`controlEventsCore`, still with `STATUS_CLIENT`) — no onion
request can exist before the SOCKS readback at `.connected`, so it adds no pre-connect event traffic.
Known limitations: before the first RECEIVED of a process there is no candidate and Tor picks (computing the
HSDir ring from `GETINFO sr/current` + the consensus is out of scope); the pin applies only to the
watchdog's re-fetch, after its 4 s window, never to Tor's own post-NEWNYM fetch. Planned later step: a
persisted "last good HSDir" (vault-scoped, expiring with the HS time period) so a fresh process can pin
its first re-fetch too.
**Several onion addresses for the same relay — the descriptor race (2026-10-23, no new codes):** cold
clients to the dev relay stalled 50–120 s in the DESCRIPTOR phase (control-port trace: `HS_DESC
REQUESTED` with no `RECEIVED` for 60–120 s at that onion's current responsible HSDirs; once `RECEIVED`,
intro + rendezvous took ~1 s), while the same cold clients reached other onions in 1–6 s. The
responsible HSDir set is derived from the onion key + SRV / time period, so a SECOND address of the
SAME relay backend lands on an independent HSDir set; the relay app is address-agnostic (capabilities
and inboxes never depend on `Host`). Config (one way only, 2026-10-23): the existing
keys take a COMMA-SEPARATED list of up to three addresses of the same relay — `relayOnionUrl=a,b,c` /
`relayDevOnionUrl=a,b,c` in `relay.properties`, `RELAY_ONION_URL` / `RELAY_DEV_ONION_URL` in the
environment; list order = slot order, entries trimmed, empty items ignored; a non-empty env var replaces
the file's WHOLE list (never mixed per entry); a single entry is exactly the old configuration. There
are no numbered keys. `generateRelayUrl` emits `RELAY_URLS_FROM_PROPERTIES` /
`RELAY_DEV_URLS_FROM_PROPERTIES` (slot 1 first, slot 1 == the unchanged scalar constant) and refuses
the build when ANY dev entry equals ANY prod entry (case-insensitive, trailing slash ignored), when a
list has more than 3 entries, or when a list of ≥ 2 entries has any entry that is not a v3 `.onion`
URL; the release scrub empties the WHOLE dev list; `scripts/verify-release-artifact.sh` greps the
artifact for every dev entry, and the maintainer-only device check probes every entry (pass = each answers; it
names entries by position only, never by address). The
`RelayConfig` actuals expose `CANDIDATE_URLS` (release-first `when{}`, gated exactly like before —
`verify-release-clean.sh` asserts the new shape) and `BASE_URL` is now the SESSION's address:
`RelayEndpoints.race.currentBaseUrl()`. The decision is the shared `RelayAddressRace` (commonMain,
process-wide — it describes Tor's descriptor cache, which a kept-warm Android daemon carries into the
next session): once per Tor HS state (Android: at `Connected` or at control-channel-up, whichever is
later, plus the warm-up's own call; iOS: right BEFORE `.connected` is published — `HS_DESC` is in the
first SETEVENTS; both: again after every accepted app-fired NEWNYM, and Android per Tor child) one bare
`HSFETCH <addr>` per address goes out at once on the COMMAND connection. Both platforms parse every
`HS_DESC` against all addresses (`RelayAddressRace.parseDescriptorEvent` → `RelayDescriptorWatchdog.
parseEvent(line, list)`, only the slot INDEX leaves it); the FIRST `RECEIVED` of the race wins and its
URL becomes `BASE_URL`; a `FAILED` of one address never ends the race. The winner is STICKY across a
NEWNYM / new Tor process until the re-race decides (never back to a slower slot 1 meanwhile). A winner
CHANGE calls the session's hook (`RunViewModel` / `IosAppController` bind
`MessageManager.noteRelayAddressSwitched`): the probe / batch peek in flight is queued on the loser's
descriptor, so it is aborted and re-run at once exactly like the NEWNYM abort below (unbooked; panel
"probe #N: abandoned for a faster relay address in X s - re-probing", uncoded). `MessageManager`
resolves its captured base URL at USE time (`RelayEndpoints.resolve`), so an instance built before the
race decided follows the winner; push registration, bug reports, debug mode and telemetry read
`BASE_URL` at use time too. The pre-unlock warm-up waits for a BEGUN race (≤
`RelayAddressRace.WARMUP_WAIT_MAX_MS` = 15 s, inside its own 25 s attempt budget; the GET keeps ≥
`RACE_MIN_GET_SECONDS` = 10 s), then sends its one `GET /` to the winner — so the full-budget
classification is unchanged; a race that was never begun (no control channel) is never waited for.
THE HEDGE ACROSS ADDRESSES: one `DescriptorHedge` per session as before — the budget of 4 is NOT
multiplied by the address count. While a race is open, the hedge sees the addresses as ONE logical
descriptor (every racing REQUESTED counts in flight; the first RECEIVED of any address closes the
episode), so with ≥ 2 addresses the racing fetches already fill `HSDESC_MAX_IN_FLIGHT` = 2 and the 1 s
hedge is deferred until they are presumed dead at 4 s — the race IS the early overlap. Each hedge then
targets the next address not `FAILED` in this race, round robin in slot order
(`RelayAddressRace.hedgeTargetSlot`); the SECOND stage pins via THAT address's own ledger
(`HsDirLedgerSet`, one `HsDirLedger` per address — each has its own HSDir set). Once decided, only the
winner is hedged, a loser's later REQUESTED is not fed to the hedge (it is not the relay's descriptor
miss) and a loser's outcome is fed only to retire a request the hedge counted. The 10 s descriptor-stage
NEWNYM therefore fires only when NO address produced a descriptor. The race's own HSFETCHes are primary
fetches, not hedges, and are not charged. `HsCircuitWatchdog` matches circuits / streams to ANY
address. Panel lines (uncoded, platform log + ConnectionLog, identical text from
`RelayAddressRace.Companion`): "descriptor race started (N addresses)", "descriptor race won by address
K of N" — the address count and slot number only, never an address. ONE ADDRESS = TODAY, EXACTLY: no
race, no extra HSFETCH (Android's warm-up keeps its single `HSFETCH` of slot 1), every event feeds the
hedge, `BASE_URL` = slot 1, no wait. Tests: `RelayAddressRaceTest`, `RelayUrlListGenerationTest` (on the
compiled constants), `RelayAddressSwitchTest`, `RelayAddressRaceParitySourceTest`. Follow-up (NOT done,
needs the relay first): a coded "winning slot" for the connect telemetry — the relay's
`/telemetry/connect` allowlist rejects a whole report with an unknown code, so the allowlist must ship
before any app sends it.
**Rendezvous hedge + session SOCKS isolation class (2026-10-25, no new codes yet):** with the
descriptor race the descriptor phase is ~1 s; the slow tail of a first connect is the RENDEZVOUS (prod
1.6.48: iOS 20 s = two `REND_CIRC_FAILED`, `REND_JOINED` ~15 s after `HSDESC_RECEIVED`; Android 15 s =
`INTRO_DONE` 5 s, `REND_JOINED` 15 s). `RendezvousHedge.decide` (commonMain, pure): while a COLD probe
attempt is in flight on a transport that can isolate, `RendezvousHedge.HEDGE_DELAY_MS` (3 s) after the
LATER of the first cold probe start and the session address's `HS_DESC RECEIVED`
(`RelayAddressRace.descriptorReceivedAtMs`, cleared with Tor's HS state), `MessageManager` sends ONE
extra bare `GET /` under a fresh CSPRNG SOCKS5 username (RFC 1929, password `SocksIsolation.PASSWORD`;
method 0x02 ONLY) — Tor's default `IsolateSOCKSAuth` (neither torrc disables it) builds an independent
intro + rendezvous pair for it. First answer wins. **The winner's credential becomes the process's
class** (`SocksIsolation.adopt`) because Tor never attaches a stream to a circuit of another
isolation class, rendezvous circuits included — measured on a Mac Tor 0.4.9 client: after an auth-X
GET joined rend 14, a NO-AUTH GET built rend 16 + intro 17, auth-X again reused 14, no-auth again
reused 16. So every Tor-proxied request (session, push, telemetry, bug report, the next warm-up) reads
`SocksIsolation.current()` per request, like `SocksPortRedirect`; null = today's handshake byte for
byte. Sticky until a new Tor process (`SocksIsolation.reset`, Android `TorManager.startAttempt`; iOS
`tor_main` dies only with the process). A hedge win hands its real answer to the blocked probe attempt
(booked `PROBE_OK`, phrase suffix `(rendezvous hedge)`), then bumps the NEWNYM-abort epoch and aborts the
opted-in requests so a parked `POST /peek` re-sends at once under the new class. Bounds: ≤ 1 per
`MessageManager`, never once the transport answered, never after an accepted NEWNYM (the in-flight
hedge opts into the NEWNYM abort), never without a known descriptor, never on the external-proxy or
direct transports (`RelayHttp.supportsSocksIsolation`; SwiftTorHttp also ignores any credential in
external mode). Android does the handshake itself (`Socks5IsolatedSocket` behind `Proxy.NO_PROXY` +
`OnionLoopbackDns`, which resolves nothing and keeps ATYP DOMAINNAME) because java.net's SOCKS client
only takes credentials from the global `Authenticator`; iOS adds method 0x02 to SwiftTorHttp. The
credential never leaves the loopback and is never logged; the hedge lines are uncoded fixed phrases.
A/B: `WDIO_REND_HEDGE=off` (debug-only control arm, phrase `rendezvous hedge off (control arm)`).
Telemetry codes `REND_HEDGE_FIRED` / `REND_HEDGE_WON` need the relay allowlist FIRST.

**NEWNYM aborts the in-flight probe (2026-10-08, no new codes):** after ANY app-fired `SIGNAL NEWNYM`
Tor accepted (`250`; both TorManagers call one hook, so every rung is covered), the session owner calls
`MessageManager.noteNewCircuitRequested`: requests opted in with `cancelOnNewCircuit` — ONLY the health
probe `GET /` and the unread prime's batch `POST /peek` (read-only) — are aborted (Android OkHttp
`Call.cancel()`; iOS `SwiftTorHttp.cancelNewCircuitSensitive` cancels the NWConnection) and an epoch is
bumped. A probe attempt that started under the old epoch and got no answer is
`ProbeAttemptOutcome.ABANDONED_BY_NEWNYM`: no bookkeeping (not a timeout, not a fast failure — the
NEWNYM rungs' evidence is untouched), uncoded panel line "probe #N: abandoned after NEWNYM in X s -
re-probing", re-run at once without consuming one of the `RELAY_HEALTH_ATTEMPTS` (≤ 2 extra per call);
a NEWNYM no booked attempt has started after yet gives `relayHealthDelayMs` one fast (1–2 s) cycle even
warm, without spending a cold credit. An abandoned batch peek is re-sent once (Failed would drop the
prime onto the slow pre-batch path). Never aborted: sends, mints, cap rotations, push (un)registration
(a failed push-toggle registration is reverted in the UI). Known limitation: a NEWNYM fired while the health
loop is SLEEPING (no probe in flight) waits out that sleep (≤ 12 s warm).
**Hung onion-circuit rung (2026-10-08, no new codes):** evidence — prod Android connects 1 + 7 and
one iOS device run (cycle 4) had descriptor received, rendezvous circuit built, `introduction circuit launched`
and NEVER `built` for 22–30 s (healthy intro circuits build in 0.4–1.0 s on every device measured);
the only rescue was the warm-up's 25 s budget → NEWNYM or the 40 s cold rung, after which a fresh intro
circuit built in 0.5 s. Mirror (another iOS device, cycle 9): `introduction complete`, no `rendezvous joined`
for 26 s (that rendezvous circuit later `failed: TIMEOUT`). The shared `HsCircuitWatchdog` (commonMain,
lock-guarded, per Tor process; `HsCircuitWatchdogTest`) reads `CIRC` / `CIRC_MINOR`: an
`HS_CLIENT_INTRO` **or `HS_CLIENT_REND`** circuit seen LAUNCHED / EXTENDED / CANNIBALIZED and not
BUILT (for rendezvous: nor `HSCR_ESTABLISHED_*`) within `HS_CIRCUIT_BUILD_STALL_MS` (6 s) — rev b, after
an iOS device run, cycle 3 (17.9 s): intro built in 0.4 s, the RENDEZVOUS circuit launched and never built for
23 s; Tor cannot send INTRODUCE1 without the rendezvous cookie, so `introduction sent` never came and the
join rule never armed (both kinds stall in the build phase; the prod cases were the intro side) — or an
intro `HSCI_DONE` (after `HSCI_INTRO_SENT`) with no
`HSCR_JOINED` within `HS_REND_JOIN_STALL_MS` (8 s), gets `CLOSECIRCUIT <id>` on the COMMAND connection
(build rule: that circuit; join rule: the rendezvous circuit in `HSCR_ESTABLISHED_WAITING`, else the
newest one; one circuit is never closed twice in one decision, and the rendezvous build case reuses the
"rendezvous circuit stalled" phrase). Tor's retry circuit is a new id with its own 6 s clock. Only before the session's
first relay answer (after it, tracking is dropped and the post-answer ladder owns stalls); ≤ 3 closes
per Tor process (`MAX_CLOSES_PER_TOR`, the first refused one logs "circuit close budget spent" once) — renewed ONCE by the guard-channel kick, which starts a new channel epoch (2026-10-13, A20e: the
post-kick rendezvous never built while the budget was spent; uncoded "circuit close budget renewed after network
reopen"; bounded at 2 × `MAX_CLOSES_PER_TOR` since `CHANNEL_KICK_MAX_PER_TOR` = 1);
never within 2 s of an accepted NEWNYM (which killed every circuit — the NEWNYM hook also clears the
tracking); Tor's `552 Unknown circuit` = already gone, never retried. **Why `CLOSECIRCUIT` and not
NEWNYM:** closing the one hung circuit makes Tor's own HS client logic retry it — the next introduction
point or a fresh rendezvous point — while the descriptor, every other circuit and the identity stay put;
it spends none of the NEWNYM budgets, and the NEWNYM rungs remain the backstop. Our-onion matching: Tor
adds `REND_QUERY=<onion>` only once the circuit has its HS identity (not on LAUNCHED); a circuit naming
another service is dropped, one without REND_QUERY yet is accepted (pre-first-answer the app dials no
other onion); the address is compared, never copied out. Identifiers: the circuit id lives only in
`HsCircuitWatchdog.Closure` (validated 1–10 digits on both platforms before the authenticated socket)
and is never logged; the only lines are the fixed, uncoded "introduction circuit stalled - closing it
so Tor retries" / "rendezvous circuit stalled - closing it so Tor retries" / "circuit close budget
spent" (the relay allowlist has no generic slot, so no telemetry code; `HsCircuitRungParitySourceTest`
scans the log call sites). Feeds: Android's event socket (`TorControlEventReader.onControlEvent` →
`TorManager.onHsCircuitEvent`, subscribed before `Connected` — see the HSDir pin); iOS's raw-650 tap
(`TorManager.hsCircuitWatchdog`, a process-wide static). Known limitation (iOS): `CIRC`/`CIRC_MINOR` are in the
FULL event set armed at `.connected` (chatty pre-connect GENERAL circuits would disturb the vendored
controller's GETINFO observers), so an HS circuit launched in the few ms before that SETEVENTS is applied
is not seen; intro / rendezvous circuits are launched only after the descriptor fetch (≥ 0.5 s later), so
in practice none is missed.
**Bootstrap-stall rung (2026-10-06, codes `TOR_BOOT_KICK` / `TOR_BOOT_KICK_SKIP` — 71 codes):** a
bootstrap whose percent stands still for `TorBootstrapStall.STALL_MS` (20 s) inside the ladder
(5 % ≤ p < 100 %) gets `SETCONF DisableNetwork=1` + `SETCONF DisableNetwork=0` on the COMMAND connection (Android
`TorManager.kickStalledBootstrap`: both lines in ONE write under `controlMutex`; iOS
`TorManager.kickStalledBootstrap`: two sequential `sendCommand`s from one main-actor turn, each with a
single-reply handler — TORController may hand them each other's reply, so ANY refused reply triggers
one idempotent `DisableNetwork=0` retry). Shared
decision `TorBootstrapStall.msUntilKick` (commonMain, `TorBootstrapStallTest`): highest percent
only (a lower re-report is not progress), clock from the later of the last increase and the last
kick, ≤ `MAX_KICKS` = 2 per Tor process (Android: per start attempt), never within
`NEWNYM_SPACING_MS` (10 s) of a NEWNYM written to that Tor (both `requestNewCircuit`s stamp it). A
skip (channel down, write failed, first SETCONF refused) costs no budget and is not retried until
the percent moves. Progress feeds: iOS the `STATUS_CLIENT BOOTSTRAP` observer; Android the NOTICE
tail (every 5th percent) AND the event socket via `TorBootstrapStall.progressFromControlEvent`
(PROGRESS integer only). Tor semantics (0.4.9 source): Tor runs every complete control line of one
read in order (on iOS the two writes may land one main-loop turn apart — the network is then
disabled for that turn, harmless);
`connection_mark_all_noncontrol_connections` closes OR channels (an OPEN one normally — no guard
blame), directory connections and streams; an unfinished directory fetch goes through
`connection_dir_client_request_failed` — the SAME path as Tor's 5-min stall reaper — so its dir
guard is noted failed (prop271 primary retry 10 min; the sample is untouched) and the fetch is
relaunched; consensus, microdescriptors, state and the monotone bootstrap percent are kept. **The
SOCKS listener is closed and `SocksPort auto` re-binds on a NEW port**, so: no kick once the port
has been handed out (Android: after `Connected` is published, both serialised under
`bootStallLock`; iOS: after `readBackSocksPort` starts — iOS reads the port only at
CIRCUIT_ESTABLISHED, after any kick, and Tor answers commands in order); Android holds `Connected`
while a kick's move is pending and adopts the port from Tor's NEW `Socks listener listening on port`
notice line (one at or past the log length captured before the write) — the old port is never handed
out again, and a lost line fails closed into the unchanged 90 s / 100 s ladder. Panel phrases (built
in `TorBootstrapStall`, identical on both): "bootstrap stalled 20 s at NN% - network re-kicked
(n/2)" and "bootstrap stalled 20 s at NN% - network re-kick unavailable". **Relay first:** the
relay allowlist must carry both codes before a client emitting them ships.
**Network-restore kick (2026-10-25, uncoded — no telemetry change):** the phone's default network
coming back (Android `ConnectivityManager.registerDefaultNetworkCallback` in `RunViewModel`,
unregistered in `onCleared`, needs `ACCESS_NETWORK_STATE`; iOS `NWPathMonitor` in `AppState`,
process-lifetime) drives ONE `DisableNetwork=1`/`=0` toggle through the existing paths, chosen by state
(`TorManager.kickForNetworkRestore` on both: Connected → the guard-channel kick body with its SOCKS-move
follow-up and new-circuit abort; bootstrapping before the port hand-out → the bootstrap re-kick's
commands, progress clock restarted). It spends neither rung's budget and bypasses their gates
(before-first-answer, one-per-process, `MAX_KICKS`), which stay unchanged for their own callers.
Shared decision `NetworkRestoreKick` (commonMain, `NetworkRestoreKickTest`): the first observation is
the baseline (the registration's own initial callback never kicks; a no-network baseline is an
observed loss), a restore = usable network after an observed loss or a switch to a different default
network, 2 s debounce, 15 s own minimum interval (a restore inside it is deferred, never dropped),
nothing on a loss. Embedded Tor only (external proxy / direct → skipped). After the toggle: the stall
watch is re-armed from the restore (Android: full first window; iOS: the miss-streak run reset,
`.stalled` → `.connecting`, never `.relaunchRequired`) and the push opt-out ladder's backoff ends early.
Phrases (identical on both): "network restored: tor kick sent", "network lost: waiting for it to
return", "network restore: skipped (<reason>)" with a closed reason list, "network restore: kick
deferred N s (rate limit)". The network key (Android network handle / iOS interface) is equality-only
and never logged. Tor semantics (0.4.9 / main source): the toggle closes every non-control connection
(no guard blame while `DisableNetwork` is set) and re-binds the listeners, but does NOT clear a guard's
`GUARD_REACHABLE_NO` — primaries marked down during the outage are retried on Tor's own 10-minute
primary schedule (`get_retry_schedule`); recovery before that depends on Tor building through a
non-primary guard. Measured 2026-10-25 (an Android phone, Case A): kick 8 s after the restore, relay DELETE
~2m20s after it (was ~10 min). The 4-pass opt-out ladder had given up before that, so a ladder that
has seen the restore epoch move keeps retrying past its normal passes (15 s backoff, 25 s per pass)
until 240 s after the restore, at most 12 passes in all (`PushRegistration.continueDeregLadder`,
`DEREG_RESTORE_GRACE_MS`, both platforms); those retries log "push dereg retry N (after network
restore)".
300-line RAM ring, `clear()` on lock and wipe on both platforms, never written to LogBuffer,
logcat, os_log or the bug report. Since 2026-09-14 one narrow egress exists: the connect-telemetry `log` field ships
the `Line.code` of the lines in the connect window — the CODES only, never `Line.text`, and only
inside that report, which since 2026-11-03 is sent only with Debug mode on (see "Connect-time
telemetry" below). The contact list stays hidden
(`contact_list_hidden_until_connected`) until the relay's first answer AND the unread prime has
settled (`REVEAL`). Since 2026-09-15 the prime settles on its **first per-contact result**
(`GroupManager.primeUnreadCounts`' `onContactUnread` — the visible list is already correct and
the peeks still in flight update their own rows in place), or when a pass that emitted nothing
ends (no contacts, no session, every peek failed, move-frozen), or when the **3 s** backstop
(was 10 s) counted from the first relay answer runs out — the only case that emits `PRIME_CAP`.
The rules are one shared pure object, `ConnectReveal` in commonMain
(`ConnectReveal.primeSettle` / `ConnectReveal.contactsReady`, `UNREAD_PRIME_REVEAL_CAP_MS`),
driven by `RunViewModel.settleUnreadPrime` and `AppState.settleUnreadPrime`, so neither the
semantics nor the panel phrases can drift between platforms. The displayed percent is
`BootstrapProgressPacer` (monotone, geometric creep, 100 only on a real answer).

### Relay-advertised client version (`ios-version` / `android-version` response headers, 2026-08-26)

The relay may append two optional response headers to EVERY main-server HTTP response (including
its default `GET /` 404 — the first request of every session — and every rejection path; never on
the admin port): `ios-version` and `android-version`, each strictly `MAJOR.MINOR.PATCH` with 1–4
ASCII digits per component and ≤ 14 chars total (the relay refuses to START on anything else, so
a typo cannot masquerade as "not configured"). They are the only relay→client channel that is
not a message blob, and they cross a trust boundary — the relay is untrusted — so the client
holds these rules (`UpdateCheck.kt`, `UpdateNudge.kt`, the `MessageManager` transport wrapper):

- **The client never sends its own version.** Nothing about the local build is added to any
  request; the compare is local. Platform is not newly inferable (both headers go to everyone).
- **Allowlisted in the platform actuals, never in commonMain.** Android reads ONLY
  `android-version`, iOS ONLY `ios-version` (both the SOCKS bridge path and the NSURLSession
  simulator path), and both surface it under the single normalised key `app-version` in
  `HttpResult.headers`, capped at 14 chars; the full relay header set never transits the Swift
  bridge (`HttpBridgeResult.appVersionHeader` is one nullable string).
- **Read once per `MessageManager` instance**, from the first `code > 0` response on ANY endpoint
  (the health probe, the unread prime `/peek` and the warm-gate race on the same transport —
  nothing orders them), via the private `RelayHttp` observer wrapper; later responses cannot
  change it. Exposed as `newerRelayVersion(): String?` (a `@Volatile` getter — no coroutines type
  is exported to Swift), polled by the existing 8–12 s relay health loops on both platforms.
- **Strict parse, upgrade-only, fail-closed.** `parseAppVersion` is a manual range-check walk
  (no regex on relay input — the K/N stack-safety rule; and never `toIntOrNull`, which accepts
  Unicode digits and `+`). `isNewerVersion` returns the remote only when BOTH sides parse and
  remote > local; any ambiguity (including an unparseable LOCAL version) means no nudge.
- **What may reach UI or vault is the re-rendered parsed triple, never the raw header.** The
  modal copy is fixed ("New version available" — no version number in the UI); the store destination is hardcoded
  (`market://details?id=com.vg.run` gated on a `com.android.vending` installer with NO https
  browser fallback; `https://apps.apple.com/app/id6762006510` gated on a present, positive
  `receipt` file). Header values are never logged — an `HttpResult` must never be interpolated
  into a log line now that its `toString()` carries the map.
- **Throttle = vault singleton `_meta` key `update_nudge_v1` = `"<maj>.<min>.<pat>|<epochDay>"`**
  (SQLCipher on both platforms — no Keychain, no journal), written ON SHOW from the UI/VM path
  (never the HTTP thread), never-throws like `consumePushPromptOnce`. Re-arms only on a new UTC
  day or an advertised version STRICTLY higher than the stored one (monotonic). Matched by no
  residue predicate (pinned in `MetaResiduePurgeTest`) — a contact/group delete must not reset it.
- **Trade-offs (2026-08-26):** a hostile relay can (a)
  make the modal appear at a moment of its choosing and thereby time a user-initiated store
  egress (the button is labelled "Open Google Play" / "Open App Store" so the egress is named),
  (b) re-nag once per session by climbing the advertised version, (c) leave ≤ ~40 bits of
  relay-chosen version digits in the `_meta` throttle value of a targeted vault. It cannot inject
  text, choose the destination, or make the client emit anything on its own. The RAM mirror of
  the version (`showUpdateNudge`) is scrubbed in `clearInMemoryIdentifierMaps()` / `AppState.lock()`.
  Suppressing the header (keeping users on an old build) is a known limitation with no regression — the
  copy must never promise the app will always announce updates.

### iOS bounded Tor keep-alive after backgrounding (2026-10-23)

**Lifecycle before:** every `.background` locked the vault, `TorManager.stop()` latched
`relaunchRequired`, and ContentView `exit(0)`ed while invisible — so every open was a cold Tor
(fresh descriptor fetch + intro/rendezvous; prod 1.6.47: almost all connect time AFTER bootstrap),
and a user who re-tapped the icon inside the ~1.3–1.5 s before that exit foregrounded the dying
process, which vanished (`RBSProcessExitContext` "voluntary", no crash report — the "crashes every
other launch" report).

**Lifecycle now** (`AppState` "Bounded Tor keep-alive", decisions in commonMain
`BackgroundTorKeepAlive`, unit-pinned by `BackgroundTorKeepAliveTest`, glue pinned by
`IosTorKeepAliveSourceTest`):
- On `.background` the vault lock + key wipe + every RAM scrub run EXACTLY as before (lock(),
  the notification sweep, `pendingMoveHandle = nil`, the debug lock batch). Only the Tor
  teardown and the `exit(0)` are deferred, and only when the gate passes (evaluated FIRST, before
  the lock — the tier read needs the device key the lock wipes): not a wipe, not
  `relaunchRequired`, not external proxy mode, Tor `.connected`, not an UNLOCKED session that never
  reached the relay (leave-and-return stays the restart remedy for a wedged connect), no device
  lock under way (`protectedDataWillBecomeUnavailable` seen, no did-become-available since — it
  can precede `.background` on a power-button lock, so the observers are permanent, installed in
  `AppState.init`), tier not MAXIMUM/Damaged (Unreadable → the session's authenticated read at
  unlock). Pre-unlock (speculative Tor at the PIN screen) is kept too.
- **The window** is the background-task budget the OS actually grants: `beginBackgroundTask`,
  then `backgroundTimeRemaining − 3 s`, clamped to [5 s, 170 s] (`windowSeconds`; an
  unknown/`DBL_MAX` read is re-read 1 s later up to 3×, then the cap). The task's expiration
  handler is the hard backstop; `protectedDataWillBecomeUnavailable` (device lock) ends the window
  at once — the Tor dir is `NSFileProtectionComplete`, whose keys go ~10 s after that notification.
  No task granted (`.invalid`) ⇒ the old immediate path. The panel/debug log gets ONE uncoded line,
  numbers only: `tor keep-alive window N s (background budget M s)`.
- **The exit race is closed on the main actor with one flag.** Every deadline source carries the
  token of the arm it belongs to; `foreground()` (scene `.active`) invalidates every token; a
  deadline is honoured only while `applicationState == .background` at that instant (`.inactive`
  = the user is coming back). Honoured ⇒ `TorManager.stop()` (the ordinary state-preserving
  teardown, which BLOCKS the main thread ≤ 2 s), then ONE main-runloop turn later
  (`finishTorKeepAliveTeardown`) `exit(0)` only if `exitStillAllowed`: no
  `.active` reached the keeper since the teardown began AND the app is background on that turn.
  A process brought forward during `stop()` does NOT exit; Tor is gone, so `relaunchRequired`
  shows close-and-reopen and the next background recycles at once.
- **Absolute residue cap.** The per-stretch window re-arms on every
  `.background`, so on its own a user tapping back inside each window could keep a process alive
  indefinitely. `RESIDUE_CAP_SEC` = 170 s is measured from the `lock()` that ended the LAST
  UNLOCKED session (`AppState.lastUnlockedSessionLockUptime`; this backgrounding's own lock when the
  vault is open at `.background`; a new unlock moves it on its next lock). At arm the cap left is
  fixed as a deadline; the scheduled window is `min(budget window, cap left now)`
  (`composeWindow`), and with ≤ 5 s (the floor) left the keep-alive refuses and today's immediate
  `stop()` + `exit(0)` runs. A process that never held an unlocked session is bounded per stretch
  only (no unlocked-session residue to bound).
- **Background unlock.** An Argon2 unlock finishing after the user left now lands in
  a process that may survive. `relockIfUnlockedInBackground` locks at once — at the end of
  `unlock()` and `recoverWithCode()` (`.background` only, never `.inactive`: Lever B's Face ID
  prompt is `.inactive`), at every keep-alive deadline (background-gated, before the decision), and
  on a warm return (`endTorKeepAliveOnForeground`, only when Tor was really kept, before adoption).
  ContentView's `.onChange(isUnlocked)` re-lock remains as the second guard.
- **Warm return** (`.active` inside the window): timer/observer/task ended, then
  `adoptKeptTor` — ring cleared, `TOR_REUSED` "reused warm Tor from the previous session" (Android's
  phrase and code) as the timeline anchor, then a NEW SESSION in the same process
  (`beginWarmTorSession`: connect anchor + report latch + reveal latch re-armed, `tor` = 0, `boot`
  omitted, relay-answered latch / early-NEWNYM budget / once-per-session nudges reset). Nothing is
  started: `speculativeTorStarted` stays latched and `TorManager.start()` refuses on `started`, so
  no second `tor_main` is ever attempted; the unlock reaches the live port through
  `startTorOrDirect`'s existing control-confirmed "Tor already up" branch, whose first health probe
  is immediate (stale circuits after the background are the NEWNYM rungs' job). The pre-unlock
  warm-up `GET /` runs again (no HSFETCH). The descriptor race is re-run only if the current Tor
  HS state never decided it (`RelayAddressRace.decidedThisState`); a decided race keeps its cached
  descriptor. The `DescriptorHedge`, `HsCircuitWatchdog`, `HsDirLedger` and the warm-NEWNYM hourly
  cap carry over with the daemon (Android does the same for its adopted Tor).
- **DEBUG measurement mode (2026-10-24, `--test-tor-keepalive-unbounded`, compiled out of
  release — the argument is read inside RunApp's `#if DEBUG`, the static switch and the
  `tor_suspend_probe` element exist only in DEBUG).** The keep-alive bypasses the residue cap and
  the tier gate and never tears down on the window / expiration deadline (the expiration handler
  still ends the task), so the process SUSPENDS with Tor kept; a device lock still tears down, and
  wipe / relaunchRequired / external proxy / not-Connected / wedged still refuse. Every warm return
  runs `AppState.runTorSuspendProbe`: backgrounded seconds, tor_main thread running, an
  authenticated control-port `GETINFO net/listeners/socks` round trip (ok + ms), a SOCKS5 greeting,
  and later the first relay answer (s after return / after unlock) — as uncoded "tor suspend
  probe: …" panel lines and a fixed-key accessibility value. It never changes the outcome: a dead
  Tor is latched by the unlock's own control confirmation as for any user. Driven by
  a maintainer-only device check (not published).
- **Residue, stated plainly:** while kept, the process holds a LOCKED app — no
  vault handle, no SQLCipher key, no Tink/CryptoProvider key, no `MessageManager`, no
  capability, the id maps scrubbed — plus the live Tor daemon (guards, consensus, the relay's
  onion descriptor and circuits, the control cookie in RAM) and whatever FREED heap the unlocked
  session left behind. That freed-heap residue is what `exit(0)` used to clear immediately; it
  is kept INVISIBLE (backgrounded) only until 170 s after that session's lock — wall clock, across
  any number of warm returns (the absolute cap above; ~27 s per background stretch today) — and
  never past a device lock (`protectedDataWillBecomeUnavailable` ends it at once). Time the user
  spends back in the FOREGROUND on the PIN screen after a warm return is not bounded by the cap
  (the app is visible and in use), but the first background after the cap has run out exits at
  once, as before 2026-10-23. MAXIMUM never keeps. Wipes never keep.

### Connect-time telemetry: four anonymous numbers + a coded timeline, once per session, Debug mode only (2026-09-11, `log` 2026-09-14, `reveal` 2026-09-15, consent gate 2026-11-03)

The ONE thing this app ever tells the relay about itself — and since 2026-11-03 **only while the
user's Debug mode consent is on** (`DebugMode.isEnabled`, the same opt-in that gates the debug-log
upload; its consent text "send anonymous diagnostic logs to the relay" covers this report). A
default install sends nothing about itself. `ConnectTelemetry.send` takes a required
`debugModeEnabled` provider (Android: the ViewModel's `_debugMode` flow; iOS: AppState's `debugMode`
gate plus `IosAppController.isDebugModeEnabled` as the Kotlin belt), reads it BEFORE the jitter (an
opted-out session skips the sleep) and AGAIN after it (consent revoked mid-window = no report;
consent is not retroactive), and treats a throwing provider as off. The once-per-session latch is
set regardless, so consent granted later in a session reports from the NEXT session. Before that
date the report went out on every connect of every install; the wire format is unchanged. On the
FIRST relay answer of a session the client `POST`s `{relayBaseUrl}/telemetry/connect`,
`Content-Type: application/json`, body (fixed key order)
`{"v":1,"platform":"android"|"ios","app":"<versionName>","secs":<int>[,"tor":<int>][,"boot":<int>][,"reveal":<int>][,"log":[[<offsetSeconds>,"<CODE>"],…]]}`.
The relay answers `204`; any other response (the emulator/simulator mock relay answers `404`) and any
transport error is ignored. `ConnectTelemetry.kt` (commonMain) holds the pure parts; `bucketSeconds`,
`bucketTorSeconds`, `bucketBootSeconds`, `revealSecondsFor`, `offsetSeconds`, `timelineWindow`,
`timelineEntries`, `reduceTimeline`, `renderTimeline`, `timelineField` and `payload` are unit-pinned
byte-for-byte by `ConnectTelemetryTest` (72 tests).

- **`secs` vs `tor` vs `boot` — three numbers, two anchors.** `secs` is the whole reported wait,
  from the POST-UNLOCK connect anchor to the first relay answer. `tor` shares that SAME anchor —
  it is the portion of `secs` spent waiting on Tor, capped at `secs`, so the relay derives the
  onion-rendezvous phase as `secs - tor` with no risk of a negative. `boot` shares NEITHER
  anchor: it is timed from this session's Tor PROCESS start (app launch / the speculative
  pre-unlock start — see lever 2 below), which on a fast unlock usually runs well *before*
  `secs`'s clock even starts, so `boot` routinely exceeds `secs` and is never capped against it.
  The relay derives nothing from `boot` — it is not combined with `secs` or `tor` server-side,
  it exists purely so the two connect-speed levers (pre-unlock warm-up vs. speculative start) can
  be judged against the ACTUAL bootstrap cost rather than only the post-unlock remainder. Omitted,
  never a sentinel, whenever this session never started Tor (Tor not required, or the debug/direct
  path) or Tor never reached Connected.

- **The `tor` PHASE SPLIT (lever 5).** `tor` is the same 5 s bucketing applied to the time from
  the SAME connect anchor to the moment Tor reported Connected / its SOCKS listener up, so
  **the relay derives the onion-rendezvous phase as `secs - tor`** — the phase the pre-unlock
  warm-up below targets, versus the bootstrap the speculative/at-launch Tor start targets.
  Three rules: its floor is **0**, not 5 (`bucketTorSeconds`; `tor == 0` means Tor was ALREADY
  up when the clock started — the speculative start paying for itself, which is a real and
  common outcome, not a sub-floor artefact); it is **capped at `secs`** so the derived
  rendezvous can never be negative out of two numbers that share one anchor; and it is
  **OMITTED entirely**, never a `null`/`-1` sentinel, when the session cannot measure it (the
  debug/direct path has no Tor at all). Android records it in `RunViewModel`'s Tor monitor on
  the FIRST `Connected` of the session, set-once like the anchor itself.

- **The `reveal` FIELD (2026-09-15).** `secs` stops at the first relay answer, but the
  contact list appears only once the relay has answered AND the connect-time unread prime has
  settled (first per-contact result, or a 3 s backstop since 2026-09-15 — 10 s when this was first
  measured) — in 39/48 Android and 44/45 iOS measured timelines the prime had NOT
  finished at the first answer, so `secs` stopped several seconds before the user saw anything.
  `reveal` is the SAME anchor as `secs` carried to the frame the list actually appeared in, 5 s
  bucketed like `secs` and **floored at `secs`** (the mirror of `tor`'s cap: the relay derives the
  reveal gate as `reveal - secs` and it can never be negative). Set by the platforms through
  the platforms at the SAME site that emits the `REVEAL` panel line (Android
  `RunViewModel.armRevealMark`, iOS `AppState.markRevealIfNeeded`), set-once with the SAME scope
  as the platform's connect anchor and report latch, and read by `send` AFTER the jitter delay —
  the same late-read design as `log`. iOS (anchor + report latch on the process-wide `AppState`)
  uses `ConnectTelemetry.markRevealed`, a process latch read by `send`'s default provider; since
  the iOS bounded keep-alive (2026-10-23) a warm return re-arms the anchor + report latch AND this
  latch together (`AppState.beginWarmTorSession` → `ConnectTelemetry.startNewRevealSession`), so
  it stays scoped exactly like the anchor (the previous session's report cannot still be sleeping
  in its jitter then: `lock()` cancelled it at `.background`). **Android
  must not** (fixed 2026-10-23): its anchor and report latch are `RunViewModel` fields, i.e. per
  SESSION, and a surviving process — always with the bounded Tor keep-alive, often without it —
  sends a second session's report, which used to carry the FIRST session's reveal measured
  against the first session's anchor (read as `secs` after a fast first session — the floor — or as
  the first session's slow reveal). Android now keeps `revealElapsedMsThisSession` (set through
  the shared `ConnectTelemetry.latchedReveal`: first non-negative value wins) and passes it as
  `send(revealElapsedMs = …)`. Read Android `reveal` from before this fix as unreliable for any
  report that was not its process's first. **OMITTED**, never a sentinel, when
  the list had not appeared by then, and nothing ever waits for it: absence is itself the honest
  statement that the reveal outlived the report's 2–8 s jitter (relay-side: the reveal histograms'
  `_count` is therefore smaller than the total's, and the shortfall is the signal — never read them
  as a sample of all connects).

- **The `log` CODED TIMELINE (2026-09-14, a deliberate product decision after a privacy review whose
  linkage concerns were weighed and accepted).** Sent on EVERY connect — never gated on
  slowness — silently, with no user-facing text of any kind (no string, no store copy, no
  privacy-policy change was made for it). It answers *where* a slow connect went, which the
  three numbers cannot. Entries are `[offsetSeconds, CODE]` where CODE is a
  `ConnectionLog.Code` enum NAME verbatim — a CLOSED vocabulary the relay allowlists, so an
  unknown token is a relay-side reject rather than a new channel. Rules:
  - **Codes only, never text.** Eligibility is `Line.code != null`; `ConnectTelemetry` never
    reads `Line.text`, so the panel's prose (including Tor's own SUMMARY/WARNING wording) is
    structurally incapable of reaching the wire. Pinned by
    `timelineField_neverCarriesLineTextOnlyTheCodeName`, which feeds an onion host and a relay
    fingerprint into `Line.text` and asserts neither survives into the body.
  - **Anchor + window.** Anchor = the first buffered line coded `TOR_START` or `TOR_REUSED` (a
    warm Android session's start marker, 2026-10-23 — so a self-heal restart's later `TOR_START`
    cannot cut the warm session's opening off), else the first
    coded line (the 300-line ring can evict the start, and the debug/direct path has no Tor);
    the window ends at and INCLUDES the first `FIRST_ROUNDTRIP` at or after the anchor — and,
    since 2026-09-15, continues to the first `REVEAL` at or after THAT when one has already been
    buffered, because the user's wait ends at the contact list, not at the answer (the lines
    between the two — `PRIME_PASS`, `PRIME_CAP` — are the phase the `reveal` field measures). The extension is
    CONDITIONAL, never a wait: no `REVEAL` in the snapshot ⇒ the window closes at
    `FIRST_ROUNDTRIP` exactly as before. Everything after that (self-heal, `NEWNYM`, later
    probes, the lock, a second connect's lines after an in-process re-auth unlock) is out of
    scope.
  - **Offsets** are seconds from the ANCHOR LINE'S OWN `Line.timestamp` (both ends read the same
    wall clock — never mixed with `boot`'s monotonic anchor), rounded UP to 5 s, clamped to
    `[0, 3600]` and forced NON-DECREASING (a mid-connect NTP step pins to the previous bucket
    instead of emitting a backwards offset). Floor 0, not 5: the anchor's own offset is 0 by
    definition.
  - **Bounded at 48 entries**, reduced in a fixed order: (1) ALWAYS drop an entry whose code AND
    bucket equal the previous kept entry's (a dozen `TOR_BOOTSTRAP_TAG` lines in one bucket are
    one indistinguishable repeat — collapsing them lowers the report's entropy); (2) if still
    over, shed `STREAM_*` (name-prefix matched) oldest-first; (3) if still over, shed every
    `PROBE_*` EXCEPT `PROBE_TIMEOUT`, NEWEST-first (the probes that bracket the start of the wait
    explain it; the ones nearest the answer are the least surprising); (4) if still over, drop the
    oldest. **`PROBE_TIMEOUT` is deliberately not sheddable by family** (2026-09-15): two
    consecutive full-budget timeouts are the evidence the cold `NEWNYM` rung fires on, so shedding
    them erased exactly the run that explains a `NEWNYM` in the same timeline — only rung (4), the
    last resort, can still take one. **No truncation marker is ever emitted** — a marker would
    itself be a "this device is unusual" token. Offsets are computed before any dropping, so
    survivors keep their true offsets.
  - **Omitted entirely** (no key, never `[]`) when nothing is eligible.
  - **Size:** the relay's body ceiling rose from 256 to 2048 B for this field. The arithmetic
    worst case derived from the longest name in `ConnectionLog.Code` (48 entries, every offset at
    the 3600 ceiling, a 16-char version, all FOUR numbers present) is **1598 B** since `reveal`
    added 14 B, i.e. **450 B of headroom** — pinned by
    `payload_worstCaseBodyStaysUnderTheRelayCeiling`, which asserts the headroom explicitly and
    fails in the test tier if a future code name or field is long enough to threaten the ceiling.
    **The size does NOT scale with the size of the vocabulary**: the body is bounded by the 48-entry
    cap times the LONGEST NAME, so the 2026-09-15 change's 15 new codes (longest `TOR_BOOT_DESCRIPTORS`, 20 chars
    against `TOR_BOOTSTRAP_PROBLEM`'s 21) cost exactly **0 B** of headroom — `codeNames_stayWithin
    TheNameLengthTheCeilingWasSizedFor` pins that longest name, because each extra character costs
    48 B. What a wider vocabulary does cost is relay-side LABEL CARDINALITY
    (the relay's connect-code metric, labelled by platform and code: 2 × 70 = 140 series; 2 × 72 = 144 since the
    bootstrap-stall rung's two codes) and a marginally sharper
    version of the already-disclosed per-SESSION linkability residual — no new channel, since the
    5 s grid, the dedupe, the cap and the "no value is ever echoed" rule are unchanged.
    `payload` also re-checks at runtime and drops the TIMELINE (never the numbers) rather than
    send an over-size body.
  - **Six diagnostic codes (2026-10-23) — RELAY FIRST.** `TOR_REUSED` codes Android's existing
    keep-alive line "reused warm Tor from the previous session" (`RunViewModel
    .adoptWarmTorFromPreviousSession`), so a WARM connect (no bootstrap; `boot` already omitted) is
    separable from a cold one on the wire. **iOS emits it too since its own bounded keep-alive
    (2026-10-23, "iOS bounded Tor keep-alive after backgrounding" below)**: same phrase word for
    word, same code, emitted by `AppState.adoptKeptTor` on a warm return after clearing the ring,
    so it anchors that session's timeline exactly as on Android. (A FOREGROUND re-unlock that
    reuses Tor — Lever C / re-auth — is still the same session and still never reports.) `HSDESC_NOT_FOUND` / `HSDESC_NO_HSDIR` / `HSDESC_RATE_LIMITED` / `HSDESC_BAD_DESC` /
    `HSDESC_UNEXPECTED` split `HSDESC_FAILED` by Tor's `HS_DESC FAILED REASON=` keyword
    (`NOT_FOUND`, `QUERY_NO_HSDIR`, `QUERY_RATE_LIMITED`, `BAD_DESC`, `UNEXPECTED`) through the
    FIXED map `TorReasonVocabulary.hsDescFailureCode` (commonMain; iOS mirror
    `TorControlEventParser.hsDescFailCodes`, pinned equal by `TorReasonParitySourceTest`).
    `QUERY_REJECTED`, a missing REASON and any future/unknown reason keep `HSDESC_FAILED`; a code
    is never derived from the string. The panel TEXT is unchanged, and Android's 2 s panel dedupe
    folds the whole family onto one key so a mixed-reason burst still shows one line. Longest new
    name 19 chars (`HSDESC_RATE_LIMITED`) ⇒ 0 B of ceiling headroom used. Cardinality: relay
    `LOG_CODES` 80 → 86. **The relay validates every code against `LOG_CODES` and answers an
    unknown one with an empty 400 for the WHOLE report** (no partial accept), so the relay carrying
    these six must be DEPLOYED before any client build that emits them ships.
  - **Debug mode keeps Tor's REASON words (2026-10-23).** `DebugLogRedactor` rule 3 turns any
    8+-char run holding `_` into `[id]`, which erased `QUERY_NO_HSDIR`, `CHANNEL_CLOSED`,
    `MEASUREMENT_EXPIRED`, `CLOCK_JUMPED`… from the consented debug upload. A run EXACTLY equal
    (case-sensitive, whole maximal run) to an entry of `TorReasonVocabulary.DEBUG_PASSTHROUGH` —
    the union of the parser's five REASON allowlists plus `CLOCK_JUMPED`, all `[A-Z_]` Tor protocol
    constants — is now kept; the general rule is unchanged (ids, capabilities, onions, a keyword
    with anything glued to it, and bootstrap TAGs still go). Pinned by `DebugModeTest
    .torReasonPassthrough_*`.
  - **No platform change.** `ConnectTelemetry.send` reads `ConnectionLog.snapshot()` itself,
    AFTER the jitter delay (the lines that close the connect land while the report sleeps), via
    a provider parameter that defaults to the singleton — so Android and iOS were not touched
    and cannot diverge.
- **What is deliberately NOT in it.** NO capability and NO auth header — this is the only
  relay endpoint the client calls unauthenticated, and a read cap here would tie a device's
  wait time to its inbox set. NO custom headers at all (not even `X-No-Push`), so the request
  carries nothing beyond what every relay call already does. NO install id, device model,
  locale, wall-clock timestamp, free text or Tor/circuit detail — `tor`/`boot` are bucketed
  DURATIONS and a `log` entry names a PHASE TRANSITION, never which guard, circuit, descriptor,
  address or consensus produced it. NOTHING is persisted: no vault row, no prefs, no
  retry queue — a session that cannot send simply does not, and there is no next-session
  obligation to leak.
- **The number is coarse on purpose.** `bucketSeconds` rounds UP to a multiple of 5 s and
  clamps to `[5, 3600]`, so the relay learns one of 720 buckets rather than a per-device
  millisecond fingerprint. Round UP, never to-nearest: rounding down would let a fast connect
  report `0`, which is both untrue and (as the only sub-floor value) distinguishing. The `log`
  offsets sit on the same 5 s grid and the same `[…, 3600]` ceiling, so the timeline cannot
  reintroduce millisecond resolution through the back door.
- **Once per SESSION on Android, once per PROCESS on iOS, jittered, fire-and-forget.** Android
  latches `connectTelemetrySent` on the first `isRelayReachable` true
  (`RunViewModel.armConnectTelemetry`, armed beside `armPushPromptForFirstRelayContact`) — a
  `RunViewModel` field, so each foreground session (a new ViewModel after `finishAndRemoveTask`)
  reports its own connect even when the process survived; iOS latches the same flag in
  `AppState.checkRelayReachability` and hands off to `IosAppController.reportConnectTime`, and
  `AppState` lives as long as the process. Neither flag is reset by a lock, so an in-process
  re-auth re-unlock cannot produce a second report. Every per-report value (`secs`/`tor`/`boot`
  anchors, `reveal`) must share that scope — see the `reveal` bullet for the 2026-10-23 fix. A uniform random 2–8 s delay (CSPRNG) separates the report from the first real relay
  request. One attempt, 20 s budget, no retry. The send rides the session job that lock / wipe
  / move-quiesce already cancel, so a teardown during the jitter window silently drops it.
- **Connect start is monotonic and set ONCE** — `SystemClock.elapsedRealtime()` at the top of
  `connectViaTor` (plus the debug direct branch) on Android, `ProcessInfo.systemUptime` at the
  top of `startTorOrDirect()` on iOS. A Tor auto-restart, a NEWNYM self-heal, a manual
  Reconnect or a move resume does NOT re-anchor it: from the user's side that is one wait.
  Deliberately NOT anchored on the pre-unlock speculative Tor start — that bootstrap overlaps
  credential entry, and counting a slow typist's thinking time would make the number
  meaningless.
- **`boot`'s anchor is a SEPARATE monotonic, set ONCE, at the Tor process start.** Android:
  `RunViewModel.torProcessStartedAtElapsedMs`, written at whichever of `startSpeculativeTor` or
  the first fresh-instance branch of `connectViaTor` actually launches this session's Tor child
  process — a later self-heal/forceFresh restart replaces the `TorManager` instance but never
  moves this anchor. **The `Connected` end of that span is stamped PRE-UNLOCK on Android since
  2026-09-15**: `RunViewModel.armBootStamp`, armed beside the speculative Tor start, waits
  for the first `Connected` and writes `bootConnectedElapsedMs` (first stamp wins —
  `firstBootStamp`). It used to be written only by the Tor monitor, which is attached at UNLOCK
  and is therefore replayed an already-`Connected` state, so Android `boot` was really
  `max(true bootstrap, time-to-unlock)` (dev-relay device runs: `boot` p50 40 s against `SOCKS_READY` at
  5 s) — read any Android `boot` histogram from before 2026-09-15 as an unlock-latency
  histogram. The observer touches nothing else: no vault, no `MessageManager`, no relay call.
  iOS needs no ViewModel-level field: `TorManager.shared.startedAtUptime` is
  already exactly this ("this process's Tor bootstrap began"), because `tor_main` can run at most
  once per iOS process — any `stop()` after a real start latches `relaunchRequired`. The one
  second report a process can send is a WARM session of the bounded keep-alive (2026-10-23),
  which started no Tor process and therefore OMITS `boot` (`AppState.warmTorSession`; Android
  omits it for an adopted Tor the same way) and reports `tor` = 0 (`torConnectedUptime` is
  re-stamped at adoption, before that session's anchor). iOS never had the Android defect
  either: its `TorManager.$state` sink is installed in `AppState.init`, i.e. pre-unlock, and
  latches `torConnectedUptime` on the first `.connected`. Both platforms floor the bucket
  at 5 s (`bucketBootSeconds`, NOT `tor`'s 0-floor) — a real bootstrap is never legitimately
  instantaneous, unlike "Tor was already up when the connect clock started".
- **One `ConnectionLog` line on send**, `Kind.RELAY`, `"connect time reported: N s"` — fixed
  phrase plus one number, per that surface's producer rule.
- **Known limitation:** the report rides the SAME Tor circuit as the health
  probe, so the relay can correlate it with the session that just connected. That is inherent
  — the report is *about* that session — and is why the body carries nothing the relay does
  not already observe from the connection itself.
- **Known limitation of the `log` timeline (2026-09-14):** a coded
  sequence with 5 s offsets is materially more distinguishing than three buckets — an unusual
  phase pattern (a repeated `TOR_RESTART`, a long `HSDESC_FAILED` run, a `CLOCK_JUMPED`) is a
  weak per-SESSION fingerprint the relay can use to tell two connects apart, and it describes
  this device's Tor experience in more detail than the connection alone shows. Bounded by the
  closed vocabulary, the 5 s quantisation, the unconditional dedupe, the 48-entry cap and the
  no-persistence rule (there is no cross-session identifier to join on), but NOT zero. The
  privacy review that raised this was weighed and accepted, and the field was shipped on every
  connect with no user-facing text.

**The PRE-UNLOCK rendezvous warm-up (lever 1, `RelayWarmup.kt`, 2026-09-11).** A v3 hidden-service
descriptor is never cached on disk by Tor, so every process pays an HSDir fetch + intro/rendezvous
build before its first byte — and that phase used to start only AFTER unlock, because the only thing
that talks to the relay is the health probe on `MessageManager`, which needs an open vault. Nothing
about a bare `GET /` does. So the moment Android's speculative pre-unlock Tor
(`RunViewModel.startSpeculativeTor`) reports `Connected` **and no vault is open**, `RelayWarmup.warm`
issues exactly one such request over `PlatformHttpClient.torProxy(port)` — preceded, when the
cookie-authenticated control socket is up, by `TorManager.requestHsDescriptorFetch` (`HSFETCH`),
which starts the descriptor fetch before any stream exists. Tor then keeps that rendezvous circuit
reusable for `MaxCircuitDirtiness` (10 min), so the session's real probe rides it. The rules:

- **No secret, ever.** No capability, no auth, no custom header, no body, no inbox named, and
  **never through a `MessageManager`** — it must be structurally impossible for this path to touch a
  vault, a counter or a ratchet. It is the same request the relay already receives first in every
  session, moved a few seconds earlier; zero new observables (the network already sees Tor bootstrap
  at launch on Android).
- **At most once per Tor instance**, armed only beside the one-shot speculative start, `vault == null`
  re-checked at fire time, 25 s budget per attempt, nothing persisted, failure never surfaced. A
  failed attempt that burned its whole budget (`RelayWarmup.shouldRotateAndRetry`) gets ONE
  `SIGNAL NEWNYM` + ONE retry, gated by the shared `MessageManager.shouldFireWarmupNewnym`:
  allowed while the session has had NO relay round trip yet — **whether or not the user has unlocked
  meanwhile** (2026-10-06; iPhone users unlock at ~t5 and the stuck first probe rides the same
  wedged HS circuits) — and spent from the same per-session `earlyNewnymsFired` budget as the cold
  rung (`EARLY_NEWNYM_MAX_FIRES` = 2 total). Cancelled by lock and by wipe; a launch-time wipe cannot race it because every wipe
  trigger runs strictly before the ViewModel exists.
- **It does NOT move the reveal gate.** It never latches `hasCompletedRelayRoundTrip` /
  `isRelayReachable`, so the contact list still stays hidden until the SESSION's own transport
  answers, and the post-unlock health probe is untouched — the warm-up only makes its circuit exist
  earlier.
- **Two `ConnectionLog` RELAY lines** — `"rendezvous warm-up started"` and `"rendezvous warm-up done
  in N s"` / `"rendezvous warm-up failed"` — fixed phrases plus one number, per that surface's
  producer rule. The onion is NEVER logged, and `RelayWarmup.v3OnionAddress` (the `HSFETCH` argument)
  is length- and charset-strict precisely because its output is interpolated into a command on an
  authenticated Tor control socket: a value carrying CR/LF would be command injection there, not a
  failed fetch. An `HSFETCH` that throws drops the control socket (degrading to restart-only
  self-heal) rather than leaving an unread reply a later `SIGNAL NEWNYM` would consume as its own
  `250`.
- **Android torrc, same package (lever 3):** `CircuitBuildTimeout 45` (was 90, `LearnCircuitBuildTimeout 0`
  unchanged) — the app's 20 s health budget rotates STREAMS, and a stream pending on a rendezvous
  inherits its circuit's fate, so a dead intro/rendezvous path used to cost the full 90 s. Never
  below ~30 s, where genuinely slow mobile builds start being killed; keep in lockstep with iOS.

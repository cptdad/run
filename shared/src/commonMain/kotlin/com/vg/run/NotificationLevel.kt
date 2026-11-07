package com.vg.run

// ---------------------------------------------------------------------------
// NotificationLevel — the mutually-exclusive notification-transport selector
// for the FCM / APNs / UnifiedPush notification tiers: how this device is told
// a message arrived while backgrounded, if at all.
//
//   OFF          — no background notification of any kind.
//   POLL         — legacy value, retained only so stored data still parses;
//                  no poller is behind it (RunViewModel maps it to off).
//   UNIFIED_PUSH — a self-hosted / non-Google push transport.
//   VENDOR_PUSH  — the platform vendor's push service (APNs on iOS, FCM on
//                  Android).
//
// TWO SLOTS, and the split is the whole fix:
//
//   • [NotificationLevelStore.KEY] — the PLAINTEXT selector, unchanged. It must
//     be readable BEFORE vault unlock and on a LOCKED screen: RunFcmService /
//     RunPushService decide whether to post a contentless banner from a process
//     the system started for a push wake, where the device key is by
//     construction unusable (Android mints it with
//     `setUnlockedDeviceRequired(true)`, iOS with
//     `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`). This slot is therefore
//     a LOCAL WAKE/DISPLAY GATE ONLY and is no longer trusted for any decision
//     that creates state off the device.
//   • [NotificationLevelStore.KEY_CONSENT] — a DEVICE-KEY AEAD blob sealing the
//     same token. This is the one a MINTING decision reads.
//
// THE PROBLEM. The plaintext slot was the SOLE gate on minting a vendor push
// identity (FCM/APNs/UnifiedPush) at every launch/unlock. Registration needs no
// OS prompt, so anyone able to write the app's files (root, a restored backup,
// an unlocked-device forensic workflow) could plant `vendor_push` and have the
// next unlock hand a push address to Google/Apple and a push row to the relay —
// silently, and repeatably. Sealing the value means a plant can only ever reach
// the local banner path, which delivers nothing to anyone.
// ---------------------------------------------------------------------------

enum class NotificationLevel(val storageValue: String) {
    OFF("off"),
    POLL("poll"),
    UNIFIED_PUSH("unified_push"),
    VENDOR_PUSH("vendor_push");

    companion object {
        /** Parse the persisted [storageValue]; null when unset/unknown. */
        fun fromStorageOrNull(v: String?): NotificationLevel? = entries.firstOrNull { it.storageValue == v }
    }
}

/**
 * Minimal commonMain accessor pair for the persisted [NotificationLevel].
 *
 * On Android `RunViewModel` writes [setLevel] at
 * TOGGLE time (`setBackgroundNotificationsEnabledAwaiting`) and reads through
 * [getLevel] (`isBackgroundNotificationsEnabled`), same computed-over-one-key
 * shape as iOS's `AppState.pushEnabled`. Android's OLD, separate opt-in flag
 * (`NotificationPollStore`'s retired `isEnabled`/`setEnabled`, prefs file
 * `notif_manifest_prefs`, key `bg_notifications_enabled`) is retired — this
 * store is the single source of truth on both platforms now.
 *
 * NOT migrated: unlike iOS's `AppState.pushEnabled` getter (which forward-folds
 * its own legacy `push_tier2_enabled` boolean into [KEY] on first read),
 * Android does NOT forward-fold the retired `bg_notifications_enabled` value.
 * A device that had it `true` but never got [KEY]
 * written (e.g. toggled on with no contacts yet — see the RunViewModel kdoc),
 * reads OFF after upgrading until the user re-toggles the switch.
 *
 * The sealed [KEY_CONSENT] slot beside [KEY]
 * splits the readers by what they DECIDE: [getLevel] for the locked-screen
 * wake gate, [provenLevel] for anything that mints or registers a push
 * identity. The writes moved to `putStringsSync` with it — two coupled slots on
 * iOS's transaction-less Keychain is exactly the case that helper exists for.
 */
object NotificationLevelStore {
    /**
     * Storage key. PUBLIC because it is the single source of truth for a value
     * that must also appear in [IosUserDefaultsKeys.all] — the iOS wipe sweep.
     * A duplicated literal here would silently drop the key from the wipe the
     * day one of the two copies changed .
     */
    const val KEY = "notif_level"

    /**
     * The device-key AEAD CONSENT PROOF for the same token — the slot
     * every identity-MINTING decision reads (see [provenLevel]).
     *
     * Lives in the SAME store as [KEY] on purpose: on Android that makes the
     * coupled write below one SharedPreferences editor commit (atomic), and the
     * file is already listed in `WipeRoutine.PREFS_FILES`, so nothing new has to
     * be added to a wipe list. On iOS it is a brand-new Keychain-resident key
     * with no NSUserDefaults era, so — exactly like `vlt_cn` / `vlt_rp` — it is
     * deliberately NOT added to [IosUserDefaultsKeys.all]: `kvDeleteAll()`
     * sweeps the whole KV service, and putting it on that list would instead arm
     * the legacy-UserDefaults READ fallback for a key that can never have one.
     */
    const val KEY_CONSENT = "notif_consent"

    /**
     * The AEAD context [KEY_CONSENT]'s blob is bound to. A NEW string,
     * never one of `VaultSelector`'s or [DebugMode.SLOT], so no blob can be
     * lifted from another slot and replayed into this one.
     */
    internal const val SLOT_CONSENT = "notif-level-consent:v1"

    /**
     * The ENCRYPTED-VAULT latch that makes the one-time
     * legacy migration actually one-time.
     *
     * The first cut of this fix used the PRESENCE of [KEY_CONSENT] as the latch.
     * That is circular, because the slot lives in exactly the store the
     * adversary can write: delete `notif_consent`, plant `notif_level=vendor_push`,
     * and the next read is byte-for-byte indistinguishable from a first-run
     * upgrade — so the plaintext gets blessed again, repeatably. The latch has to
     * live somewhere a prefs/UserDefaults/Keychain-level write cannot reach, and
     * the only such place on this device is INSIDE the vault (SQLCipher on
     * Android, `IosVaultDatabase` on iOS), behind CR-1.
     *
     * A GLOBAL `_meta` singleton, exactly the shape of `onboard_push_prompt_v1`
     * and `update_nudge_v1`: it belongs to no contact and no group, so NO purge
     * classifier applies to it and none may match it — it must NOT be added to
     * `ratchetMetaKeysForContact` or `GroupMetaKeys`, or a delete/re-pair would
     * reset the latch and re-open the window. It does not travel on a device move
     * (`MoveMetaPolicy` denies anything not on its allowlist), which is correct:
     * the new phone has no legacy plaintext to migrate either. A wipe destroys the
     * vault and takes the latch with it — also correct, since a wiped install has
     * nothing to migrate.
     *
     * IT IS AN EPOCH, NOT A BOOLEAN (replay). [SealedPref] binds
     * only the slot NAME as AAD, so a blob this device legitimately sealed keeps
     * decrypting forever under the same device key: an operator who images the
     * filesystem while push is ON, waits for the user to opt OUT, and restores
     * the old `notif_consent` entry has silently reverted the opt-out, and a
     * presence-only latch would see nothing wrong. So the marker holds a decimal
     * COUNTER, every proven write seals `"<level>:<epoch+1>"` and then records
     * `epoch+1`, and a blob is honoured ONLY when its epoch matches the vault's
     * (or is exactly one ahead — the seal-first/latch-last crash window, which
     * heals the latch forward). An older epoch is a replay and reads OFF.
     */
    const val VAULT_MARKER_KEY = "notif_consent_v1"

    /** The epoch the one-time legacy establish records. Writes start at 1, so 0 means "never established". */
    internal const val FIRST_EPOCH: Long = 1L

    /** Separator between the level token and the epoch inside the sealed payload. */
    private const val EPOCH_SEP = ':'

    /**
     * The LENIENT read of the plaintext slot: the LOCAL wake/display gate.
     *
     * This one is deliberately left plaintext and leaves every caller on
     * it (`RunFcmService.handleIntent`, `RunPushService.onMessage` /
     * `onNewEndpoint` / `onUnregistered`, `UnifiedPushSupport`'s
     * distributor-gone teardown, the Settings switch's displayed state). All of
     * them run either on a LOCKED screen — where the device key cannot be used
     * at all, so a sealed read would answer "off" and silently kill every banner
     * — or on a teardown path where the fail direction is already "do less".
     * A plant here buys an attacker a banner on a device that receives no
     * pushes, because [provenLevel] is what decides whether an address was ever
     * handed to a push service or to the relay.
     */
    fun getLevel(store: KeyValueStore): NotificationLevel =
        NotificationLevel.fromStorageOrNull(store.getString(KEY)) ?: NotificationLevel.OFF

    /**
     * The PROVENANCE-AWARE read — the only one a decision that MINTS or
     * REGISTERS a push identity may consume.
     *
     * Answers [NotificationLevel.OFF] for anything that is not an authenticated
     * decrypt of [KEY_CONSENT]: a plant, a damaged blob, or a device key that is
     * transiently unavailable. OFF-on-unreadable is safe here and nowhere near
     * the brick-safety class of decision — registration is unconditional and
     * session-scoped on both platforms (the internals doc's "do not persist
     * `vendorPushRegisteredIds`/`vendorPushToken`" rule), so a deferred pass
     * costs at most one session of push wakes and the next unlock re-registers.
     *
     * ESTABLISH-ON-READ, and the ONE-TIME TRUST OF THE LEGACY VALUE.
     * When [KEY_CONSENT] is ABSENT *and* the vault latch [VAULT_MARKER_KEY] says
     * no decision has ever been recorded, this reads the legacy plaintext [KEY]
     * ONCE, seals whatever it says — including `off` — and returns it, so a real
     * user who opted into push before this shipped does not silently lose it.
     *
     * THE LATCH IS THE VAULT MARKER, NOT THE PRESENCE OF [KEY_CONSENT]. Using the
     * sealed slot's own presence would have been circular: the adversary this
     * whole fix assumes can write that store, so deleting `notif_consent` and
     * planting `notif_level=vendor_push` would look exactly like a first-run
     * upgrade and re-bless the plaintext, repeatably. Once the marker is set,
     * ABSENT and UNAUTHENTICATED both answer OFF and the plaintext is never read
     * for a minting decision again — deleting the proof is now a way to turn push
     * OFF, and nothing else.
     *
     * NO VAULT, NO MIGRATION. If the vault is not open (or its meta cannot be
     * read) the latch cannot be consulted, so the establish is SKIPPED and the
     * answer is OFF. A PROVEN proof is still honoured without a vault — that is
     * an authenticated read, not a migration.
     *
     * Known limitation: one launch on one install: an attacker who plants the
     * plaintext before the very first post-upgrade read WITH THE VAULT OPEN gets
     * it blessed once. (The alternative, "never trust the legacy value", was
     * rejected: it would turn every existing push user's device silent with no
     * signal but the absence of notifications.)
     *
     * The plaintext slot is deliberately KEPT rather than deleted after the
     * migration — it is the locked-screen wake gate [getLevel] documents, and
     * deleting it would break banner display on exactly the devices the feature
     * exists for.
     *
     * [legacyPlaintext] is passed IN rather than read from [store], and that is
     * not a style choice: on iOS the plaintext slot lives in NSUserDefaults
     * (written by Swift's `AppState.pushEnabled`), [KEY] is on
     * [IosUserDefaultsKeys.all], and `KeyValueStore.getString` would therefore
     * MIGRATE it into the Keychain and DELETE the NSUserDefaults copy — after
     * which the Swift getter reads nil and every banner stops. Each platform
     * hands over the value it actually stores: Android its own
     * SharedPreferences read, iOS its NSUserDefaults read.
     */
    fun provenLevel(
        store: KeyValueStore,
        crypto: CryptoProvider,
        vault: VaultDatabase?,
        legacyPlaintext: String?,
    ): NotificationLevel =
        provenLevelIn(
            store.asNotifLevelStore(),
            crypto.asDeviceKeyCipher(),
            vault.asNotifConsentMarker(),
            legacyPlaintext,
        )

    /**
     * Writes BOTH slots — the plaintext wake gate and the sealed consent proof —
     * in ONE coupled write.
     *
     * `putStringsSync`, never two `putString`s: on iOS the Keychain has no
     * transaction and `kvPut` fails SILENTLY on a locked keybag, so a sequential
     * pair can land half-written. Half-written in the dangerous direction
     * (plaintext on, proof missing) would send the next [provenLevel] through
     * the establish-on-read branch, which re-derives the proof from that same
     * plaintext and converges — but the other half (proof on, plaintext gone)
     * would register the device and then drop every banner, which nothing
     * recovers. One journalled batch avoids both.
     *
     * @return true when the sealed proof READ BACK at the new epoch. `false`
     * means nothing this call wrote may be relied on — the caller must treat the
     * enable as FAILED and revert, or it would register a push identity that no
     * future [provenLevel] will ever acknowledge (and therefore that no opt-out
     * sweep will ever find). A closed vault is one of those `false`s: the epoch
     * lives in the vault, and a proof sealed against a counter we cannot read is
     * one no later read can validate.
     */
    fun setLevel(
        store: KeyValueStore,
        crypto: CryptoProvider,
        vault: VaultDatabase?,
        level: NotificationLevel,
    ): Boolean =
        setLevelIn(
            store.asNotifLevelStore(),
            crypto.asDeviceKeyCipher(),
            vault.asNotifConsentMarker(),
            level,
        )

    /**
     * Writes ONLY the sealed consent proof — the iOS half of [setLevel].
     *
     * iOS keeps the plaintext slot in NSUserDefaults (Swift's
     * `AppState.persistNotifLevel`), so the two slots genuinely live in two
     * stores there and no single write can cover both. The split is safe in one
     * direction only, which is why the proof is written SECOND on that platform:
     * plaintext-without-proof converges on the next [provenLevel] (the
     * establish-on-read branch re-derives the proof from it), while
     * proof-without-plaintext would register a device whose banners are all
     * dropped.
     *
     * @return true when the proof READ BACK at the new epoch — the same
     * unproven-write rule [provenLevel]'s migration follows. `false` with no
     * vault open, for the reason on [setLevel].
     */
    fun setConsentProof(
        store: KeyValueStore,
        crypto: CryptoProvider,
        vault: VaultDatabase?,
        level: NotificationLevel,
    ): Boolean =
        setConsentProofIn(
            store.asNotifLevelStore(),
            crypto.asDeviceKeyCipher(),
            vault.asNotifConsentMarker(),
            level,
        )

    /**
     * Removes the persisted level entirely — used on opt-out/registration-revert
     * instead of writing [NotificationLevel.OFF], so an untouched or reverted
     * preference never manifests as an on-disk artifact (absence reads back as
     * OFF via [getLevel]'s fallback). Mirrors iOS's `clearWipeResidue()` switching
     * to `removeObject(forKey:)` instead of writing `"off"` — a written falsy value is itself proof the app was configured;
     * an absent key is not.
     *
     * Removes BOTH slots. The consent proof must go with the level on
     * every opt-out / revert / distributor-gone path, or a later
     * [provenLevel] would keep re-registering the device from a proof the user
     * revoked. Order is proof FIRST: the proof is the slot that authorises a
     * relay-visible action, so if the process dies between the two removals the
     * survivor is the inert local wake gate, never a live minting authority.
     *
     * AND IT INVALIDATES EVERY PROOF SEALED SO FAR. Removing
     * the two slots is not enough on its own: the vault epoch would still read N
     * — the last proven-ON epoch — so restoring a pre-opt-out blob sealed at N
     * from a filesystem image is an EXACT match and silently reverts the opt-out.
     * That is the replay the epoch exists to stop, reached through the shipped
     * opt-out path rather than through [setLevel]. So an opt-out ADVANCES the
     * epoch and seals an explicit OFF at the new one, which kills every earlier
     * blob and leaves the slot in a state the next read accepts with no further
     * writes.
     *
     * The PLAINTEXT slot is still REMOVED, never written to `"off"` — that is
     * the slot the absence-not-artifact rule is about, and it is the wake gate
     * `RunFcmService`/`RunPushService` read, so its absence is what turns banners
     * off the instant the user opts out. The sealed slot is a different object:
     * it is written for EVERY provisioned install already (the establish-on-read
     * latch), so an OFF there signals nothing its presence did not signal before.
     *
     * WITH NO VAULT the epoch cannot be advanced here — the two push-service
     * teardown paths (`RunPushService.onUnregistered`, `UnifiedPushSupport`'s
     * distributor-gone sweep) run in a process that has none. The removal still
     * happens, and the invalidation lands at the next vault-open read of an
     * ABSENT proof (see [provenLevelIn]). Known limitation: between such
     * a teardown and the next unlock, an attacker who RESTORES the old blob is
     * seen by the PROVEN branch and wins that round. Closing it would need a
     * durable write to a store that is, by construction, not open.
     */
    fun clearLevel(store: KeyValueStore, crypto: CryptoProvider, vault: VaultDatabase?) {
        clearLevelIn(store.asNotifLevelStore(), crypto.asDeviceKeyCipher(), vault.asNotifConsentMarker())
    }

    internal fun clearLevelIn(store: NotifLevelStore, cipher: DeviceKeyCipher, marker: NotifConsentMarker) {
        // Removal FIRST, proof before plaintext, so a failed seal below still
        // leaves nothing behind rather than a stale ON proof.
        store.remove(KEY_CONSENT)
        store.remove(KEY)
        invalidateSealedProofs(store, cipher, marker)
    }

    /**
     * Advance the epoch past every blob sealed so far by sealing an explicit OFF
     * at `epoch + 1`.
     *
     * IDEMPOTENT by construction, which is why it is a seal and not a bare
     * counter bump: the proof it writes reads back PROVEN at the new epoch, so
     * the next call takes [provenLevelIn]'s PROVEN branch and writes nothing. A
     * bare bump would re-fire on every read while the proof stayed absent — one
     * durable `_meta` write per control-poll cycle for as long as the user stays
     * opted out.
     *
     * No-op without a vault (no epoch to advance) and never throws.
     */
    private fun invalidateSealedProofs(
        store: NotifLevelStore,
        cipher: DeviceKeyCipher,
        marker: NotifConsentMarker,
    ) {
        if (marker.epoch() == null) return
        setConsentProofIn(store, cipher, marker, NotificationLevel.OFF)
    }

    // -- internal seam --------------------------------------------------------
    //
    // [KeyValueStore] / [CryptoProvider] are `expect class`es needing a platform
    // handle, so commonTest cannot construct either — the same constraint
    // [DebugModeStore] and [DeviceKeyCipher] document. These two take tiny
    // interfaces so the decision table is unit-testable without a
    // platform.

    internal fun provenLevelIn(
        store: NotifLevelStore,
        cipher: DeviceKeyCipher,
        marker: NotifConsentMarker,
        legacyPlaintext: String?,
    ): NotificationLevel {
        val read = try {
            SealedPref.open(cipher, SLOT_CONSENT, store.get(KEY_CONSENT))
        } catch (_: Exception) {
            return NotificationLevel.OFF
        }
        return when (read.state) {
            SealedPrefState.PROVEN -> provenLevelForEpoch(read.value, marker)
            // A planted / damaged proof, or a device key we cannot use right
            // now. Both answer OFF; neither is ever "repaired" from the
            // plaintext, because that is the plant channel this closes.
            SealedPrefState.UNREADABLE -> NotificationLevel.OFF
            // A proof that is present but not ours is a plant or damage; a proof
            // that is absent over a latched vault is a DELETION. Neither may
            // re-run the legacy migration — that is the whole point of the latch.
            SealedPrefState.UNAUTHENTICATED -> NotificationLevel.OFF
            SealedPrefState.ABSENT -> when (marker.epoch()) {
                // No vault open, or its meta could not be read: the latch cannot
                // be consulted, so the migration must not run. OFF, retried when
                // a vault is available.
                null -> NotificationLevel.OFF
                0L -> establishConsentFromLegacy(store, cipher, marker, legacyPlaintext)
                // THE ATTACK. The proof is gone but the vault records a decision
                // on this install, so its absence is a deletion, not a first run.
                // Answer OFF — and INVALIDATE, once: this is where an opt-out
                // taken with NO vault open (the two push-service teardown paths)
                // finally advances the epoch, so every blob sealed before that
                // removal is dead from here on. Idempotent — the seal it writes
                // makes the next read take the PROVEN branch.
                else -> {
                    invalidateSealedProofs(store, cipher, marker)
                    NotificationLevel.OFF
                }
            }
        }
    }

    /**
     * The FRESHNESS half: a decrypting blob is only the CURRENT consent if its
     * epoch matches the vault's.
     *
     * Four outcomes, and the `+1` one is the crash window rather than slack:
     *  - blob epoch == vault epoch (≥ 1) ⇒ current. Honour it.
     *  - blob epoch == vault epoch + 1 ⇒ the seal landed and the latch write did
     *    not (process death, a failed `putMeta`). Honour it and HEAL the latch
     *    forward, which is also what shuts the window for good.
     *  - anything lower ⇒ a RESTORED OLDER BLOB. This is the replay: a
     *    filesystem image taken while push was on, put back after an opt-out.
     *    OFF.
     *  - no epoch in the payload, or the vault epoch cannot be read ⇒ nothing
     *    can be concluded. OFF.
     */
    private fun provenLevelForEpoch(payload: String?, marker: NotifConsentMarker): NotificationLevel {
        val sep = payload?.lastIndexOf(EPOCH_SEP) ?: -1
        if (payload == null || sep <= 0) return NotificationLevel.OFF
        val level = NotificationLevel.fromStorageOrNull(payload.substring(0, sep))
            ?: return NotificationLevel.OFF
        val blobEpoch = payload.substring(sep + 1).toLongOrNull() ?: return NotificationLevel.OFF
        if (blobEpoch < FIRST_EPOCH) return NotificationLevel.OFF
        val vaultEpoch = marker.epoch() ?: return NotificationLevel.OFF
        return when (blobEpoch) {
            vaultEpoch -> level
            vaultEpoch + 1 -> {
                marker.recordEpoch(blobEpoch)
                level
            }
            else -> NotificationLevel.OFF
        }
    }

    /**
     * The one-time legacy migration described on [provenLevel]. Seals whatever
     * the plaintext slot says (defaulting to OFF — the seal is written for EVERY
     * install, including one that never enabled push) and returns it only once
     * the seal READS BACK: an unproven write is not a decision, and returning the
     * level over one would repeat the legacy trust every session while claiming
     * it had been retired.
     *
     * ORDER: seal, then latch. A crash after the seal leaves a proven consent
     * whose next read self-heals the latch (see [provenLevelIn]); a crash before
     * it leaves nothing at all and the establish simply re-runs. Never the other
     * order — a latch without a seal would answer OFF forever and strand a legacy
     * push user with no way back but re-toggling.
     *
     * The plaintext slot is NOT deleted here, and deliberately: it is the
     * locked-screen wake gate `RunFcmService`/`RunPushService` read (the device
     * key is unusable there by construction), so deleting it would silently kill
     * every banner for the user this migration exists to protect. It buys nothing
     * now that the latch lives in the vault — after the marker is set the
     * plaintext has no vote, so re-planting it is inert.
     *
     * Never throws and never writes the plaintext slot: [setLevel] owns that.
     */
    private fun establishConsentFromLegacy(
        store: NotifLevelStore,
        cipher: DeviceKeyCipher,
        marker: NotifConsentMarker,
        legacyPlaintext: String?,
    ): NotificationLevel {
        val legacy = NotificationLevel.fromStorageOrNull(legacyPlaintext) ?: NotificationLevel.OFF
        return if (setConsentProofIn(store, cipher, marker, legacy)) legacy else NotificationLevel.OFF
    }

    /**
     * The payload sealed into [KEY_CONSENT]: the level token and the epoch it
     * belongs to, so a blob cannot outlive the decision it recorded.
     */
    private fun sealedPayload(level: NotificationLevel, epoch: Long): String =
        "${level.storageValue}$EPOCH_SEP$epoch"

    internal fun setLevelIn(
        store: NotifLevelStore,
        cipher: DeviceKeyCipher,
        marker: NotifConsentMarker,
        level: NotificationLevel,
    ): Boolean = try {
        // No vault ⇒ no epoch ⇒ no consent may be minted at all. A proof sealed
        // against a counter we cannot read is one no future read can validate.
        val next = (marker.epoch() ?: return false) + 1
        val payload = sealedPayload(level, next)
        val sealed = SealedPref.seal(cipher, SLOT_CONSENT, payload)
        store.putAllSync(mapOf(KEY to level.storageValue, KEY_CONSENT to sealed))
        val back = SealedPref.open(cipher, SLOT_CONSENT, store.get(KEY_CONSENT))
        val proven = back.proven && back.value == payload
        // Seal FIRST, latch SECOND — a crash between them leaves epoch+1 sealed
        // over epoch latched, which the read path honours and heals forward.
        // The reverse order would strand a latched epoch with no blob for it,
        // i.e. a silent permanent OFF.
        if (proven) marker.recordEpoch(next)
        proven
    } catch (_: Exception) {
        // The device key could not seal (it is unusable while the screen is
        // locked) or the store refused. Report the failure: a plaintext-only
        // write would leave the old plaintext-only shape on disk for the
        // establish-on-read to bless, and a registration over an unpersisted
        // consent is one no later opt-out sweep can find.
        false
    }

    internal fun setConsentProofIn(
        store: NotifLevelStore,
        cipher: DeviceKeyCipher,
        marker: NotifConsentMarker,
        level: NotificationLevel,
    ): Boolean = try {
        // SINGLE-key `putStringSync`, not the batch: on iOS `putStringsSync`
        // opens the `vlt_txn_journal` write-ahead journal, and a journal that is
        // still live makes `VaultSelector`'s orphan purge defer. That defer
        // is safe, but this write runs on EVERY unlock (it is the establish-on-read
        // latch), and coupling a non-credential preference to the credential
        // journal for no reason is exactly the kind of surprise the journal note
        // in the internals doc warns about. One key needs no transaction.
        val next = (marker.epoch() ?: return false) + 1
        val payload = sealedPayload(level, next)
        store.putSync(KEY_CONSENT, SealedPref.seal(cipher, SLOT_CONSENT, payload))
        val back = SealedPref.open(cipher, SLOT_CONSENT, store.get(KEY_CONSENT))
        val proven = back.proven && back.value == payload
        // Latch AFTER the seal is proven — see [setLevelIn] for why this order
        // and never the reverse. The legacy establish reaches here with a vault
        // epoch of 0, so it writes [FIRST_EPOCH].
        if (proven) marker.recordEpoch(next)
        proven
    } catch (_: Exception) {
        false
    }
}

/**
 * The three [KeyValueStore] operations [NotificationLevelStore] needs, as an
 * interface commonTest can implement. See the seam note in
 * [NotificationLevelStore].
 */
internal interface NotifLevelStore {
    fun get(key: String): String?
    /** Durable single-key write — [KeyValueStore.putStringSync]. */
    fun putSync(key: String, value: String)
    /** Atomic multi-key write — [KeyValueStore.putStringsSync]. */
    fun putAllSync(values: Map<String, String>)
    fun remove(key: String)
}

/**
 * The encrypted-vault latch behind [NotificationLevelStore.VAULT_MARKER_KEY], as
 * an interface commonTest can implement — `VaultDatabase`'s actuals are SQLCipher
 * and `IosVaultDatabase`, neither constructible in commonTest.
 *
 * TRI-STATE, and the third state is the load-bearing one: [established] answers
 * `null` when there is NO OPEN VAULT or its meta could not be read. `null` must
 * never be collapsed into `false` — that is precisely "we cannot tell whether a
 * decision was recorded", and migrating on it would hand the attack back (delete
 * the proof, plant the plaintext, read while the vault happens to be closed).
 */
internal interface NotifConsentMarker {
    /** The recorded epoch: ≥1 = a decision is on file, 0 = none, null = cannot tell. */
    fun epoch(): Long?

    /**
     * Record [epoch]. MONOTONIC — a value not greater than the one on file is
     * ignored, so the self-heal (and a stale caller) can never rewind the
     * counter and re-open the replay window it exists to close.
     *
     * @return true when [epoch] is on file after this call. Never throws.
     */
    fun recordEpoch(epoch: Long): Boolean
}

/** Adapts the currently-open vault, or the absence of one. */
internal fun VaultDatabase?.asNotifConsentMarker(): NotifConsentMarker {
    val db = this ?: return object : NotifConsentMarker {
        override fun epoch(): Long? = null
        override fun recordEpoch(epoch: Long): Boolean = false
    }
    return object : NotifConsentMarker {
        override fun epoch(): Long? = try {
            // A row we cannot parse is treated as epoch 0 — not as "cannot
            // tell". Only an unreadable VAULT is ambiguous; a garbage value in
            // a table only the vault key can write is, at worst, our own bug,
            // and answering 0 re-establishes cleanly instead of wedging OFF.
            db.getMeta(NotificationLevelStore.VAULT_MARKER_KEY)?.toLongOrNull() ?: 0L
        } catch (_: Exception) {
            null
        }

        override fun recordEpoch(epoch: Long): Boolean = try {
            val current = db.getMeta(NotificationLevelStore.VAULT_MARKER_KEY)?.toLongOrNull() ?: 0L
            if (epoch <= current) return current >= epoch
            db.putMeta(NotificationLevelStore.VAULT_MARKER_KEY, epoch.toString())
            true
        } catch (_: Throwable) {
            // `putMeta` is @Throws so a lost write is catchable. Losing this one
            // costs nothing immediately: the seal already landed one epoch ahead,
            // so the next PROVEN read honours it and heals the latch.
            false
        }
    }
}

internal fun KeyValueStore.asNotifLevelStore(): NotifLevelStore {
    val self = this
    return object : NotifLevelStore {
        override fun get(key: String): String? = self.getString(key)
        override fun putSync(key: String, value: String) = self.putStringSync(key, value)
        override fun putAllSync(values: Map<String, String>) = self.putStringsSync(values)
        override fun remove(key: String) { self.remove(key) }
    }
}

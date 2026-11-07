package com.vg.run

import android.content.Context


// ---------------------------------------------------------------------------
// InactivityWipe — destroys all data if the app hasn't been opened within
// a configurable time window.
//
// Security purpose: if a device is lost or abandoned and later opened, the
// data self-destructs once the inactivity threshold has elapsed.
//
// SCOPE / LIMITATION: this is a DEFENSE-IN-DEPTH
// bonus, NOT the primary at-rest protection. The check runs only from
// MainActivity.onCreate (a foreground launch) and is skipped while the device
// is locked (the unlocked-device-required Keystore key can't decrypt the
// timestamp then). So a device that is seized and NEVER unlocked-and-launched
// again does not auto-wipe. That case is still protected at rest by the PIN +
// the unlocked-device-required Keystore-wrapped SQLCipher key — the wipe is an
// extra layer for the "opened again later"
// path, not a standalone seizure countermeasure. (There is intentionally no
// background WorkManager/boot-receiver job — the app follows a foreground-only
// model.)
//
// Nor does it stop a careful examiner (review 2026-11-06, S2 F5): someone who can
// unlock the phone and launch Rún can turn off automatic time, set the clock to
// just after the seizure and reboot first, which drops the elapsedRealtime
// anchor and leaves only the wall clock they set. A reboot costs them nothing
// here: this check only runs on an UNLOCKED device, so they already hold the
// passcode, and a passcode crack reboots the phone anyway. The user-facing copy
// therefore says the erase happens "the next time Rún is opened" after the limit.
//
// The timestamp VALUE is encrypted with CryptoProvider (Tink/Keystore), so the
// CONTENT of inactivity_prefs.xml does not disclose when the app was last used.
//
// Known limitation (iOS sibling: InactivityWipe.swift's plist-mtime note): the
// file's inode mtime still shows roughly when it was last written, readable from a
// filesystem image without breaking the AEAD, and there is no application-level
// fix for that. checkAndWipeIfNeeded() below writes an unrelated, content-free
// random probe key on every bare (unlocked) launch, so the file is touched for
// reasons other than a real vault unlock — this blurs the mtime, it does not hide
// it. Don't "improve" this by resetting mtime with
// File.setLastModified(): that only rewrites mtime, and the kernel stamps ctime
// to the real write instant on that same call.
//
// The last-active VALUE (as opposed to the probe above) is refreshed ONLY on a
// real vault UNLOCK (recordUnlock, called from RunViewModel.onVaultOpened) —
// NOT on a bare app launch, so an unlocked-but-not-vault-unlocked phone cannot
// keep a seized vault alive by tapping the launcher icon; the
// mtime probe is a SEPARATE key and never touches KEY_LAST_OPENED's stored
// value, so it cannot reopen that. Mirrors iOS InactivityWipe.touch(), called
// only from the .opened unlock/recovery branch.
//
// If decryption fails (tampered data, Keystore cleared) WHILE the device is
// unlocked AND a vault still exists, the timestamp is treated as expired and a
// wipe is triggered — fail-safe; a locked-device decrypt failure defers instead
// (see below). With NO vault configured a decrypt failure does NOT wipe: that is
// post-wipe residue, and wiping again would re-arm a wipe-on-every-launch loop.
// After a wipe NOTHING is re-encrypted here — re-writing the timestamp through the
// just-erased key would recreate the inactivity_prefs / run_master_key /
// run_keyset_prefs artifact trio and seal an undecryptable blob (the CRITICAL).
//
// The paragraphs above describe the CONTENT
// threat model; deleting the FILE OUTRIGHT was a separate, unaddressed hole —
// an absent timestamp was unconditionally treated as "never armed", so an
// examiner who deletes inactivity_prefs.xml before every launch restarts the
// dead-man's clock from zero forever. Fixed with an ANCHOR marker
// (INACTIVITY_ARMED_KEY) written into vault_selector_prefs — the SAME file
// VaultSelector's DB-key wrap (vlt_c) lives in, so it cannot be deleted
// without destroying the vault outright — mirroring PinAttemptsStore's
// established-marker exactly. The anchor's whole correctness rests on
// one invariant: MARKER ARMED ⇒ A TIMESTAMP BLOB WAS DURABLY PERSISTED. So the
// blob is written with commit() (fsync'd, like PinAttemptsStore's putStringSync)
// and the marker armed only after that returns true — a marker that is more
// durable than the thing it attests to turns an interrupted first arm into a
// false deletion-tamper verdict and wipes an untouched vault. See
// storeTimestamp/armInactivityMarker and the storedB64==null branch of
// checkAndWipeIfNeeded below.
//
// The sealed value is no longer a bare wall-clock
// millisecond count. It is InactivityPolicy.formatStamp's "<wallMs>|<uptimeMs>",
// carrying the kernel-uptime anchor (currentUptimeMs) INSIDE the same AEAD blob —
// so the dead-man's switch also measures elapsed time on a clock the person
// holding the phone cannot wind ("disable automatic time, pin the date to
// the seizure day" used to disarm it permanently). Every LEGACY bare-decimal blob
// still parses (wall-clock rules only) and gains its anchor on the next
// recordUnlock — migrate-on-write, never a hard break. The other half:
// the backward-clock branch now needs InactivityPolicy.CLOCK_BACK_TOLERANCE_MS
// of slack before it can crypto-erase a vault, because it fires unconfirmed and
// takes the recovery blob with it.
// ---------------------------------------------------------------------------

object InactivityWipe {

    private const val TAG = "InactivityWipe"
    private const val PREFS_NAME = "inactivity_prefs"
    private const val KEY_LAST_OPENED = "last_opened_enc"
    private const val AEAD_CONTEXT = "inactivity-wipe-timestamp"

    // mtime-dilution probe (see header) — deliberately a SEPARATE key
    // from KEY_LAST_OPENED, never read back by anything. Its value is random, not
    // temporal, so it discloses nothing on its own even if read directly.
    private const val KEY_MTIME_PROBE = "launch_probe"

    // The fate-shared anchor store — same file as VaultSelector's vlt_c
    // (DB-key wrap), same pattern PinAttemptsStore uses for its own
    // ESTABLISHED_KEY anchor. Deleting THIS store destroys the vault's own
    // credential state, so an attacker cannot delete it "for free" the way
    // they can delete inactivity_prefs alone.
    private const val ANCHOR_PREFS_NAME = VAULT_SELECTOR_PREFS_NAME

    // "The last-opened timestamp has been armed at least once" marker.
    // Plain presence flag, not credential material — stored unencrypted, same
    // as PinAttemptsStore.ESTABLISHED_KEY. See armInactivityMarker /
    // inactivityMarkerArmed / absentTimestampIsDeletionTamper /
    // absentTimestampShouldEstablish.
    private const val INACTIVITY_ARMED_KEY = INACTIVITY_ARMED_ANCHOR_KEY

    /** Default inactivity threshold: 7 days. Shared with iOS via InactivityPolicy. */
    var thresholdMs: Long = InactivityPolicy.THRESHOLD_MS

    /**
     * The un-rollable corroborating clock, sampled at the
     * same instants as the wall clock. `SystemClock.elapsedRealtime()` is kernel
     * uptime — INCLUDES deep sleep, and no app/adb/Settings surface can wind it
     * back (unlike `System.currentTimeMillis`, which "disable automatic time" hands
     * straight to the person holding the phone). Identical source to
     * `RunViewModel.monotonicSampler`, which feeds `PinAttemptsStore`'s
     * `windowRolled` — same trust argument, deliberately not a second mechanism.
     * A reboot resets it to ~0, which reads as "uptime went backwards" and falls
     * back to the wall clock (see InactivityPolicy.isExpired).
     */
    private fun currentUptimeMs(): Long = android.os.SystemClock.elapsedRealtime()

    // internal (was private): reused by MainActivity's orphan-wipe guard
    // so the destructive branch relies on device state, not exception taxonomy.
    internal fun isDeviceCurrentlyLocked(context: Context): Boolean {
        val km = context.getSystemService(Context.KEYGUARD_SERVICE) as android.app.KeyguardManager
        return km.isDeviceLocked
    }

    fun checkAndWipeIfNeeded(
        context: Context,
        deviceLocked: Boolean = isDeviceCurrentlyLocked(context)
    ): Boolean {
        // The last-opened timestamp is encrypted with the unlocked-device-required
        // Keystore key. While the device is locked that key is unusable; decrypting
        // then fails and the fail-open path below would wipe the vault. Defer the
        // check to the next unlocked launch.
        if (deviceLocked) return false

        // This is a THROWAWAY device-key provider
        // — nothing outside this call ever holds it — and the decision below
        // DECRYPTS with it, which unwraps the Tink/Keystore AES-256 data keyset into
        // process RAM on every unlocked launch of a configured vault. Only the two
        // destructive branches used to scrub it (and those for a different reason:
        // crypto-erase-first); every ordinary launch returned with the keyset still
        // cached in an object nobody could reach to wipe. Own it here and scrub on
        // EVERY exit path. Same defect and same idiom as MainActivity's
        // orphaned-credential probe and iOS's inactivityCrypto (commit 41633aa);
        // wipeKey() is idempotent and Android's only drops the cached CryptoManager,
        // which manager() re-creates lazily, so the two destructive branches keep
        // their earlier, ORDERED call and this one is a harmless no-op after them.
        // [recordUnlock] is unaffected: it takes the CALLER's warm provider.
        val crypto = CryptoProvider(context)
        return try {
            checkAndWipeIfNeededInner(context, crypto)
        } finally {
            try { crypto.wipeKey() } catch (_: Exception) { /* best-effort */ }
        }
    }

    /** Body of [checkAndWipeIfNeeded], split out only so the device-key provider can
     *  be scrubbed in a `finally` around every return path — see the note there. */
    private fun checkAndWipeIfNeededInner(context: Context, crypto: CryptoProvider): Boolean {
        // Per-level inactivity threshold (threat-level slider), read through the
        // SAME decrypting path iOS uses (VaultSelector.protectionLevelForEnforcement
        // → InactivityPolicy.thresholdMsOrNull). The stored level is a device-key
        // AEAD blob — the old raw SharedPreferences read
        // parsed the blob as null and silently fell back to the 7-day default,
        // crypto-erasing a CASUAL (180-day) vault ~173 days early. The device key
        // is the pre-unlock layer (CryptoProvider is lazy; a fresh install with no
        // stored level never touches the Keystore here), and a level that exists
        // but can't be read right now because of a TRANSIENT Keystore outage
        // yields null → DEFER this launch rather than apply a shorter window.
        // A DAMAGED blob is no longer in that bucket: the
        // device key works and the value failed AEAD, so it yields MAXIMUM's
        // 7-day window instead of null — deferring on it, every launch, was a
        // permanent disarm of the dead-man's switch for one flipped byte.
        val selector = VaultSelector(
            store = KeyValueStore(context, VAULT_SELECTOR_PREFS_NAME),
            crypto = crypto,
            // Never invoked by the level read (no DB is opened), but the
            // VaultSelector constructor requires a factory.
            vaultFactory = androidVaultFactory(context)
        )
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val now = System.currentTimeMillis()

        // An Unreadable level yields null → DEFER (never apply a shorter window and
        // wipe early). Unlike the old code we do NOT record on defer: the last-active
        // timestamp is refreshed on a real UNLOCK (recordUnlock), never on a bare
        // launch, so a stale-clock/early-wipe can't be manufactured from an
        // un-authenticated launch.
        thresholdMs = InactivityPolicy.thresholdMsOrNull(
            selector.protectionLevelForEnforcement(), defaultMs = thresholdMs
        ) ?: run {
            platformLogWarn(TAG, "protection level unreadable — deferring inactivity check")
            return false
        }

        val storedB64 = prefs.getString(KEY_LAST_OPENED, null)

        if (storedB64 == null) {
            // No timestamp recorded yet: a just-provisioned-but-never-unlocked vault,
            // a fresh install, the state right AFTER a wipe — OR the file was
            // DELETED to reset this clock. Start the clock ONLY if a vault actually
            // exists; recording when none does (post-wipe) would re-encrypt through —
            // and so regenerate — the just-erased Keystore master key, recreating the
            // inactivity_prefs / run_master_key / run_keyset_prefs wipe-fingerprint
            // trio AND sealing a blob undecryptable under the erased key (the permanent
            // wipe-on-launch loop). Mirrors iOS (records 'now' only when configured).
            if (vaultConfigured(selector)) {
                // Brick-safe anchor decision (see
                // PinAttemptsStore for the canonical version of this exact rule):
                //  - marker ARMED + vault configured + timestamp absent ⇒ the
                //    timestamp blob was DELETED after being armed at least once —
                //    the deletion-tamper signature. Treat exactly like an
                //    expired timestamp (wipe), not like a fresh install.
                //  - marker NOT armed + vault configured ⇒ a genuine first arm
                //    (fresh provision) OR an install upgrading from a build that
                //    predates this marker and has not yet had a post-upgrade real
                //    unlock (recordUnlock arms it too — see storeTimestamp).
                //    ESTABLISH-ON-READ: write 'now' + arm the marker, NEVER wipe.
                //    Ambiguous absence must never brick a vault (see PinAttemptsStore
                //    for the same rule).
                val armed = inactivityMarkerArmed(context)
                if (absentTimestampIsDeletionTamper(armed, vaultConfigured = true)) {
                    platformLogWarn(TAG, "inactivity timestamp missing but marker survived — treating as deleted (expired)")
                    crypto.wipeKey()
                    wipeAllData(context)
                    return true
                }
                // absentTimestampShouldEstablish(armed, true) is the only other
                // case reachable here (the two are complements when configured).
                storeTimestamp(context, crypto, prefs, now)
            }
            return false
        }

        // A timestamp exists → decide expiry.
        val stamp = try {
            val encrypted = decodeBase64(storedB64)
            val plaintext = crypto.decrypt(encrypted, AEAD_CONTEXT.toByteArray(Charsets.UTF_8))
            // The sealed record is now "<wallMs>[|<uptimeMs>]". A LEGACY
            // bare-decimal blob (every vault provisioned before this build) parses
            // fine and yields NO_UPTIME — wall-clock rules only, exactly as before;
            // it re-writes in the anchored shape on the next recordUnlock. A
            // genuinely malformed plaintext still throws into the same handler that
            // has always caught it, so the fail-safe taxonomy below is unchanged.
            InactivityPolicy.parseStamp(plaintext.toString(Charsets.UTF_8))
                ?: throw IllegalStateException("malformed inactivity stamp")
        } catch (e: KeyUnavailableException) {
            // Device key transiently unavailable (Keystore glitch, or the device
            // locked mid-call even though the pre-check saw it unlocked). NOT tamper:
            // decrypting the timestamp is impossible right now, so DEFER to the next
            // unlocked launch rather than falling through to 0L → wipe. CryptoProvider
            // raises this type specifically so callers defer; parity with iOS.
            platformLogWarn(TAG, "key unavailable (transient) — deferring inactivity check")
            return false
        } catch (e: Exception) {
            if (isDeviceCurrentlyLocked(context)) {
                platformLogWarn(TAG, "key unavailable (device locked) — deferring inactivity check")
                return false
            }
            // AEAD failure on an unlocked device. Fail-safe (treat as expired) ONLY
            // when a real vault still exists — a genuine key-rotation/tamper against a
            // live vault. With NO vault configured this is post-wipe residue (an orphan
            // blob sealed under an erased key); wiping again would re-arm the
            // wipe-on-launch loop. Do NOT wipe.
            if (!vaultConfigured(selector)) {
                platformLogWarn(TAG, "undecryptable timestamp but no vault configured — not wiping (post-wipe residue)")
                return false
            }
            platformLogWarn(TAG, "Failed to decrypt timestamp — treating as expired")
            // Epoch 0 + no anchor: the wall-clock term alone makes this expired for
            // every real threshold, which is the fail-safe this branch has always
            // produced (it used to be a bare `0L` lastOpened).
            InactivityStamp(0L, InactivityPolicy.NO_UPTIME)
        }

        // Expiry decision — incl. the clock-rollback defense and the
        // monotonic term — is the SHARED InactivityPolicy so Android and iOS
        // can't diverge. elapsedRealtime alone cannot measure
        // inactivity (it resets on reboot), which is why it is a SECOND, additive
        // term next to the wall clock rather than a replacement for it — see
        // InactivityPolicy.isExpired.
        if (InactivityPolicy.isStampExpired(stamp, now, currentUptimeMs(), thresholdMs)) {
            platformLogWarn(TAG, "Inactivity threshold exceeded (or clock rolled back). Wiping all data.")
            // Drop the stale in-RAM Tink keyset BEFORE the crypto-erase so a RAM
            // capture right after the wipe can't recover it (mirrors
            // RunViewModel.performEmergencyWipe). CRITICAL: NO post-wipe storeTimestamp —
            // re-encrypting through the erased key is exactly the artifact-trio /
            // wipe-on-launch-loop bug (see the header + absent-branch notes).
            crypto.wipeKey()
            wipeAllData(context)
            return true
        }

        // Present + valid timestamp on a bare launch: do NOT re-stamp it. That reset
        // is what let a seized-but-not-vault-unlocked phone hold the vault alive
        // forever; the clock advances only on a real unlock.
        //
        // DO refresh the mtime-dilution probe (a separate key — see
        // header + refreshMtimeProbe) here on every bare launch that reaches this
        // point. It never touches KEY_LAST_OPENED, so it cannot reopen that.
        refreshMtimeProbe(prefs)
        return false
    }

    /**
     * Records this successful vault UNLOCK as the last-active time (encrypted).
     *
     * The inactivity dead-man's-switch is refreshed ONLY on a
     * real unlock — never on a bare app launch — so an adversary holding an
     * unlocked-but-not-vault-unlocked phone cannot keep the vault alive by tapping the
     * launcher icon. Mirrors iOS InactivityWipe.touch(), called only from the .opened
     * unlock/recovery branch. [crypto] is the caller's already-warm provider, so this
     * is a single in-RAM AEAD encrypt (storeTimestamp swallows transient failures).
     */
    fun recordUnlock(context: Context, crypto: CryptoProvider) {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        storeTimestamp(context, crypto, prefs, System.currentTimeMillis())
    }

    /**
     * True when a real vault exists by EITHER witness — the credential store
     * ([VaultSelector.isConfigured]) OR the filesystem ([VaultSelector.vaultFileExists],
     * an independent witness that doesn't share the store's failure mode). Gates every
     * post-wipe re-encryption: after a wipe both are false, so we never recreate the
     * crypto artifacts the wipe just destroyed.
     */
    private fun vaultConfigured(selector: VaultSelector): Boolean =
        try {
            selector.isConfigured() || selector.vaultFileExists()
        } catch (_: Exception) {
            false
        }

    @android.annotation.SuppressLint("ApplySharedPref")
    private fun storeTimestamp(
        context: Context,
        crypto: CryptoProvider,
        prefs: android.content.SharedPreferences,
        timestampMs: Long
    ) {
        try {
            // Seal the monotonic uptime anchor INSIDE the same AEAD blob as the
            // wall-clock stamp, so it is as unforgeable as the timestamp itself. See
            // currentUptimeMs / InactivityPolicy.formatStamp; a legacy vault gets its
            // first anchor here, on this write (migrate-on-write).
            val plaintext = InactivityPolicy
                .formatStamp(timestampMs, currentUptimeMs())
                .toByteArray(Charsets.UTF_8)
            val encrypted = crypto.encrypt(plaintext, AEAD_CONTEXT.toByteArray(Charsets.UTF_8))
            // commit(), NOT apply() — the ORDER alone is not enough, the two writes
            // must also be equally DURABLE. armInactivityMarker below goes through
            // putStringSync -> commit(), so with an async apply() here the marker
            // could reach disk while the timestamp was still only in the in-memory
            // map; a SIGKILL / power loss in that window left marker-present +
            // timestamp-absent on the next launch, which
            // absentTimestampIsDeletionTamper reads as deletion tamper and WIPES a
            // vault nobody touched (total loss). commit() returns only once the
            // blob is fsync'd, so the marker can never be more durable than the
            // thing it attests to. Matches PinAttemptsStore.write()'s
            // putStringSync-then-markEstablished exactly (its counter blob is
            // written synchronously for the same reason), and its blocking cost is
            // the same order as the pinAttempts.establishVerified() / Tink work the
            // unlock path already runs on this thread.
            if (!prefs.edit().putString(KEY_LAST_OPENED, encodeBase64(encrypted)).commit()) {
                // Durable write failed (full disk / IO error). Do NOT arm: an armed
                // marker with no blob behind it is exactly the false-tamper state
                // above. Nothing is armed, so the next storeTimestamp retries and
                // the vault stays intact meanwhile (fails toward NOT-tamper).
                platformLogWarn(TAG, "inactivity timestamp write failed — marker not armed")
                return
            }
            // Arm the anchor marker AFTER the timestamp blob is DURABLY written
            // above, mirroring PinAttemptsStore.write()'s counter-then-marker order —
            // a process death between the two writes can then only ever produce
            // "timestamp present, marker absent" (never armed with nothing to
            // anchor), so "marker present, timestamp absent" can only mean the
            // file was actually deleted afterward. Called from BOTH the initial
            // arm (checkAndWipeIfNeeded's absent-timestamp branch, gated on
            // vaultConfigured) and every real unlock (recordUnlock) — the latter
            // is what self-heals an upgrade install that had a timestamp but no
            // marker: its first post-upgrade unlock arms it going forward.
            armInactivityMarker(context)
        } catch (e: Exception) {
            // Encrypt failure (or any throw before the commit above) leaves BOTH
            // unwritten — never a marker without a timestamp.
            platformLogError(TAG, "Failed to encrypt timestamp", e)
        }
    }

    /**
     * Idempotent, best-effort "timestamp has been armed at least once"
     * marker write, in the fate-shared [ANCHOR_PREFS_NAME] store. Mirrors
     * PinAttemptsStore.markEstablished(): checks presence first so repeated
     * calls (every unlock) do not re-write, and never throws — a missed arm
     * only delays deletion-tamper detection to the next successful timestamp
     * write, never crashes or wipes the launch it runs on.
     *
     * PRECONDITION (load-bearing): call ONLY after [KEY_LAST_OPENED] has been
     * COMMITTED — see [storeTimestamp]. This store's putStringSync is durable
     * (commit()); arming it while the timestamp write is still an un-flushed
     * apply() is what makes an interrupted first arm look like deletion tamper.
     */
    private fun armInactivityMarker(context: Context) {
        try {
            val anchor = KeyValueStore(context, ANCHOR_PREFS_NAME)
            if (anchor.getString(INACTIVITY_ARMED_KEY) == null) {
                anchor.putStringSync(INACTIVITY_ARMED_KEY, "1")
            }
        } catch (_: Exception) {
            // Best-effort — see kdoc above.
        }
    }

    /**
     * Has the anchor marker been armed? A store-read failure is treated as
     * "absent" (fails toward NOT-tamper — same brick-safe direction as every
     * other absence probe on this path / PinAttemptsStore's own anchor read).
     */
    private fun inactivityMarkerArmed(context: Context): Boolean = try {
        KeyValueStore(context, ANCHOR_PREFS_NAME).getString(INACTIVITY_ARMED_KEY) != null
    } catch (_: Exception) {
        false
    }

    /**
     * Mtime-dilution probe (see header): writes [KEY_MTIME_PROBE] — a
     * throwaway random value, NOT a timestamp, and never read back by anything —
     * so inactivity_prefs.xml gets a genuine disk write (and therefore a fresh
     * mtime) on every bare launch that reaches here, not only on a real vault
     * unlock. A value that happens to be IDENTICAL to what's already stored would
     * risk SharedPreferences' own no-op change detection silently skipping the
     * disk write (it diffs the new value against the in-memory one before
     * deciding whether there's anything to flush) — a random 8-byte value is
     * different from whatever was there before with overwhelming probability, so
     * the write always actually happens. This widens what the file's mtime can be attributed to: "app opened
     * around this time" instead of "vault unlocked at this exact time". Does NOT
     * touch [KEY_LAST_OPENED], so the real-unlock-only guarantee is unaffected. Swallows
     * its own failures: this is a cosmetic best-effort refresh, never allowed to
     * affect the real wipe decision above it.
     *
     * commit(), NOT apply() (task #11, 2026-07-31). This one is cosmetic, but its
     * WRITE is not: apply() snapshots the whole `inactivity_prefs` map — probe
     * AND [KEY_LAST_OPENED] — and flushes it later, and this call is followed, on
     * the same thread and in the same `MainActivity.onCreate`, by the
     * orphaned-credential check that can run `WipeRoutine.wipePersistentState`
     * (MainActivity.kt: the inactivity check is line ~232, the orphan wipe line
     * ~266). `deleteSharedPreferences` neither cancels nor awaits that queued
     * flush, and `SharedPreferencesImpl.writeToFile` only short-circuits when the
     * file still EXISTS — so the flush would RE-CREATE inactivity_prefs.xml,
     * carrying the wiped install's encrypted last-active timestamp, dated after
     * the erasure. commit() lands it before the wipe, which then deletes it.
     * (iOS has no sibling here: its probe is a `UserDefaults.set` into a single
     * mutable domain dict, so the wipe's later `removeObject` + `synchronize`
     * always wins — there is no per-write snapshot to resurrect. Its ordering is
     * the reverse of Android's anyway: `runLaunchSecurityChecks` runs the orphan
     * wipe BEFORE the inactivity check.)
     *
     * Touches NEITHER of this file's two durability invariants: [storeTimestamp]
     * keeps its own checked commit() for [KEY_LAST_OPENED], and
     * [armInactivityMarker] still runs only after that returns true. The probe is
     * a different key, is never read back, and never gates the marker.
     */
    @android.annotation.SuppressLint("ApplySharedPref")
    private fun refreshMtimeProbe(prefs: android.content.SharedPreferences) {
        try {
            val nonce = ByteArray(8)
            java.security.SecureRandom().nextBytes(nonce)
            prefs.edit().putString(KEY_MTIME_PROBE, encodeBase64(nonce)).commit()
        } catch (_: Exception) {
            // Best-effort — see doc above.
        }
    }

    private fun wipeAllData(context: Context) {
        // Single source of truth — crypto-erases the Keystore master key
        // first, then deletes DBs + every prefs file (incl. the
        // pin_attempts_prefs, which this path used to leak).
        WipeRoutine.wipePersistentState(context)

        // ------------------------------------------------------------------
        // DELIBERATELY NOTHING AFTER THE WIPE. In particular: there is NO
        // relay-side push unregister (`DELETE /inbox/{id}/push`) on this path,
        // and re-adding one is a regression — do not.
        //
        // WHY. This is the ONE wipe path that fires while the user is ABSENT,
        // from MainActivity.onCreate, before RunViewModel / viewModelScope /
        // any transport exists. A relay DELETE therefore has to stand up its
        // OWN TorManager. A revision of this file (reverted 2026-07-30) did
        // exactly that, and it re-created post-wipe state:
        //   * It snapshotted the warm Tor cache, whose AEAD init REGENERATED the
        //     run_torcache_master_key Keystore alias and the
        //     run_torcache_keyset_prefs Tink keyset when absent, then wrote
        //     filesDir/tor_warm_cache.enc — all three destroyed moments earlier
        //     by WipeRoutine. No Tor teardown has ever touched that TOP-LEVEL
        //     blob (it sits outside tor_direct/), so nothing cleaned it up
        //     afterwards — and since 2026-08-01 an ordinary TorManager.stop()
        //     deletes nothing at all. (The warm
        //     cache is RETIRED as of 2026-07-31 — see LegacyTorWarmCache — so
        //     this exact resurrection is no longer reachable; the RULE below is
        //     not about the warm cache, it is about doing ANY work after a wipe.)
        //   * The result is a Keystore key, a Tink keyset file and an encrypted
        //     Tor guard/consensus blob all dated AFTER the wipe: standalone
        //     forensic proof Tor was used, on the one path where the user is
        //     not present to notice and re-wipe.
        //   * It also starts a fresh outbound .onion beacon from a device the
        //     app has just classified as abandoned, out of a detached
        //     CoroutineScope(Dispatchers.IO) with no retained Job, no
        //     lifecycle owner and no cancellation — racing any foreground
        //     TorManager, which sweeps stale sibling Tor dirs on start.
        //
        // WHAT COVERS IT INSTEAD. WipeRoutine.wipePersistentState calls
        // VendorPush.destroyLocalPushIdentity, whose deleteToken() invalidates
        // the FCM token AT GOOGLE — so the relay's stored `inboxId -> token`
        // row becomes a dead reference — and the inbox itself dies with the
        // vault. A marginal relay-side row deletion is not worth starting Tor
        // after a wipe. (The two USER-PRESENT paths keep their unregister:
        // RunViewModel fires it while the vault and transport are still alive,
        // BEFORE the wipe, so it stands up no new Tor and writes nothing.)
        // ------------------------------------------------------------------
    }
}

/**
 * Brick-safe deletion-tamper decision for
 * an ABSENT inactivity timestamp, extracted pure (mirrors
 * PinAttemptsStore.absentCounterIsTamper — same shape, same
 * rationale): TAMPER requires POSITIVE evidence the timestamp was previously
 * armed — the marker surviving while the timestamp blob is gone AND the vault
 * is still configured. An absent timestamp on a vault that was NEVER armed
 * (fresh provision, or an upgrade install mid-way through self-healing — see
 * [absentTimestampShouldEstablish]) must NEVER read as tamper.
 */
internal fun absentTimestampIsDeletionTamper(markerArmed: Boolean, vaultConfigured: Boolean): Boolean =
    markerArmed && vaultConfigured

/**
 * The establish-on-read complement of [absentTimestampIsDeletionTamper]:
 * an absent timestamp with NO marker on a configured vault is a genuine first
 * arm OR an install upgrading from a build that predates this marker (an
 * existing timestamp that just hasn't gone through a post-upgrade
 * [InactivityWipe] `storeTimestamp` call yet). ESTABLISH-ON-READ (write now +
 * arm the marker), NEVER wipe — ambiguous absence must never brick a vault.
 * The two functions are complements whenever [vaultConfigured] is true (which
 * is the only case either is consulted — see checkAndWipeIfNeeded).
 */
internal fun absentTimestampShouldEstablish(markerArmed: Boolean, vaultConfigured: Boolean): Boolean =
    !markerArmed && vaultConfigured

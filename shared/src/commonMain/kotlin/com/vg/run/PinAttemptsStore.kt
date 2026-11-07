package com.vg.run

// ---------------------------------------------------------------------------
// PinAttemptsStore — encrypted, tamper-detecting wrong-PIN counter.
//
// The plain UserDefaults / SharedPreferences integer that previously held
// pin_failed_attempts is trivially forgeable: a rooted device or a
// known-passcode iCloud/iTunes backup can write an arbitrary value.
//
// This wrapper encrypts a 4-byte counter with 8 bytes of random padding
// using the CryptoProvider AEAD with context "pin-attempts". Any MODIFIED
// value fails the GCM tag and surfaces as TamperException, which the unlock
// screens treat as adversarial behaviour and route to emergencyWipe().
//
// Brick-safe deletion defense (2026-07-23) for the CONSECUTIVE
// counter. Deleting the counter blob to reset the throttle is detected ONLY on
// POSITIVE evidence it was previously established, and a legacy / unmigrated /
// freshly-provisioned vault is NEVER wiped:
//  - The wipe fires iff the counter blob is ABSENT, the fate-shared "established"
//    MARKER is present, AND the vault is still configured (its DB-key wrap vlt_c
//    is present). Marker-survives-while-counter-gone is the deletion signature.
//  - An absent counter with NO marker on a configured vault is a legacy /
//    unmigrated / interrupted-provision vault → ESTABLISH-ON-READ (write 0 + arm
//    the marker), return 0, never wipe. This is the brick fix: an earlier version treated
//    vlt_c-present-with-counter-absent as tamper BY ITSELF and wiped legacy
//    vaults + interrupted provisions on their first launch.
//  - vlt_c-presence is NOT a tamper trigger on its own — only the AND-gate above.
//  Fate-sharing of the marker (so deleting ONLY the counter can't erase it):
//   - Android: the marker + vlt_c live in the SAME vault_selector_prefs FILE, so
//     deleting pin_attempts_prefs (the counter-deletion attack) leaves the marker → wipe;
//     deleting vault_selector_prefs destroys vlt_c so the vault won't open anyway.
//   - iOS: every KeyValueStore key is its own Keychain item, so the marker is
//     per-item deletable alongside the counter. Deleting the counter alone leaves
//     the marker → wipe; deleting BOTH counter + marker is a known limitation
//     (→ establish-on-read → reset to 0), bounded in depth by the Argon2id KDF
//     cost that actually gates decryption.
// See read()/readAbsentCounter()/markEstablished()/absentCounterShouldEstablish().
//
// KNOWN LIMITATIONS (do not overstate this control):
//  - A rollback to a captured OLDER (still-valid) blob passes AEAD on BOTH
//    platforms — in-place EDIT of prefs/Keychain items remains out of scope.
//    The marker stops the "delete the counter state" reset, not every
//    filesystem-write attack.
//  - Legacy / unmigrated / interrupted-provision vaults DO NOT wipe: an absent
//    counter with no marker on a configured vault ESTABLISHES on read (see
//    above), so a vault carried across the counter/marker introduction — or a
//    provision the process interrupted before the counter landed — self-heals to
//    count 0 on its first launch instead of self-wiping. This
//    replaced an earlier one-time migration-window wipe.
//  - More fundamentally, the counter only exists ON-DEVICE. The realistic
//    forensic attack extracts the device key + wrapped blobs and brute-forces
//    the PIN OFFLINE, where no counter ever runs. The real defenses there are
//    the KDF (Argon2id), the hardware auth-bound DB-key gate (Lever B), and a
//    high-entropy passphrase (Lever A). This counter is an on-device
//    rate-limit for casual/interactive guessing, not a brute-force boundary.
// ---------------------------------------------------------------------------

class PinAttemptsStore(
    private val store: KeyValueStore,
    private val crypto: CryptoProvider,
    // Fate-shared-with-the-vault store for the "counter established" marker.
    // MUST be a DIFFERENT physical store from [store] on any platform where the
    // counter store can be deleted independently of the vault (Android: pass
    // vault_selector_prefs). Defaults to [store] for iOS and the unit tests —
    // on iOS the marker is just another per-item-deletable Keychain item (no
    // file-level fate-sharing exists there), so iOS relies on [dbKeyWrapPresent]
    // below instead.
    private val anchorStore: KeyValueStore = store,
    // iOS: presence probe for the DB-key wrap item
    // (VaultStoreKeys.WRAPPED_DBKEY) — the iOS "vault configured" signal, the same
    // AND-gate role [vaultWrapKeyInAnchorStore] plays on Android. An absent counter
    // with the MARKER present while this reads true is the deletion signature
    // (→ wipe); with the marker ALSO absent it is establish-on-read (→ write 0,
    // never wipe). Deleting BOTH the counter and the per-item-deletable marker is
    // a known limitation (→ reset). null (Android/tests) leaves "configured" to
    // [vaultWrapKeyInAnchorStore]. The probe may throw KeyUnavailableException —
    // readAbsentCounter treats that as "absent" (fails toward not-tamper).
    private val dbKeyWrapPresent: (() -> Boolean)? = null,
    // The key under which the vault's DB-key wrap (VaultStoreKeys.WRAPPED_DBKEY /
    // vlt_c) lives INSIDE [anchorStore] — the "vault configured" signal read
    // straight from the fate-shared store (Android vault_selector_prefs) instead
    // of a second lambda. It is the AND-gate for BOTH the tamper decision (marker
    // present + configured → wipe) and establish-on-read (marker absent +
    // configured → establish, never wipe), NOT a tamper trigger by itself. Because
    // establish-on-read self-heals a provisioned-but-never-established vault, this
    // no longer depends on the provision-time [establishVerified] ordering. null
    // (iOS uses [dbKeyWrapPresent]; tests) leaves "configured" unsignalled. A
    // crypto-free presence check whose transient failure is treated as "absent".
    private val vaultWrapKeyInAnchorStore: String? = null,
    // Forward-clock defense: supplies an un-rollable monotonic time
    // sample so the rolling-window expiry can be judged against REAL elapsed
    // time, not the attacker-controlled wall clock — closing the forward-jump
    // reset (the forward sibling of the backward clamp defense). The value is
    // kernel uptime only — Android SystemClock.elapsedRealtime(), iOS
    // ProcessInfo.systemUptime — with [MonotonicSample.bootId] fixed to 0; a
    // reboot is detected as "uptime went backwards" (no shell-writable reboot id
    // is trusted). null (unwired / unit tests) or a transient
    // null keeps the historical wall-clock roll, just undefended until wired.
    private val monotonicNow: (() -> MonotonicSample?)? = null,
) {
    companion object {
        /**
         * UserDefaults / SharedPreferences key under which the encrypted
         * counter is written. Public so the platform wipe routines (iOS
         * IosAppController.emergencyWipe, iOS RunApp.wipeAllPersistentStateForTest,
         * Android RunViewModel.performEmergencyWipe) can reference exactly
         * the same string PinAttemptsStore writes to — see
         * IosUserDefaultsKeysTest for the regression guard.
         */
        const val STORAGE_KEY: String = "pin_failed_attempts_v2"

        /**
         * Key for the rolling-window cumulative wrong-PIN counter. Lives in the
         * SAME store as [STORAGE_KEY] (Android pin_attempts_prefs / iOS
         * UserDefaults) so the existing wipe routines clear it with no new
         * wipe-list entry. See [recordWrongAttemptInWindowAndCheckLimit].
         */
        const val WINDOW_STORAGE_KEY: String = "pin_failed_window_v1"

        /**
         * "Counter has been established" marker. Lives in
         * the [anchorStore] — on Android the fate-shared vault_selector_prefs
         * FILE, so deleting the counter store cannot erase it: an absent counter
         * WITH this marker set means the blob was deleted (tamper). On iOS the
         * marker is a per-item-deletable Keychain item (NOT fate-shared by
         * itself); the [dbKeyWrapPresent] probe supplies the real anchor there.
         * A plain boolean flag ("1"), not credential material, so it is stored
         * unencrypted. Cleared by every wipe (Android WipeRoutine deletes
         * vault_selector_prefs; iOS emergencyWipe kvDeleteAll clears the
         * Keychain), so a re-provisioned vault starts fresh.
         */
        const val ESTABLISHED_KEY: String = "pin_attempts_established_v1"

        /**
         * Brick-safe deletion defense: pure decisions for an ABSENT
         * counter blob, one copy for both platforms (commonTest-pinned — the
         * expect-class stores have no common fake seam). The two are mutually
         * exclusive; when the vault is NOT configured both are false (→ read 0).
         *
         * TAMPER (→ wipe) requires POSITIVE evidence the counter was once
         * established: the fate-shared "established" MARKER survives while the
         * counter blob is gone AND the vault is still configured (its DB-key wrap
         * is present). vlt_c-presence is NO LONGER a tamper trigger by itself —
         * that was an earlier bricking mechanism: a legacy / unmigrated vault has
         * vlt_c but no marker and no v2 counter, and MUST NOT read as tamper.
         */
        internal fun absentCounterIsTamper(established: Boolean, vaultConfigured: Boolean): Boolean =
            established && vaultConfigured

        /**
         * ESTABLISH-ON-READ (the brick fix): an absent counter with NO marker on a
         * CONFIGURED vault is a legacy / unmigrated / freshly- or interrupted-
         * provisioned vault — the read site establishes it now (writes count=0 and
         * arms the marker) and returns 0, NEVER wiping. Gated on [vaultConfigured]
         * so a post-wipe state (vlt_c gone) writes nothing (CRITICAL guard:
         * establish-on-read must never resurrect state after a wipe).
         */
        internal fun absentCounterShouldEstablish(established: Boolean, vaultConfigured: Boolean): Boolean =
            !established && vaultConfigured

        /**
         * Provision-time establishment loop, extracted pure
         * (commonTest-pinned — same seam rationale as [absentCounterIsTamper]):
         * try [writeCounter], then confirm via [readBack] that the freshly
         * written counter blob is durably present and decryptable (`0`), up to
         * [attempts] times. False = establishment could NOT be verified — the
         * provision must then FAIL rather than complete: completing would leave
         * the DB-key wrap present with counter state absent, which is EXACTLY
         * the counter-deletion signature, and the next launch's read() would
         * emergency-wipe the honest, freshly-provisioned vault.
         */
        internal fun runVerifiedEstablishment(
            attempts: Int = 4,
            writeCounter: () -> Boolean,
            readBack: () -> Int?,
        ): Boolean {
            repeat(attempts) {
                if (writeCounter() && readBack() == 0) return true
            }
            return false
        }

        /**
         * Hard cap on WRONG PIN entries within [WINDOW_MS], independent of the
         * 5-consecutive budget. A wipe fires on the MAX_WRONG_PER_DAY-th wrong
         * entry in the window. Set well above any plausible legitimate daily
         * mistyped-PIN count (a correct PIN never consumes the budget), but far
         * below the PBKDF2-throttled rate needed to brute-force a 6-digit PIN.
         */
        const val MAX_WRONG_PER_DAY: Int = 30

        /** Rolling window length: one day. */
        const val WINDOW_MS: Long = 24L * 60 * 60 * 1000
    }

    private val key = STORAGE_KEY
    private val ctx = "pin-attempts".encodeToByteArray()
    private val windowCtx = "pin-attempts-window".encodeToByteArray()

    /**
     * Returns 0 if no value was ever stored. Throws TamperException if a stored
     * value exists but cannot be decrypted (intentional tampering, or crypto-key
     * rotation that should be treated as untrusted state) — OR if the
     * blob is ABSENT while the fate-shared "established" marker survives AND the
     * vault is still configured, the counter-deletion signature. An absent counter
     * with NO marker on a configured vault is NOT tamper: it ESTABLISHES on read
     * (write 0 + arm the marker) and returns 0, so a legacy / unmigrated /
     * interrupted-provision vault is never wiped. See [readAbsentCounter].
     */
    @Throws(KeyUnavailableException::class, TamperException::class)
    fun read(): Int {
        val b64 = store.getString(key) ?: return readAbsentCounter()
        val bytes = try {
            crypto.decrypt(decodeBase64(b64), ctx)
        } catch (e: KeyUnavailableException) {
            throw e
        } catch (e: Exception) {
            throw TamperException("pin-attempts ciphertext failed AEAD verification")
        }
        if (bytes.size < 4) throw TamperException("pin-attempts payload too short")
        return decodeCounter(bytes)
    }

    /**
     * Swift-facing variant of [read] that mirrors the InactivityWipe.tryDecrypt
     * split so the iOS caller never has to introspect Kotlin exception types
     * across the bridge (a bare Swift `catch` cannot tell KeyUnavailableException
     * from TamperException, and folding both into a wipe destroyed data on a
     * transient Keychain glitch on an UNLOCKED device):
     *   - throws KeyUnavailableException → the device key is transiently
     *     unresolvable; the caller MUST defer (return without wiping). The stored
     *     count is intact and re-read once the key is available.
     *   - returns null → the key resolved but the ciphertext failed AEAD
     *     verification (genuine tamper / key rotation) → the caller wipes.
     *   - returns the count otherwise (0 if nothing stored).
     */
    @Throws(KeyUnavailableException::class)
    fun readOrNullOnTamper(): Int? = try {
        read()
    } catch (_: TamperException) {
        null
    }

    /**
     * Stores [count] encrypted with 8 bytes of length-hiding random pad.
     * Written synchronously: the increment must be durable
     * before the slow PIN evaluation runs, so a force-quit mid-evaluation
     * cannot discard the attempt and reset the brute-force budget.
     */
    fun write(count: Int) {
        require(count in 0..1_000_000) { "pin-attempts count out of range" }
        val payload = encodeCounter(count) + generateSecureRandom(8)
        store.putStringSync(key, encodeBase64(crypto.encrypt(payload, ctx)))
        // Mark the counter established AFTER the blob is durably written, so
        // "established" always implies "a blob was persisted at least once". If the
        // process dies between the two writes, next launch sees a PRESENT blob
        // (the marker is only consulted on the absent path) — never a false tamper.
        markEstablished()
    }

    /**
     * Decide what an ABSENT counter blob means, brick-safe.
     *  - MARKER present + vault CONFIGURED → the counter blob was deleted while
     *    its fate-shared marker survived → tamper (→ wipe).
     *  - MARKER absent + vault CONFIGURED → legacy / unmigrated / freshly- or
     *    interrupted-provisioned vault → ESTABLISH-ON-READ (write 0 + arm the
     *    marker) and return 0. NEVER wipes; this is the brick fix.
     *  - vault NOT configured (fresh install / post-wipe) → return 0, write
     *    nothing (so a post-wipe state, vlt_c gone, can never establish/wipe).
     * "Configured" = the vault's DB-key wrap is present, read from the iOS probe
     * ([dbKeyWrapPresent]) OR straight from the fate-shared [anchorStore] when the
     * caller names the wrap key ([vaultWrapKeyInAnchorStore]). All presence reads
     * are crypto-free; a transient failure is treated as "absent" (fails toward
     * NOT-tamper). The establish WRITE needs the device key, so a transient
     * KeyUnavailableException there DEFERS (return 0, nothing armed; retried on
     * the next read) — a transient key outage is never tamper and never a wipe.
     */
    private fun readAbsentCounter(): Int {
        val established = try {
            anchorStore.getString(ESTABLISHED_KEY) != null
        } catch (_: Exception) {
            false
        }
        val wrapPresent = try {
            dbKeyWrapPresent?.invoke() == true
        } catch (_: Exception) {
            false  // iOS contains() throws KeyUnavailableException transiently — defer
        }
        // The Android "vault configured" signal read straight from the fate-shared
        // [anchorStore] (vault_selector_prefs also holds VaultStoreKeys.WRAPPED_DBKEY, which the
        // attacker cannot delete without destroying the vault). A store read
        // failure is treated as "absent" so a transient outage DEFERS (→ 0).
        val wrapInAnchor = try {
            vaultWrapKeyInAnchorStore != null && anchorStore.getString(vaultWrapKeyInAnchorStore) != null
        } catch (_: Exception) {
            false
        }
        val configured = wrapPresent || wrapInAnchor
        if (absentCounterIsTamper(established, configured)) {
            throw TamperException("pin-attempts counter blob deleted after establishment (marker survived)")
        }
        if (absentCounterShouldEstablish(established, configured)) {
            // Legacy / unmigrated / interrupted-provision vault: no counter, no
            // marker, but the vault IS configured. Establish now so the FIRST real
            // attempt is measured from 0 and the deletion anchor arms — NEVER wipe.
            // Only reachable when configured==true, so a post-wipe state (vlt_c
            // gone) writes nothing (CRITICAL guard).
            try {
                write(0)  // counter blob first, then markEstablished() (write()'s order)
            } catch (_: KeyUnavailableException) {
                // Device key transiently gone — defer: nothing armed, return 0,
                // retried on the next read once the key is available.
            } catch (_: Exception) {
                // Best-effort: an establish-on-read write must never wipe or crash.
            }
        }
        return 0
    }

    /**
     * Idempotent, best-effort "counter established" marker in the fate-shared
     * anchor store. Written once (subsequent calls short-circuit on the read) and
     * synchronously, at provision-time reset() / the first wrong-attempt write() —
     * never after a wipe (the composition returns early once wiped), so it cannot
     * resurrect the credential file the way an async counter flush once did
     * (see RunViewModel). Never throws: a marker write must not crash or
     * wipe unlock — a transient failure just defers establishment to the next write.
     */
    private fun markEstablished() {
        try {
            if (anchorStore.getString(ESTABLISHED_KEY) == null) {
                anchorStore.putStringSync(ESTABLISHED_KEY, "1")
            }
        } catch (_: Exception) { /* best-effort; retried on the next write */ }
    }

    /**
     * Best-effort [write] that never throws on a transient key outage. Returns
     * true if the count was durably written, false if the device key was
     * unavailable (the write is skipped; the durable count keeps its prior
     * value). Use where the write is a non-critical counter adjustment that must
     * not crash or wipe — e.g. rolling back the pre-evaluation increment after an
     * UnlockResult.Error, which can now itself be caused by device-key
     * unavailability: a plain write() there would raise
     * KeyUnavailableException and, being non-@Throws to Swift, SIGABRT.
     */
    fun tryWrite(count: Int): Boolean = try {
        write(count)
        true
    } catch (_: KeyUnavailableException) {
        false
    }

    // Best-effort (tryWrite), NOT the throwing write(). reset() runs
    // after a SUCCESSFUL unlock (.opened); if the device key vanishes in the window
    // between the vault open and this reset, the throwing write() would raise
    // KeyUnavailableException across the non-@Throws Kotlin/Native → Swift boundary
    // → SIGABRT — same hazard the pre-eval and .error writes avoid with tryWrite.
    //
    // RETRY the best-effort clear. reset() runs immediately after a
    // successful unlock, so the device key was just available; a single transient
    // KeyUnavailable glitch that slipped the pre-eval count to MAX would otherwise
    // strand it and SELF-WIPE the vault on next launch DESPITE the correct PIN. A
    // few retries almost always land the clear while the key is still warm. (If all
    // fail, the key is genuinely down — next-launch readAttempts then also throws
    // KeyUnavailable and DEFERS the wipe, so the stranded count only bites in the
    // vanishingly-narrow key-drops-then-returns race.)
    fun reset() { repeat(4) { if (tryWrite(0)) return } }

    /**
     * VERIFIED counter establishment for PROVISION. Unlike
     * [reset] (best-effort — tryWrite swallows a device-key outage and reset
     * returns Unit), this confirms by READ-BACK that the counter blob actually
     * persisted, and reports failure so the caller can ABORT the provision
     * (ok=false, retryable) instead of completing with counter state absent —
     * on iOS that completed state (DB-key wrap present, counter + marker
     * absent) is indistinguishable from the counter-deletion attack and would
     * emergency-wipe the honest vault on the next launch.
     *
     * Ordering guarantees relied on by the provision flows:
     *  - inside [write], the counter blob lands BEFORE the marker, so no
     *    interruption of this call can produce marker-present-with-counter-
     *    absent (Android's tamper rule);
     *  - the iOS caller (IosAppController) runs this BEFORE
     *    provisionCredentialAndVault persists the DB-key wrap, so no
     *    interruption can produce wrap-present-with-counter-absent either
     *    (the iOS tamper rule). See the interleaving enumeration there.
     * Never throws — every failure (outage, silent store, tamper read) is a
     * failed attempt; reached from non-@Throws bridge flows.
     */
    fun establishVerified(): Boolean = runVerifiedEstablishment(
        writeCounter = { try { tryWrite(0) } catch (_: Exception) { false } },
        // Presence check FIRST: a bare read() returns 0 via readAbsentCounter()
        // in the honest pre-wrap provision state (counter+marker+wrap all
        // absent), which would falsely "verify" a silently-rejected iOS kvPut
        // (fail-closed log-only store). The blob must exist AND
        // decrypt to 0.
        readBack = { try { if (store.getString(key) == null) null else read() } catch (_: Exception) { null } },
    )

    /**
     * Records one WRONG PIN entry in a rolling 24h window and returns true if
     * the window count has reached [MAX_WRONG_PER_DAY] — in which case the
     * caller MUST trigger an emergency wipe.
     *
     * Backstop to the 5-consecutive auto-wipe: a successful
     * unlock resets the consecutive counter via [reset], so an attacker could
     * otherwise alternate one correct unlock (reset) <-> four wrong guesses
     * indefinitely and never trip the 5-strike wipe. This window counter is NOT
     * reset by any unlock (only by the daily roll or an emergency wipe), so it
     * bounds total PIN probing per day. Only WRONG entries count — a correct
     * PIN never consumes the budget — so a heavy legitimate user is never
     * falsely wiped. Call ONLY on the Denied path. Written synchronously.
     *
     * Fail-open by design: this is a SECONDARY cap behind the consecutive
     * counter, which is the strict tamper authority ([read] throws
     * TamperException -> wipe, and is evaluated first on every attempt). So this
     * must NEVER wipe and NEVER throw — an uncaught Kotlin exception here would
     * SIGABRT the iOS main actor. Failure handling:
     *  - KeyUnavailableException (device locked / key transiently unreadable):
     *    DEFER. Return false and leave the blob untouched — a valid, in-window
     *    count must not be clobbered just because the key was momentarily gone.
     *  - present-but-undecryptable blob (tamper / key rotation): trade-off, fail OPEN —
     *    reset to a fresh window. This lets a FILESYSTEM-WRITE adversary reset
     *    the daily count, but an attacker without the key cannot corrupt an
     *    encrypted blob, and hardening this to wipe would risk spurious data
     *    loss (differs deliberately from [ChangePinAttemptStore],
     *    which is the ONLY bound on its flow and so stays strict).
     */
    fun recordWrongAttemptInWindowAndCheckLimit(): Boolean {
        val now = currentTimeMillis()
        val nowMono = try { monotonicNow?.invoke() } catch (_: Exception) { null }
        val prior: WindowState? = try {
            readWindowState() // (0,0,null) when no blob yet; throws on locked key / corrupt blob
        } catch (e: KeyUnavailableException) {
            return false // device locked — defer, do NOT overwrite a possibly-valid blob
        } catch (_: Exception) {
            null // present-but-corrupt — fail open (reset below), never wipe/throw
        }
        val newStart: Long
        val newCount: Int
        val newMono: MonotonicSample?
        if (prior == null) {
            newStart = now; newCount = 1; newMono = nowMono
        } else {
            // A roll past the window resets the count. Two clock defenses:
            //  - BACKWARD (now < windowStart): clamp the start down to now
            //    but KEEP the count, so rolling back between guesses can't neuter
            //    the cap.
            //  - FORWARD: [windowRolled] judges the roll against the
            //    un-rollable monotonic sample when one is available, so advancing
            //    the wall clock past WINDOW_MS no longer zeroes the count.
            val rolled = windowRolled(prior.windowStart, now, WINDOW_MS, prior.mono, nowMono)
            newStart = if (rolled) now else minOf(prior.windowStart, now)
            newCount = (if (rolled) 0 else prior.count) + 1
            // Re-anchor the monotonic reference only when the window (re)starts or
            // when migrating a legacy blob that had none; otherwise preserve the
            // window-START sample so elapsed-since-start keeps growing. With no
            // fresh sample, keep whatever anchor we had.
            newMono = when {
                nowMono == null -> prior.mono
                rolled || prior.mono == null -> nowMono
                else -> prior.mono
            }
        }
        try { writeWindowState(newStart, newCount, newMono) } catch (_: Exception) {}
        return newCount >= MAX_WRONG_PER_DAY
    }

    /**
     * Read-only check of whether the 24h wrong-PIN WINDOW cap has
     * ALREADY been reached, for the launch fast-path. The launch check previously
     * re-read only the 5-consecutive counter, so a force-quit between the durable
     * window write and the wipe could strand an already-maxed window
     * (count == MAX_WRONG_PER_DAY) unchecked until the next LIVE wrong attempt —
     * one guess of slack per force-quit. Mirrors [read]'s failure handling:
     * throws [KeyUnavailableException] on a locked/transient key (caller DEFERS);
     * returns false on a corrupt blob (fail-open, matching
     * [recordWrongAttemptInWindowAndCheckLimit]) or an already-rolled window.
     * Read-only — never records an attempt.
     */
    @Throws(KeyUnavailableException::class)
    fun windowLimitReached(): Boolean {
        val prior = try {
            readWindowState()
        } catch (e: KeyUnavailableException) {
            throw e
        } catch (_: Exception) {
            return false // present-but-corrupt — fail open (matches the record path)
        }
        val now = currentTimeMillis()
        val nowMono = try { monotonicNow?.invoke() } catch (_: Exception) { null }
        // Recompute the roll from the same monotonic-aware rule as the
        // record path, so a forward wall-clock jump no longer clears the launch
        // fast-path (which previously re-derived `rolled` from the wall clock and
        // stopped firing the moment the clock moved forward).
        val rolled = windowRolled(prior.windowStart, now, WINDOW_MS, prior.mono, nowMono)
        return !rolled && prior.count >= MAX_WRONG_PER_DAY
    }

    // payload layout: windowStart(8 BE) ‖ count(4 BE) [‖ monoElapsedMs(8 BE) ‖
    // bootId(8 BE)] ‖ randomPad(8) — mirrors ChangePinAttemptStore so the two
    // windowed counters share an on-disk shape. The monotonic anchor block is
    // OPTIONAL: legacy 20-byte blobs (no anchor) still decode, migrated to the
    // 36-byte shape on the next write (backward compatibility).
    private fun readWindowState(): WindowState {
        val b64 = store.getString(WINDOW_STORAGE_KEY) ?: return WindowState(0L, 0, null)
        val bytes = crypto.decrypt(decodeBase64(b64), windowCtx)
        if (bytes.size < 12) throw IllegalStateException("pin-window payload too short")
        val windowStart = decodeLong(bytes, 0)
        val count = decodeCounter(bytes.copyOfRange(8, 12))
        val mono = if (bytes.size >= 28) MonotonicSample(decodeLong(bytes, 12), decodeLong(bytes, 20)) else null
        return WindowState(windowStart, count, mono)
    }

    private fun writeWindowState(windowStart: Long, count: Int, mono: MonotonicSample?) {
        require(count in 0..1_000_000) { "pin-window count out of range" }
        val head = encodeLong(windowStart) + encodeCounter(count)
        val anchor = if (mono != null) encodeLong(mono.elapsedRealtimeMs) + encodeLong(mono.bootId) else ByteArray(0)
        val payload = head + anchor + generateSecureRandom(8)
        store.putStringSync(WINDOW_STORAGE_KEY, encodeBase64(crypto.encrypt(payload, windowCtx)))
    }

    class TamperException(message: String) : RuntimeException(message)
}

/**
 * An un-rollable elapsed-time sample. [elapsedRealtimeMs] is a monotonic
 * uptime clock the user cannot wind (Android `SystemClock.elapsedRealtime()`,
 * iOS `ProcessInfo.processInfo.systemUptime`); it resets to ~0 on reboot.
 * [windowRolled] detects a reboot as "uptime went BACKWARDS" and safely falls
 * back to the wall clock — so no separate reboot id is needed. [bootId] is
 * therefore VESTIGIAL and fixed to 0 on both platforms: the original Android
 * source (`Settings.Global.BOOT_COUNT`) was adb/shell-writable with no root
 * (WRITE_SECURE_SETTINGS), so trusting a bootId match let an attacker forge the
 * reboot signal and force the wall-clock fallback WITHOUT rebooting. The field is retained for on-disk blob-layout compatibility
 * (old 36-byte blobs still decode); [windowRolled] no longer consults it.
 */
class MonotonicSample(val elapsedRealtimeMs: Long, val bootId: Long)

/** Decoded rolling-window state: wall-clock start, count, and the optional
 *  monotonic anchor sampled when the window started (null for legacy blobs). */
internal class WindowState(val windowStart: Long, val count: Int, val mono: MonotonicSample?)

/**
 * The pure "has the rolling window expired?" decision, shared by the
 * wrong-PIN and change-PIN counters (commonTest-pinned; the stores are expect
 * classes with no common fake seam).
 *
 * UPTIME MOVED FORWARD (both samples present, uptime not gone backwards): the
 * monotonic delta is the EXACT, un-rollable elapsed time, so it governs the roll.
 * This is the defense's teeth: the attack — advance the wall clock +25h and
 * RELAUNCH THE APP (same boot; `elapsedRealtime` persists across an app restart)
 * — can no longer reset the window, because the monotonic delta still reads only
 * minutes. No bootId is consulted: the original
 * Android bootId came from the shell-writable `Settings.Global.BOOT_COUNT`, so an
 * attacker could forge a bootId mismatch to force the wall-clock fallback WITHOUT
 * rebooting. Kernel uptime is not writable, so trusting a forward uptime delta
 * directly removes that lever.
 *
 * OTHERWISE (no monotonic reference — unwired, a transient sample failure, a
 * legacy blob — OR uptime went BACKWARDS, which is exactly a REBOOT resetting
 * `elapsedRealtime`): fall back to the wall clock. A reboot genuinely destroys
 * the anchor, so we cannot measure across it; using the wall clock here (rather
 * than holding the count forever) avoids false-wiping a legitimate reboot-heavy
 * user, and a reboot drops the device to the much harder BFU state, so it is not
 * a cheap way to launder a forward jump. The caller's `minOf(windowStart, now)`
 * clamp still defends the BACKWARD direction on this path.
 */
internal fun windowRolled(
    windowStartWall: Long,
    nowWall: Long,
    windowMs: Long,
    storedMono: MonotonicSample?,
    nowMono: MonotonicSample?,
): Boolean {
    if (storedMono != null && nowMono != null &&
        nowMono.elapsedRealtimeMs >= storedMono.elapsedRealtimeMs
    ) {
        return nowMono.elapsedRealtimeMs - storedMono.elapsedRealtimeMs >= windowMs
    }
    return windowStartWall <= 0L || nowWall - windowStartWall >= windowMs
}

internal fun encodeCounter(count: Int): ByteArray = byteArrayOf(
    (count ushr 24).toByte(),
    (count ushr 16).toByte(),
    (count ushr 8).toByte(),
    count.toByte(),
)

internal fun decodeCounter(bytes: ByteArray): Int =
    ((bytes[0].toInt() and 0xFF) shl 24) or
    ((bytes[1].toInt() and 0xFF) shl 16) or
    ((bytes[2].toInt() and 0xFF) shl 8)  or
     (bytes[3].toInt() and 0xFF)

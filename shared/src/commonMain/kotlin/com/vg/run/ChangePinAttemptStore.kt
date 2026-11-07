package com.vg.run

// ---------------------------------------------------------------------------
// ChangePinAttemptStore — encrypted, tamper-detecting daily change-PIN counter.
//
// The change-PIN flow is deliberately exempt from the unlock-screen 5-attempt
// auto-wipe (the user is already authenticated inside the vault). That leaves it
// as an otherwise penalty-free channel for probing the PIN: every change-PIN
// attempt is gated by a current-PIN check (verifyCredential), and an attacker
// could iterate candidate PINs through it. The
// CONFLICT oracle was already removed and a 5s floor added, but neither bounds
// the *number* of attempts. This counter does: it records each change-PIN
// credential operation in a rolling 24h window and signals an emergency wipe
// once MAX_PER_DAY is reached.
//
// Mirrors PinAttemptsStore: a 4-byte counter (plus an 8-byte window-start
// timestamp and 8 bytes of random pad) is AEAD-encrypted with the
// CryptoProvider under context "change-pin-attempts". Any tampering fails the
// GCM tag and is treated as adversarial (→ wipe). The encrypted blob lives in
// the same store as the wrong-PIN counter so it is removed by the same wipe
// routines (Android pin_attempts_prefs; iOS IosUserDefaultsKeys.all).
// ---------------------------------------------------------------------------

class ChangePinAttemptStore(
    private val store: KeyValueStore,
    private val crypto: CryptoProvider,
    // Deletion → fail closed: a store fate-shared with the vault that
    // also holds the DB-key wrap ([vaultWrapKeyInAnchorStore]). On Android pass
    // vault_selector_prefs; defaults to [store] (iOS single-store / tests).
    private val anchorStore: KeyValueStore = store,
    // Key of the DB-key wrap inside [anchorStore] (VaultStoreKeys.WRAPPED_DBKEY).
    // The "vault configured" signal — the AND-gate for the deletion wipe, NOT a
    // trigger by itself. An absent counter is a DELETION (→ wipe) only when the
    // fate-shared [ESTABLISHED_KEY] marker ALSO survives while the wrap is present;
    // an absent counter with NO marker on a configured vault is a legacy /
    // pre-anchor / first-ever change-PIN → establish-on-read, never wipe.
    // null (default) leaves "configured" unsignalled (marker-only).
    private val vaultWrapKeyInAnchorStore: String? = null,
    // Forward-clock defense: un-rollable monotonic sample so the 100/day
    // cap's window roll is judged against real elapsed time, not the wall clock
    // (see [MonotonicSample] / [windowRolled]). null keeps the wall-clock roll.
    private val monotonicNow: (() -> MonotonicSample?)? = null,
) {
    companion object {
        const val STORAGE_KEY: String = "change_pin_attempts_v1"

        /**
         * "Counter established" marker in the fate-shared [anchorStore]
         * (Android vault_selector_prefs / iOS the Keychain KV store holding vlt_c),
         * mirroring PinAttemptsStore.ESTABLISHED_KEY. It distinguishes "counter
         * deleted after establishment" (marker survives + vault configured → wipe)
         * from "counter never established" (legacy / pre-anchor / first-ever
         * change-PIN → establish-on-read, never wipe). A plain "1" flag, not
         * credential material; cleared by every wipe with the rest of the store /
         * file (Android WipeRoutine deletes vault_selector_prefs; iOS kvDeleteAll
         * clears the Keychain).
         */
        const val ESTABLISHED_KEY: String = "change_pin_attempts_established_v1"

        /** A wipe is triggered on the MAX_PER_DAY-th attempt within the window. */
        const val MAX_PER_DAY: Int = 100

        /** Rolling window length: one day. */
        const val WINDOW_MS: Long = 24L * 60 * 60 * 1000
    }

    private val ctx = "change-pin-attempts".encodeToByteArray()

    /**
     * Records one change-PIN credential operation and returns true if the
     * rolling-24h count has reached [MAX_PER_DAY] — in which case the caller
     * MUST trigger an emergency wipe. The window resets automatically once
     * [WINDOW_MS] has elapsed (or the clock jumps backwards). Written
     * synchronously so a force-quit cannot discard the increment and reset the
     * budget. A counter that fails AEAD verification on a RESOLVABLE key
     * (tampered, or written under a since-rotated crypto key) is adversarial and
     * returns true, mirroring PinAttemptsStore.
     *
     * Throws [KeyUnavailableException] when the device key is transiently
     * unreadable (locked keybag / transient Keychain error): the counter can be
     * neither read nor written, so the caller MUST DEFER — never wipe on a
     * transient. Folding this into "return true" (the old behaviour) destroyed
     * the vault on a glitch. Mirrors PinAttemptsStore.read(); @Throws makes the
     * exception catchable in Swift rather than terminating the process.
     */
    @Throws(KeyUnavailableException::class)
    fun recordAttemptAndCheckLimit(): Boolean {
        val now = currentTimeMillis()
        val nowMono = try { monotonicNow?.invoke() } catch (_: Exception) { null }
        val prior: WindowState? = try {
            readState() // null when the blob is absent; throws on locked key / corrupt blob
        } catch (e: KeyUnavailableException) {
            throw e // transient key — caller defers, NEVER wipe
        } catch (_: Exception) {
            return true // tampered / undecryptable on a resolvable key → adversarial → wipe
        }

        if (prior == null) {
            // Brick-safe: an absent counter is a DELETION (→ wipe) only
            // on POSITIVE evidence of prior establishment — the fate-shared MARKER
            // survives while the vault is still configured (its DB-key wrap present).
            // Otherwise (marker absent — a legacy / pre-anchor / first-ever
            // change-PIN, or a not-yet-configured install) it ESTABLISHES on this
            // attempt and NEVER wipes, so a pre-existing
            // vault's first-ever change-PIN does not emergency-wipe (iOS never
            // re-establishes outside provision). All presence reads are crypto-free;
            // a transient failure → "absent" → fails toward NOT wiping. Trade-off:
            // deleting BOTH counter + marker re-establishes the counter,
            // bounded in depth by the Argon2id KDF cost.
            val established = try {
                anchorStore.getString(ESTABLISHED_KEY) != null
            } catch (_: Exception) {
                false
            }
            val configured = try {
                vaultWrapKeyInAnchorStore != null && anchorStore.getString(vaultWrapKeyInAnchorStore) != null
            } catch (_: Exception) {
                false
            }
            if (established && configured) return true   // counter deleted after establishment → wipe
            writeState(now, 1, nowMono)                  // records this attempt AND arms the marker
            return 1 >= MAX_PER_DAY
        }

        // Roll defenses mirror PinAttemptsStore: BACKWARD via the minOf clamp
        // — keep the count so rolling the clock back can't neuter
        // it; FORWARD via the monotonic-aware [windowRolled] so advancing
        // the wall clock past WINDOW_MS no longer zeroes this 100/day cap — the
        // change-PIN flow's only numeric bound (it's exempt from the 5-attempt wipe).
        val rolled = windowRolled(prior.windowStart, now, WINDOW_MS, prior.mono, nowMono)
        val baseStart = if (rolled) now else minOf(prior.windowStart, now)
        val baseCount = if (rolled) 0 else prior.count
        val newMono = when {
            nowMono == null -> prior.mono
            rolled || prior.mono == null -> nowMono
            else -> prior.mono
        }

        val newCount = baseCount + 1
        writeState(baseStart, newCount, newMono)
        return newCount >= MAX_PER_DAY
    }

    /**
     * Write an initial zero-count window (+ arm the [ESTABLISHED_KEY]
     * marker, via [writeState]) at PROVISION time as an OPTIMISATION, so a
     * provisioned vault already has the counter before the first change-PIN.
     * Correctness no longer depends on it: [recordAttemptAndCheckLimit] itself
     * establishes-on-read (marker absent → record + arm, never wipe), so a
     * legacy / pre-anchor vault — or a provision the process interrupted before
     * this ran — self-heals on the first change-PIN instead of wiping.
     * Idempotent — a no-op once established; defers on a transient
     * locked-keybag error (retried on the next vault open).
     */
    fun establish() {
        val already = try {
            readState() != null
        } catch (_: KeyUnavailableException) {
            return // transient — retry on next open
        } catch (_: Exception) {
            return // corrupt blob — recordAttemptAndCheckLimit handles it
        }
        if (already) return
        val mono = try { monotonicNow?.invoke() } catch (_: Exception) { null }
        writeState(currentTimeMillis(), 0, mono)
    }

    /**
     * Idempotent, best-effort deletion marker in the fate-shared
     * [anchorStore] (mirrors PinAttemptsStore.markEstablished). Written once
     * (subsequent calls short-circuit on the read) after the counter blob lands,
     * so "marker present" always implies "a counter blob was durably written".
     * Never throws — a marker write must not crash or wipe a change-PIN; a
     * transient failure is retried on the next durable write.
     */
    private fun markEstablished() {
        try {
            if (anchorStore.getString(ESTABLISHED_KEY) == null) {
                anchorStore.putStringSync(ESTABLISHED_KEY, "1")
            }
        } catch (_: Exception) { /* best-effort; retried on the next write */ }
    }

    /** Clears the counter (e.g. tests). Production relies on the daily roll. */
    // Block body, not an expression body: [KeyValueStore.remove] returns a
    // confirmation Boolean now, and this stays Unit (it is also exported to
    // Swift, where the return type is part of the selector).
    fun reset() { store.remove(STORAGE_KEY) }

    // payload layout: windowStart(8) ‖ count(4) [‖ monoElapsedMs(8) ‖ bootId(8)]
    // ‖ randomPad(8). The monotonic anchor block is OPTIONAL — legacy 20-byte
    // blobs (no anchor) still decode and are migrated to the 36-byte shape on the
    // next write (backward compatibility). Returns null when absent.
    private fun readState(): WindowState? {
        val b64 = store.getString(STORAGE_KEY) ?: return null
        val bytes = crypto.decrypt(decodeBase64(b64), ctx)
        if (bytes.size < 12) throw IllegalStateException("change-pin counter payload too short")
        val windowStart = decodeLong(bytes, 0)
        val count = decodeCounter(bytes.copyOfRange(8, 12))
        val mono = if (bytes.size >= 28) MonotonicSample(decodeLong(bytes, 12), decodeLong(bytes, 20)) else null
        return WindowState(windowStart, count, mono)
    }

    private fun writeState(windowStart: Long, count: Int, mono: MonotonicSample?) {
        require(count in 0..1_000_000) { "change-pin count out of range" }
        val head = encodeLong(windowStart) + encodeCounter(count)
        val anchor = if (mono != null) encodeLong(mono.elapsedRealtimeMs) + encodeLong(mono.bootId) else ByteArray(0)
        val payload = head + anchor + generateSecureRandom(8)
        store.putStringSync(STORAGE_KEY, encodeBase64(crypto.encrypt(payload, ctx)))
        // Arm the fate-shared deletion marker AFTER the counter blob
        // lands, so "marker present" always implies "a counter blob was durably
        // written". A later deletion of the counter alone leaves the marker →
        // detected as tamper on the next read.
        markEstablished()
    }
}

// Shared with PinAttemptsStore's rolling-window wrong-PIN counter.
internal fun encodeLong(v: Long): ByteArray =
    ByteArray(8) { i -> (v ushr (56 - i * 8)).toByte() }

internal fun decodeLong(b: ByteArray, off: Int): Long {
    var r = 0L
    for (i in 0 until 8) r = (r shl 8) or (b[off + i].toLong() and 0xFF)
    return r
}

package com.vg.run

// ---------------------------------------------------------------------------
// SealedPref — the device-key AEAD envelope for PRE-UNLOCK preference values
// that feed a SECURITY decision.
//
// WHY THIS EXISTS. `VaultSelector` has carried this shape since 2026-07-13
// for `vlt_m` / `vlt_lvl` / `vlt_abk` / `vlt_rp`: a value that must
// be readable BEFORE the vault is unlocked cannot be wrapped under the PIN, so
// it is wrapped under the DEVICE key with a fixed per-slot AEAD context, and the
// READ reports whether it came out of a successful decrypt. Two preferences
// outside that class turned out to steer security decisions from PLAINTEXT
// storage that anyone able to write the app's files can choose:
//
//   • The Debug-mode consent flag (Android `debug_mode_prefs`). A planted
//     `"1"` starts redacted diagnostic uploads in a RELEASE build.
//   • The `NotificationLevel` opt-in, the sole gate on minting a vendor
//     push identity (FCM/APNs/UnifiedPush) at every launch/unlock. Registration
//     needs no OS prompt, so a plant is invisible.
//
// Those two live in their own stores (not `vault_selector_prefs`), so they
// cannot reuse `VaultSelector`'s private helpers — this file is the same
// primitive, extracted so both can consume it without widening that class's
// surface. It deliberately does NOT re-implement the legacy-cleartext tolerance
// `readSelectorMetaRaw` has: a value that did not decrypt is reported as
// UNAUTHENTICATED and every consumer here fails toward OFF.
//
// THE FAIL DIRECTIONS, stated once:
//   • [SealedPrefState.PROVEN]          — an AEAD decrypt under the slot's own
//                                         context succeeded. The ONLY state a
//                                         security decision may act on.
//   • [SealedPrefState.ABSENT]          — nothing stored. Means "off"/"never
//                                         consented", never tamper.
//   • [SealedPrefState.UNAUTHENTICATED] — something is stored that is not our
//                                         blob (a plant, a legacy plaintext
//                                         value, a damaged blob). Reads as OFF.
//   • [SealedPrefState.UNREADABLE]      — the device key is transiently
//                                         unavailable (locked keybag, Android
//                                         `setUnlockedDeviceRequired(true)` on a
//                                         locked screen, a Keystore hiccup).
//                                         DEFER: never a wipe, never a decision.
//
// UNREADABLE is a real, ORDINARY state for these two values, not an edge case:
// the Android device key is minted with `setUnlockedDeviceRequired(true)` and
// the iOS one with `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`, so a
// process started by a push wake on a LOCKED phone cannot decrypt anything.
// That is why neither consumer moved its locked-screen paths onto this
// primitive — see the notes in [DebugMode] and [NotificationLevelStore].
//
// WHAT THIS PRIMITIVE DOES *NOT* GIVE YOU: FRESHNESS. The AAD binds the SLOT
// NAME only, so every blob this device ever sealed for a slot decrypts forever
// under the same device key. An operator who images the filesystem, waits for
// the user to change the setting, and restores the OLD blob has replayed a
// legitimate value — [SealedPrefState.PROVEN] cannot tell that apart from the
// current one. Freshness needs a monotonic counter the attacker cannot rewind,
// i.e. one stored somewhere they cannot write:
//
//   • [NotificationLevelStore] binds an EPOCH held in the ENCRYPTED VAULT and
//     accepts a blob only when its epoch matches (see its VAULT_MARKER_KEY).
//   • [DebugMode] deliberately does NOT (known limitation): it
//     has no vault latch (there is no migration to latch, and the flag must be
//     readable before any vault is open). The exposure is bounded — a replay
//     there can only restore a consent THIS DEVICE genuinely sealed at some
//     point, i.e. re-enable diagnostic uploads the user once asked for; it
//     cannot forge one that never existed, and the uploads are redacted by
//     [DebugLogRedactor] either way. Do not copy that exemption to a new slot
//     without re-deciding it.
// ---------------------------------------------------------------------------

/**
 * The two [CryptoProvider] operations a sealed preference needs, as an interface
 * commonTest can implement.
 *
 * [CryptoProvider] is an `expect class` whose actuals need a platform handle (an
 * Android `Context`, the iOS Keychain bridge), so commonTest cannot construct
 * one — the same constraint [DebugModeStore] documents. Keeping the seam this
 * narrow also keeps the fake honest: a test cipher that "decrypts" anything is
 * indistinguishable from the real one only if it is fed the real contexts.
 */
internal interface DeviceKeyCipher {
    /** @throws KeyUnavailableException on a transient device-key outage. */
    fun seal(plaintext: ByteArray, context: ByteArray): ByteArray

    /** @throws KeyUnavailableException on a transient device-key outage. */
    fun open(ciphertext: ByteArray, context: ByteArray): ByteArray
}

/** Adapts the platform device key. */
internal fun CryptoProvider.asDeviceKeyCipher(): DeviceKeyCipher {
    val self = this
    return object : DeviceKeyCipher {
        override fun seal(plaintext: ByteArray, context: ByteArray): ByteArray =
            self.encrypt(plaintext, context)

        override fun open(ciphertext: ByteArray, context: ByteArray): ByteArray =
            self.decrypt(ciphertext, context)
    }
}

/** Provenance of a [SealedPref.open] result. See the file header for the fail directions. */
internal enum class SealedPrefState {
    PROVEN,
    ABSENT,
    UNAUTHENTICATED,
    UNREADABLE,
}

/**
 * A sealed-preference read. [value] is non-null ONLY for
 * [SealedPrefState.PROVEN] — an unauthenticated value is deliberately never
 * surfaced, so no caller can accidentally consume a planted token the way the
 * old legacy-cleartext fallback allowed.
 */
internal class SealedPrefRead(val value: String?, val state: SealedPrefState) {
    val proven: Boolean get() = state == SealedPrefState.PROVEN
}

internal object SealedPref {

    /**
     * Fixed plaintext length before the AEAD, so the (length-preserving)
     * AES-GCM ciphertext is a CONSTANT size regardless of the token — the same
     * rule `vlt_m`/`vlt_lvl` follow, and for the same reason: without
     * it `"off"` (3 B) and `"unified_push"` (12 B) are distinguishable at rest
     * with no device key and no decryption. Every token these two consumers
     * store is short ASCII and never contains a NUL, so the padding is
     * unambiguous and reversible.
     *
     * 32, not 16: [NotificationLevelStore] now seals `"<level>:<epoch>"` (the
     * replay binding below), and the padding has to hide the epoch's digit
     * count as well as the level. Reads are unaffected by the change — [unpad]
     * strips trailing NULs whatever the length was.
     */
    const val PADDED_LEN: Int = 32

    /** Fixed AEAD context binding a sealed value to ONE storage slot. */
    internal fun context(slot: String): ByteArray = slot.encodeToByteArray()

    /**
     * Device-key-seal [value] into the base64 blob persisted at [slot]'s key.
     * Propagates [KeyUnavailableException] so a caller can tell "not written
     * yet" from "written wrong".
     */
    fun seal(cipher: DeviceKeyCipher, slot: String, value: String): String {
        val raw = value.encodeToByteArray()
        check(raw.size <= PADDED_LEN) { "sealed-pref token too long to pad" }
        return encodeBase64(cipher.seal(raw + ByteArray(PADDED_LEN - raw.size), context(slot)))
    }

    /**
     * Read a sealed value back. Never throws: every failure is classified, and
     * the classification is the whole point — see the file header.
     */
    fun open(cipher: DeviceKeyCipher, slot: String, raw: String?): SealedPrefRead {
        if (raw == null) return SealedPrefRead(null, SealedPrefState.ABSENT)
        return try {
            SealedPrefRead(unpad(cipher.open(decodeBase64(raw), context(slot))), SealedPrefState.PROVEN)
        } catch (_: KeyUnavailableException) {
            SealedPrefRead(null, SealedPrefState.UNREADABLE)
        } catch (_: KeyPermanentlyInvalidException) {
            // The device key is gone for good. Still UNREADABLE, never
            // UNAUTHENTICATED: nothing about this value was tampered with, and a
            // permanently dead device key is a vault-level problem the unlock
            // path owns — it must not be reported here as evidence of a plant.
            SealedPrefRead(null, SealedPrefState.UNREADABLE)
        } catch (_: Exception) {
            SealedPrefRead(null, SealedPrefState.UNAUTHENTICATED)
        }
    }

    /** Strip the trailing NUL padding [seal] adds. */
    internal fun unpad(bytes: ByteArray): String {
        var end = bytes.size
        while (end > 0 && bytes[end - 1] == 0.toByte()) end--
        return bytes.copyOfRange(0, end).decodeToString()
    }
}

package com.vg.run

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import com.google.crypto.tink.Aead
import com.google.crypto.tink.BinaryKeysetReader
import com.google.crypto.tink.InsecureSecretKeyAccess
import com.google.crypto.tink.KeyTemplates
import com.google.crypto.tink.KeysetHandle
import com.google.crypto.tink.LegacyKeysetSerialization
import com.google.crypto.tink.aead.AeadConfig
import com.google.crypto.tink.integration.android.AndroidKeysetManager
import com.google.crypto.tink.integration.android.AndroidKeystoreKmsClient
import com.google.crypto.tink.integration.android.SharedPrefKeysetWriter
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory

/**
 * Where a platform-keystore key actually lives, verified from `KeyInfo`.
 *
 * Surfaced LIVE IN RELEASE as a plain queryable value (NOT via the
 * LoggingState-gated [LogBuffer], which App Store / Play builds never enable),
 * so a higher layer — RunViewModel / the ProtectionLevel surface — can read it
 * and refuse to advertise a hardware at-rest guarantee the device does not
 * actually provide. [UNKNOWN] means the backing could NOT be verified; callers
 * must treat it as "not hardware" and never assume.
 */
enum class KeystoreBacking { HARDWARE, SOFTWARE, UNKNOWN }

/**
 * Pure, off-device-testable classifier for a Keystore key's hardware backing
 * across the whole minSdk-30 range (kept android-free so a JVM unit test can pin
 * both branches, exactly like [CryptoProvider.isKeystoreClassName]):
 *   - API 31+ read `KeyInfo.getSecurityLevel()` -> [fromSecurityLevel].
 *   - API 30 (no securityLevel; minSdk is 30) read the deprecated-but-present
 *     `KeyInfo.isInsideSecureHardware()` -> [fromInsideSecureHardware].
 * NEVER reports HARDWARE for a level it cannot positively place in secure
 * hardware — the "don't assume hardware when it can't be verified" rule.
 */
object KeystoreSecurity {
    // android.security.keystore.KeyProperties.SECURITY_LEVEL_* (API 31). Mirrored
    // as plain ints so the classifier compiles and unit-tests with no android
    // dependency; these are stable public framework values.
    internal const val SECURITY_LEVEL_UNKNOWN = -1
    internal const val SECURITY_LEVEL_UNKNOWN_SECURE = -2
    internal const val SECURITY_LEVEL_SOFTWARE = 0
    internal const val SECURITY_LEVEL_TRUSTED_ENVIRONMENT = 1
    internal const val SECURITY_LEVEL_STRONGBOX = 2

    /** API 31+ path: TEE / StrongBox / UNKNOWN_SECURE are hardware; SOFTWARE is
     *  software; a bare UNKNOWN (-1) is unverifiable -> [KeystoreBacking.UNKNOWN]. */
    internal fun fromSecurityLevel(level: Int): KeystoreBacking = when (level) {
        SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
        SECURITY_LEVEL_STRONGBOX,
        SECURITY_LEVEL_UNKNOWN_SECURE -> KeystoreBacking.HARDWARE
        SECURITY_LEVEL_SOFTWARE -> KeystoreBacking.SOFTWARE
        else -> KeystoreBacking.UNKNOWN
    }

    /** API 30 path (minSdk 30): `isInsideSecureHardware` still gives a definite hardware
     *  vs software answer (it just can't tell TEE from StrongBox). */
    internal fun fromInsideSecureHardware(inside: Boolean): KeystoreBacking =
        if (inside) KeystoreBacking.HARDWARE else KeystoreBacking.SOFTWARE

    // The two load-bearing POLICY decisions a backing verdict feeds, kept here as
    // one shared source of truth so every sink (the Tink master key in
    // [CryptoManager], the Lever-B auth-bound key in [AuthBoundKeyStore], and
    // their unit tests) answers identically and can't silently drift.

    /**
     * May a higher layer ADVERTISE a hardware at-rest guarantee for a key with
     * this [backing]? Only a POSITIVELY-verified [KeystoreBacking.HARDWARE] key
     * qualifies: [KeystoreBacking.SOFTWARE] (extractable) and
     * [KeystoreBacking.UNKNOWN] (unverifiable) both fail — the "never claim
     * hardware we can't prove" rule.
     */
    fun claimsHardware(backing: KeystoreBacking): Boolean =
        backing == KeystoreBacking.HARDWARE

    /**
     * May we ACCEPT a key whose lifecycle we control — a fresh mint, or a stale
     * alias on a NEW Lever-B enable — with this [backing]? Refused ONLY when the
     * key is positively [KeystoreBacking.SOFTWARE] (extractable, no hardware
     * barrier). [KeystoreBacking.HARDWARE] is accepted; [KeystoreBacking.UNKNOWN]
     * is ALSO accepted (fail toward not blocking access — the probe couldn't
     * place it and refusing would over-block devices whose `KeyInfo` isn't
     * derivable), while [claimsHardware] still never claims hardware for it. The
     * two decisions differ EXACTLY on UNKNOWN: never claim it, never refuse it.
     */
    fun acceptsForNewKey(backing: KeystoreBacking): Boolean =
        backing != KeystoreBacking.SOFTWARE
}

/**
 * Byte-level probe for the state of the PERSISTED Tink keyset. Kept as a separate, android-free object for the same reason as
 * [KeystoreSecurity]: this decision is load-bearing, so it must be pinnable by a
 * JVM unit test, and it must NOT depend on a library flag.
 *
 * Why not `AndroidKeysetManager.isUsingKeystore()`: in the pinned tink-android
 * 1.21.0 it is literally `masterAead != null`, i.e. it reports that a Keystore
 * AEAD HANDLE was obtained — never whether the bytes on disk are encrypted. The
 * builder's *second* cleartext fallback (`parseEncryptedKeyset` throws ->
 * `readKeysetInCleartext`) runs with `masterAead` ALREADY SET, so the one state
 * the repair exists for — a cleartext keyset on disk while the Keystore is
 * healthy — reports `isUsingKeystore() == true`. Ask the bytes instead.
 *
 * The discriminator: a cleartext `google.crypto.tink.Keyset` parses with
 * [LegacyKeysetSerialization.parseKeyset]; the `EncryptedKeyset` proto a healthy
 * (wrapped) install persists does NOT — different field numbers/wire types, and
 * the keyset-level validation additionally rejects it (empirically verified
 * against tink-android 1.21.0: `InvalidProtocolBufferException`).
 *
 * Both error directions are safe, which is why a parse is an acceptable oracle:
 * a false CLEARTEXT verdict merely re-writes an already-wrapped keyset with the
 * same key material, and a false WRAPPED verdict is exactly today's behaviour.
 */
internal object KeysetWrapProbe {

    /**
     * Decodes the hex string `SharedPrefKeysetWriter` persists (it stores
     * `Hex.encode(bytes)`; upper case is accepted too). Returns null — meaning
     * "no classifiable bytes" — for an absent/empty/odd-length/non-hex value.
     * Hand-rolled rather than `Hex.decode` so the decoder is total (no throw)
     * and unit-testable without pulling in a `subtle` internal.
     */
    fun hexToBytesOrNull(hex: String?): ByteArray? {
        if (hex.isNullOrEmpty() || hex.length % 2 != 0) return null
        val out = ByteArray(hex.length / 2)
        var i = 0
        while (i < hex.length) {
            val hi = hexDigit(hex[i])
            val lo = hexDigit(hex[i + 1])
            if (hi < 0 || lo < 0) return null
            out[i / 2] = ((hi shl 4) or lo).toByte()
            i += 2
        }
        return out
    }

    private fun hexDigit(c: Char): Int = when (c) {
        in '0'..'9' -> c - '0'
        in 'a'..'f' -> c - 'a' + 10
        in 'A'..'F' -> c - 'A' + 10
        else -> -1
    }

    /**
     * True when [raw] IS a cleartext Tink keyset, i.e. the AES-256 data key is on
     * disk in the clear with no Keystore involved. Absent/empty bytes are NOT
     * cleartext (nothing to classify — see the callers for the two opposite
     * readings of that). The parsed handle is discarded immediately and never
     * logged: on a `true` verdict it holds live key material.
     */
    fun isCleartextKeyset(raw: ByteArray?): Boolean {
        if (raw == null || raw.isEmpty()) return false
        return try {
            LegacyKeysetSerialization.parseKeyset(
                BinaryKeysetReader.withBytes(raw),
                InsecureSecretKeyAccess.get(),
            )
            true
        } catch (_: Exception) {
            // Not a cleartext keyset: a wrapped EncryptedKeyset, or garbage.
            false
        }
    }
}

/**
 * CryptoManager handles all symmetric encryption and decryption for the app.
 *
 * Keys are generated and managed by Google Tink using the AES-256-GCM algorithm.
 * The keyset is stored in SharedPreferences and wrapped (encrypted at rest) by a
 * master key that lives exclusively in the Android Keystore — it never leaves
 * secure hardware on supported devices.
 *
 * The master key is UNLOCKED-DEVICE-bound (not "auth-bound" — in this codebase
 * that term means the Lever B biometric key in AuthBoundKeyStore): we pre-create
 * it with `setUnlockedDeviceRequired(true)` BEFORE Tink wraps the keyset, so the key —
 * and therefore the entire wrapped keyset and every CryptoProvider-encrypted
 * blob beneath it — can only be unwrapped while the device is unlocked. This
 * denies forensic tooling that images or accesses a locked-but-powered device,
 * matching the iOS posture (`kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`).
 *
 * @param context Application or activity context used to access SharedPreferences
 *                and the Android Keystore.
 */
class CryptoManager(context: Context) {

    companion object {
        // SharedPreferences file that holds the serialized (wrapped) Tink keyset.
        // Not private: the wipe routine must delete this file.
        const val PREF_FILE_NAME = "run_keyset_prefs"

        // Key name inside the SharedPreferences file for the keyset entry.
        private const val KEYSET_NAME = "run_aead_keyset"

        // Alias of the master wrapping key inside the Android Keystore.
        private const val MASTER_KEY_ALIAS = "run_master_key"

        // URI that tells Tink to use the Android Keystore for the master wrapping key.
        private const val MASTER_KEY_URI = "android-keystore://$MASTER_KEY_ALIAS"

        /**
         * Verified hardware backing of the active master wrapping key, refreshed
         * on every [ensureMasterKey] run (i.e. every CryptoManager construction).
         * LIVE IN RELEASE — a plain value, NOT the LoggingState-gated [LogBuffer]
         * warning — so a higher layer (RunViewModel / ProtectionLevel) can read it
         * to warn the user or refuse to advertise a hardware at-rest guarantee.
         * A [KeystoreBacking.SOFTWARE] master key is extractable from a filesystem
         * image, collapsing CR-1 at-rest protection to the credential alone.
         * Starts [KeystoreBacking.UNKNOWN] until the first crypto use.
         */
        @Volatile
        var masterKeyBacking: KeystoreBacking = KeystoreBacking.UNKNOWN
            private set

        /**
         * REAL consumer surface for [masterKeyBacking]: the
         * master key wraps the whole Tink keyset, so it is the at-rest CR-1
         * barrier for EVERY tier (not just Lever B). Returns true ONLY when that
         * key is positively hardware-backed; a [KeystoreBacking.SOFTWARE]
         * (extractable) or [KeystoreBacking.UNKNOWN] (unverifiable) verdict
         * returns false. Refreshed on every [CryptoManager] construction
         * (`ensureMasterKey` → `auditMasterKeySecurityLevel`).
         *
         * NOT WIRED as of 13ce3610: no production code calls this (only
         * KeystoreBackingClassifyTest's comments name it), so no surface is gated
         * on it today. The honest consumer would be a UI/tier gate. Before advertising a hardware at-rest
         * guarantee — the PRIVATE/MAXIMUM "keyed to this phone's security chip"
         * copy / the runestone hardware assurance — RunViewModel / the
         * ProtectionLevel surface MUST gate on
         * `CryptoManager.isMasterKeyHardwareBacked()`; when it is false, render
         * the "at-rest security falls back to the credential alone" warning
         * instead and do not claim the hardware barrier. NEVER refuse to open the
         * vault on a false result — the data is already at rest, so blocking
         * helps no one and would brick the minority of devices with a software
         * keystore; this is observational + refuse-to-CLAIM, never refuse-access.
         */
        fun isMasterKeyHardwareBacked(): Boolean =
            KeystoreSecurity.claimsHardware(masterKeyBacking)

        /**
         * Cryptographic erasure. Deletes the Android Keystore
         * master key and the wrapped Tink keyset. Without the Keystore key
         * the keyset can never be unwrapped, so every CryptoProvider-encrypted
         * blob — credential verifiers, the PIN-wrapped SQLCipher DB keys
         * (CR-1), the wrong-PIN counter (CR-5) — becomes permanently
         * unrecoverable, even from a disk image taken before the wipe and
         * even if the subsequent file deletions are interrupted. This is
         * why every wipe path must call it FIRST, before deleting databases
         * or prefs: destroying the key is instantaneous and irreversible,
         * whereas file deletion is best-effort and racy.
         *
         * Best-effort and idempotent: a missing alias / absent keyset file
         * is a no-op (e.g. wipe invoked before first crypto use).
         *
         * This used to be ONE unverified
         * `deleteEntry` inside a bare `catch {}` plus an unchecked
         * `deleteSharedPreferences` — the single irreversible step of the whole
         * wipe, with no read-back, no retry and no second kill. A swallowed
         * Keystore failure left the alias alive, and a pre-wipe image of
         * `run_keyset_prefs` + a later unlocked device then reduced CASUAL to an
         * unthrottled offline Argon2id grind (the PIN-attempt counters are wiped
         * too). Now: (1) the alias delete is read back with `containsAlias` and
         * retried; (2) INDEPENDENTLY, the wrapped keyset ciphertext is overwritten
         * in place with random hex of the same length via a synchronous
         * `commit()` BEFORE the file is deleted, so either half alone completes
         * the crypto-erase; (3) the outcome is returned and logged, never
         * silently swallowed. Returns true when at least one half is PROVEN.
         */
        fun eraseMasterKey(context: Context): Boolean {
            var aliasGone = false
            for (attempt in 1..3) {
                try {
                    val ks = KeyStore.getInstance("AndroidKeyStore")
                    ks.load(null)
                    if (ks.containsAlias(MASTER_KEY_ALIAS)) ks.deleteEntry(MASTER_KEY_ALIAS)
                    if (!ks.containsAlias(MASTER_KEY_ALIAS)) { aliasGone = true; break }
                    platformLogWarn("CryptoManager", "master key alias survived deleteEntry (attempt $attempt)")
                } catch (e: Exception) {
                    platformLogWarn("CryptoManager", "master key delete attempt $attempt failed: ${e::class.simpleName}")
                }
            }
            // Second, independent kill: destroy the ciphertext itself. Overwrite
            // (not just delete) so a pre-wipe copy of the file is the only copy that
            // ever held the real blob, and a surviving alias unwraps only junk here.
            var blobDestroyed = false
            try {
                val prefs = context.getSharedPreferences(PREF_FILE_NAME, Context.MODE_PRIVATE)
                val existing = prefs.getString(KEYSET_NAME, null)
                blobDestroyed = if (existing == null) {
                    true    // nothing persisted — nothing to destroy
                } else {
                    val junk = bytesToHex(generateSecureRandom(maxOf(16, existing.length / 2)))
                    prefs.edit().putString(KEYSET_NAME, junk).commit()   // synchronous, never apply()
                }
            } catch (e: Exception) {
                platformLogWarn("CryptoManager", "keyset overwrite failed: ${e::class.simpleName}")
            }
            val fileGone = try { context.deleteSharedPreferences(PREF_FILE_NAME) } catch (_: Exception) { false }
            if (!aliasGone && !blobDestroyed) {
                platformLogError("CryptoManager", "crypto-erase NOT proven: alias survived and keyset overwrite failed (file deleted=$fileGone)")
            } else if (!aliasGone || !blobDestroyed) {
                platformLogWarn("CryptoManager", "crypto-erase proven by one half only (alias=$aliasGone blob=$blobDestroyed file=$fileGone)")
            }
            return aliasGone || blobDestroyed
        }

        /**
         * Builds the [KeyGenParameterSpec] for the Tink master wrapping key.
         * Mirrors the AES-256-GCM / no-padding spec Tink's
         * `AndroidKeystoreKmsClient` would otherwise create by default, but adds
         * `setUnlockedDeviceRequired(true)` so the key can only be exercised
         * while the device is unlocked.
         *
         * We deliberately use `setUnlockedDeviceRequired`, NOT
         * `setUserAuthenticationRequired`: the app's auth factor is its own PIN,
         * not the device credential, and per-operation device-credential prompts
         * would conflict with that model. Unlocked-device binding is the
         * proportionate control for the threat (forensic access to a
         * locked-but-powered device) and mirrors iOS's `WhenUnlocked`-class
         * accessibility.
         *
         * Public so the unlocked-device flag can be asserted directly in tests:
         * it is not exposed by `KeyInfo`, so the spec is the only deterministic
         * place to verify the property. (Available since API 28, so present
         * across the whole minSdk-30 range.)
         *
         * [strongBox] requests the device's dedicated secure element (StrongBox,
         * API 28+) for the strongest hardware binding. Not all devices have one,
         * so callers must catch [StrongBoxUnavailableException] and retry with
         * `false` — see [ensureMasterKey].
         */
        fun buildMasterKeySpec(alias: String, strongBox: Boolean = false): KeyGenParameterSpec =
            KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUnlockedDeviceRequired(true)
                .apply { if (strongBox) setIsStrongBoxBacked(true) }
                .build()

        /**
         * Ensures the Android Keystore master wrapping key exists with the
         * hardened [buildMasterKeySpec] BEFORE Tink is asked to wrap the keyset.
         * If the alias is absent we create it ourselves (preferring StrongBox,
         * falling back to the TEE); Tink then finds and reuses it instead of
         * auto-creating one without setUnlockedDeviceRequired. Idempotent — an existing alias is
         * left untouched (the unlocked-device flag cannot be added to an existing
         * key in place; a wipe/re-provision is required to upgrade a pre-hardening
         * install — acceptable pre-release).
         *
         * Whatever key ends up active, [auditMasterKeySecurityLevel] then verifies
         * its hardware backing and publishes it to [masterKeyBacking] (live in
         * release) so a SOFTWARE-backed (extractable) key — which collapses
         * at-rest protection to the credential alone — is surfaced through a
         * queryable channel, not silently accepted, regardless of when the key
         * was provisioned or which Android version this is.
         */
        private fun ensureMasterKey() {
            val ks = KeyStore.getInstance("AndroidKeyStore")
            ks.load(null)
            if (!ks.containsAlias(MASTER_KEY_ALIAS)) {
                fun generate(strongBox: Boolean) =
                    KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
                        .apply { init(buildMasterKeySpec(MASTER_KEY_ALIAS, strongBox)) }
                        .generateKey()
                try {
                    generate(strongBox = true)           // prefer the dedicated secure element
                } catch (_: StrongBoxUnavailableException) {
                    generate(strongBox = false)          // no StrongBox — fall back to the TEE
                } catch (_: Exception) {
                    // Some OEMs signal absent StrongBox with a generic exception
                    // rather than the typed one; clean up a half-created alias and
                    // fall back rather than failing key creation outright.
                    //
                    // A generic exception is ambiguous —
                    // it can equally be a TRANSIENT keystore outage, and this branch
                    // runs exactly once (the alias is absent only at first provision),
                    // so a momentary blip used to pin the install to a TEE key for
                    // life with no path back: re-attempting StrongBox later would mean
                    // deleting the master key, which crypto-erases the vault. Retry
                    // once before conceding, and say so loudly when we do concede.
                    try { ks.deleteEntry(MASTER_KEY_ALIAS) } catch (_: Exception) {}
                    try {
                        generate(strongBox = true)
                    } catch (_: StrongBoxUnavailableException) {
                        generate(strongBox = false)
                    } catch (e: Exception) {
                        try { ks.deleteEntry(MASTER_KEY_ALIAS) } catch (_: Exception) {}
                        LogBuffer.append(
                            "W", "CryptoManager",
                            "StrongBox keygen failed twice (${e.javaClass.simpleName}) — pinning this install to a TEE key",
                        )
                        generate(strongBox = false)
                    }
                }
            }
            auditMasterKeySecurityLevel(ks)
        }

        /**
         * Builds (or loads) the [AndroidKeysetManager] that stores the wrapped
         * Tink keyset in SharedPreferences under the Android Keystore master key.
         */
        private fun buildKeysetManager(context: Context): AndroidKeysetManager =
            AndroidKeysetManager.Builder()
                .withSharedPref(context, KEYSET_NAME, PREF_FILE_NAME)
                .withKeyTemplate(KeyTemplates.get("AES256_GCM"))
                .withMasterKeyUri(MASTER_KEY_URI)
                .build()

        /**
         * Raw bytes of the PERSISTED keyset, exactly as `SharedPrefKeysetWriter`
         * wrote them (the pref holds `Hex.encode(bytes)`). Returns null when the
         * entry is ABSENT or not hex-decodable; the two call sites read that null
         * in DELIBERATELY OPPOSITE directions — see each of them.
         *
         * Never logged and never returned upward: on a cleartext install this
         * array IS the AES-256 data key, so callers zero it after classifying.
         */
        private fun readPersistedKeysetBytes(context: Context): ByteArray? =
            try {
                KeysetWrapProbe.hexToBytesOrNull(
                    context.getSharedPreferences(PREF_FILE_NAME, Context.MODE_PRIVATE)
                        .getString(KEYSET_NAME, null),
                )
            } catch (_: Exception) {
                // Unreadable prefs — indistinguishable from absent here; the
                // detector below treats that as "nothing to repair", never as a
                // reason to rewrite the one copy of the keyset.
                null
            }

        /**
         * The REAL cleartext detector — over the bytes on disk, not over
         * `AndroidKeysetManager.isUsingKeystore()` (see [KeysetWrapProbe] for why
         * that flag cannot see this state at all).
         *
         * ABSENT reads as NOT cleartext: a missing entry is a first provision (or
         * a keyset Tink is about to write), not evidence of a downgrade. Only a
         * value that positively parses as a cleartext keyset triggers the repair.
         */
        private fun persistedKeysetIsCleartext(context: Context): Boolean {
            val raw = readPersistedKeysetBytes(context) ?: return false
            return try {
                KeysetWrapProbe.isCleartextKeyset(raw)
            } finally {
                raw.fill(0)   // don't keep a second copy of a cleartext keyset in RAM
            }
        }

        /**
         * The persisted keyset is NOT Keystore-wrapped (Tink fell back to
         * cleartext when its master-key probe failed, at this launch or at any
         * earlier one). Re-wrap it in place under the master key and verify the
         * rewrite took — by re-reading the BYTES, never by asking the library.
         *
         * Re-wrapping rather than refusing is deliberate: the cleartext keyset is the
         * only copy of the key that decrypts this install's vault material, so
         * failing closed on it would destroy exactly what we are trying to protect.
         * If the re-wrap does NOT stick we throw [KeyUnavailableException] — the
         * deferrable type every caller already handles — so the app retries on the
         * next launch instead of silently operating on an unwrapped keyset.
         *
         * Ordering is what makes this brick-safe: `KeysetHandle.write` ENCRYPTS
         * first and only then hands the result to the writer, and
         * `SharedPrefKeysetWriter` throws when the SharedPreferences commit returns
         * false — so an unusable master key (locked device, Keystore outage) or a
         * failed commit throws BEFORE the only copy of the keyset is replaced.
         * Nothing on this path deletes anything.
         */
        private fun rewrapKeysetUnderKeystore(context: Context, handle: KeysetHandle): KeysetHandle {
            LogBuffer.append(
                "E", "CryptoManager",
                "master keyset is NOT Keystore-wrapped (cleartext in prefs) — re-wrapping",
            )
            val masterAead = AndroidKeystoreKmsClient().getAead(MASTER_KEY_URI)
            handle.write(SharedPrefKeysetWriter(context, KEYSET_NAME, PREF_FILE_NAME), masterAead)

            // Verification = the detector IN REVERSE, over the bytes now on disk:
            // the cleartext parse must FAIL. The old check (`verified.isUsingKeystore()`)
            // was vacuous — true whenever `getAead` worked, whether or not the write
            // landed. NOTE the deliberate asymmetry with the pre-write reading of a
            // null/unreadable pref: there it means "nothing to repair"; HERE it means
            // the write did not land, which is a failure.
            val after = readPersistedKeysetBytes(context)
            val stillCleartext = after == null || KeysetWrapProbe.isCleartextKeyset(after)
            after?.fill(0)
            if (stillCleartext) {
                throw KeyUnavailableException(
                    "master keyset could not be wrapped by the Android Keystore"
                )
            }

            // Re-read through the manager too. With the bytes PROVEN not to parse as
            // a cleartext keyset, the only way this build can succeed is Tink's
            // parseEncryptedKeyset path — i.e. the Keystore key really did unwrap
            // what we just wrote.
            val verified = try {
                buildKeysetManager(context)
            } catch (e: Exception) {
                // A PERMANENT invalidation keeps its identity — it has its own,
                // distinct handling upstream — but everything else becomes
                // DEFERRABLE: failing to re-read a keyset we wrote seconds ago is a
                // Keystore/storage problem, never a forged blob, and a bare
                // GeneralSecurityException escaping here could be misread as tamper
                // by the counter path. Class name only in the message — never the
                // exception text, never bytes.
                if (CryptoProvider.isPermanentKeyInvalidation(e)) throw e
                throw KeyUnavailableException(
                    "re-wrapped master keyset could not be re-read: ${e.javaClass.simpleName}"
                )
            }
            LogBuffer.append("I", "CryptoManager", "master keyset re-wrapped under the Keystore key")
            return verified.keysetHandle
        }

        /**
         * Verifies and records the hardware backing of the active master key.
         *
         * Runs across the WHOLE minSdk-30 range — API 31+ via
         * `KeyInfo.getSecurityLevel()`, API 30 via the deprecated-but-present
         * `KeyInfo.isInsideSecureHardware()` — so Android 10/11 are covered, not
         * skipped. The verdict is published to [masterKeyBacking], which is LIVE
         * IN RELEASE (unlike the [LogBuffer] warning, which production builds never
         * enable), so a SOFTWARE-backed (extractable) master key — which collapses
         * at-rest protection to the credential — is surfaced through a queryable
         * channel instead of being silently accepted. We record rather than refuse
         * to launch: refusing would brick the minority of devices with no hardware
         * keystore. Best-effort: an underivable `KeyInfo` yields
         * [KeystoreBacking.UNKNOWN], which callers must treat as "not hardware".
         */
        private fun auditMasterKeySecurityLevel(ks: KeyStore) {
            val backing = probeMasterKeyBacking(ks)
            masterKeyBacking = backing
            when (backing) {
                KeystoreBacking.SOFTWARE -> LogBuffer.append(
                    "W", "CryptoManager",
                    "master key is SOFTWARE-backed — extractable; at-rest security falls back to the credential alone",
                )
                KeystoreBacking.UNKNOWN -> LogBuffer.append(
                    "W", "CryptoManager",
                    "master key security level could not be verified — treating as NOT hardware-backed",
                )
                KeystoreBacking.HARDWARE -> LogBuffer.append(
                    "I", "CryptoManager", "master key is hardware-backed",
                )
            }
        }

        private fun probeMasterKeyBacking(ks: KeyStore): KeystoreBacking = try {
            val key = ks.getKey(MASTER_KEY_ALIAS, null) as? SecretKey
                ?: return KeystoreBacking.UNKNOWN
            val factory = SecretKeyFactory.getInstance(key.algorithm, "AndroidKeyStore")
            val info = factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S) {
                KeystoreSecurity.fromSecurityLevel(info.securityLevel)   // API 31+ (guarded)
            } else {
                // API 30 (minSdk): securityLevel is API 31; isInsideSecureHardware still
                // distinguishes secure hardware from software here — a real answer,
                // not a skip.
                @Suppress("DEPRECATION")
                KeystoreSecurity.fromInsideSecureHardware(info.isInsideSecureHardware)
            }
        } catch (_: Exception) {
            // KeyInfo not derivable on this keystore — non-fatal; leave UNKNOWN.
            KeystoreBacking.UNKNOWN
        }
    }

    // The AEAD primitive is the single entry point for encrypt/decrypt operations.
    // It is initialised once and reused for the lifetime of this CryptoManager instance.
    private val aead: Aead

    init {
        // Register all AEAD key types with the Tink runtime.
        // This must be called before any keyset operations.
        AeadConfig.register()

        // Pre-create the unlocked-device-bound master key so Tink reuses it
        // instead of auto-creating one with the default spec (no
        // setUnlockedDeviceRequired). Must run BEFORE the keyset is wrapped.
        ensureMasterKey()

        // Build (or load) the keyset using AndroidKeysetManager:
        //   • withSharedPref  — store the wrapped keyset in SharedPreferences
        //   • withKeyTemplate — if no keyset exists yet, generate a new AES-256-GCM key
        //   • withMasterKeyUri — wrap the keyset with a key from the Android Keystore;
        //                        ensureMasterKey() above has already created it, so
        //                        Tink REUSES that key (its own auto-create would use
        //                        a spec without setUnlockedDeviceRequired)
        val manager = buildKeysetManager(context)

        // AndroidKeysetManager silently DISABLES the
        // master key and persists the keyset as CLEARTEXT in SharedPreferences if
        // its Keystore probe fails (documented library behaviour), and the read path
        // then prefers that cleartext keyset forever. auditMasterKeySecurityLevel
        // above inspects the Keystore KEY (which looks perfectly healthy), never the
        // keyset WRAPPING, so the downgrade is invisible: a transient Keystore outage
        // during first provision leaves every credential verifier, PIN-wrapped DB key
        // and attempt counter readable from a disk image with no Keystore at all.
        //
        // HOW that is detected is load-bearing:
        // the decider is the BYTES ON DISK ([persistedKeysetIsCleartext]), never the
        // library flag. `AndroidKeysetManager.isUsingKeystore()` in tink-android
        // 1.21.0 is exactly `masterAead != null`, and the builder's SECOND cleartext
        // fallback (`parseEncryptedKeyset` throws -> `readKeysetInCleartext`) leaves
        // `masterAead` SET — so the one state this repair exists for (cleartext on
        // disk, healthy Keystore) reported "using keystore" and the repair could
        // never fire. The flag is kept only as a cheap ADDITIONAL trigger for the
        // masterAead == null case (Keystore probe failed at this launch), where the
        // two agree anyway: a wrapped keyset could not have been parsed without it.
        //
        // Detect and re-wrap rather than fail: the cleartext keyset IS the real
        // keyset, so refusing to load it would brick the vault it is meant to protect.
        val keysetHandle = if (persistedKeysetIsCleartext(context) || !manager.isUsingKeystore()) {
            rewrapKeysetUnderKeystore(context, manager.keysetHandle)
        } else {
            manager.keysetHandle
        }

        // Obtain the AEAD primitive from the keyset handle.
        // All encrypt/decrypt calls go through this object.
        aead = keysetHandle.getPrimitive(Aead::class.java)
    }

    /**
     * Tink AES-256-GCM with [contextInfo] as associated data. The one thing that
     * matters beyond AEAD basics: Tink prefixes a 5-byte key-id header, so every
     * Android device-key blob is 5 B LONGER than the iOS one for the same
     * plaintext — which `SelectorMetaPolicy.isSelectorMetaBlobShaped`'s ≥ 28-byte
     * floor (IV + tag) tolerates on both platforms.
     */
    fun encrypt(plaintext: ByteArray, contextInfo: ByteArray): ByteArray {
        return aead.encrypt(plaintext, contextInfo)
    }

    /** Inverse of [encrypt]; throws `GeneralSecurityException` on a wrong key, tamper or context mismatch. */
    fun decrypt(ciphertext: ByteArray, contextInfo: ByteArray): ByteArray {
        return aead.decrypt(ciphertext, contextInfo)
    }
}

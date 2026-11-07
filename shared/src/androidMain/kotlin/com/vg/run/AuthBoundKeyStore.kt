package com.vg.run

import android.annotation.SuppressLint
import android.content.Context
import android.hardware.biometrics.BiometricManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.spec.MGF1ParameterSpec
import javax.crypto.Cipher
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

// ---------------------------------------------------------------------------
// AuthBoundKeyStore — the hardware AUTH-BOUND key for the DB-key OUTER layer
// (Lever B, Android).
//
// An RSA-2048 keypair in the Android Keystore, StrongBox-preferred:
//   • setUserAuthenticationRequired(true) + setUserAuthenticationParameters(
//     0, AUTH_BIOMETRIC_STRONG)  → auth-PER-USE (timeout 0), no time window,
//     STRONG BIOMETRIC ONLY (NO device-credential fallback). A fresh strong
//     biometric is required for each PRIVATE-key (decrypt/unwrap) operation. A
//     cracked device passcode can NO LONGER release the key — the PRIVATE-tier
//     hardening gap this closes (mirrors iOS `.biometryCurrentSet`).
//   • setUnlockedDeviceRequired(true) — belt-and-suspenders with the auth gate.
//   • setInvalidatedByBiometricEnrollment(true) — the key is DESTROYED on any
//     fingerprint re-enrollment (strictest binding). The shared side (VaultSelector)
//     makes this safe, not a brick: it REFUSES to enable Lever B without first
//     minting + read-back-verifying a recovery code, and that code is the way back
//     after an invalidation (KeyPermanentlyInvalidatedException → recovery path).
//
// Why asymmetric (deviates from a literal "AES + CryptoObject" design): the PUBLIC
// key wraps the DB key with NO authentication, so provisioning / enabling the
// feature / KDF migration never prompt; only the PRIVATE-key unwrap at unlock
// prompts. This mirrors the iOS Secure-Enclave ECIES design (public-key wrap,
// SE-gated unwrap) and gives per-use auth on unwrap exactly as required,
// with strictly better UX. RSA-2048-OAEP-SHA256 (max 190 B of plaintext) handles
// the inner blob directly: 61 B for a passphrase-mode payload, 93 B once raw-key
// adoption has added K' (60 B for a legacy untagged payload). Recorded as a plan-consistent default (autonomous mandate §0).
//
// The private-key op is driven by a BiometricPrompt.CryptoObject — see
// [BiometricGate]. This class never shows UI; it only manages the key and the
// unauthenticated public-key wrap.
// ---------------------------------------------------------------------------

object AuthBoundKeyStore {

    private const val ALIAS = "run_dbkey_auth_key"
    private const val KEYSTORE = "AndroidKeyStore"

    // OAEP params: Android Keystore uses MGF1-with-SHA-1 internally even when the
    // OAEP digest is SHA-256, so BOTH encrypt and decrypt must pin MGF1 to SHA-1
    // or the padding check fails on decrypt. (Well-known Keystore OAEP gotcha.)
    private val OAEP_SPEC = OAEPParameterSpec(
        "SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT
    )
    private const val TRANSFORMATION = "RSA/ECB/OAEPPadding"

    /**
     * Verified hardware backing of the auth-bound key, refreshed on every
     * [ensureKey] call. LIVE IN RELEASE (a plain value, not the LoggingState-gated
     * [LogBuffer]) so a higher layer can reconcile an EXISTING vault's advertised
     * PRIVATE tier with reality — Lever B's whole claim is a NON-extractable
     * hardware key, and [KeystoreBacking.SOFTWARE] means that barrier is absent.
     * [ensureKey] additionally REFUSES to newly enable Lever B on a software key.
     * Starts [KeystoreBacking.UNKNOWN] until the first [ensureKey].
     * No iOS twin (SE keys are hardware by construction — IosDbKeyProtector header);
     * wiring this into the tier display is plan-only (P-8).
     */
    @Volatile
    var lastKeyBacking: KeystoreBacking = KeystoreBacking.UNKNOWN
        private set

    /**
     * REAL consumer surface for [lastKeyBacking]: true ONLY
     * when the Lever-B auth-bound key is positively hardware-backed;
     * [KeystoreBacking.SOFTWARE] / [KeystoreBacking.UNKNOWN] → false. Lever B's
     * whole claim is a NON-extractable hardware barrier, so a false result means
     * that barrier is absent and a vault persisted PRIVATE is over-claiming.
     *
     * NOT WIRED as of 13ce3610: no production code calls this. The pre-existing
     * software-key case can only be made honest by a tier reconciler — refusing
     * a pre-existing key here would brick a vault that already unlocks. After an
     * unlock / [ensureKey] on a PRIVATE vault, VaultSelector.currentProtectionLevel
     * / RunViewModel / Settings MUST reconcile the advertised tier down (drop the
     * hardware-barrier copy, offer re-provision) when
     * `AuthBoundKeyStore.isHardwareBacked()` is false. NEVER block the existing
     * vault's unlock on a false result — the unwrap path (which never calls
     * [ensureKey]) must keep working (backward compatible / no brick).
     */
    fun isHardwareBacked(): Boolean = KeystoreSecurity.claimsHardware(lastKeyBacking)

    /**
     * True when the device can do per-use BIOMETRIC auth-binding: a STRONG
     * biometric is enrolled (Class 3 / BIOMETRIC_STRONG). PRIVATE-tier hardening:
     * the auth-bound key is now biometric-only (no device-credential fallback), so
     * a device-credential-only phone can NO LONGER use Lever B — a passcode a
     * forensic tool cracks must not open PRIVATE. Passcode-only users get
     * CASUAL/MAXIMUM instead. Drives PRIVATE selectability (via
     * VaultSelector.supportsDbKeyAuthBinding).
     */
    // USE_BIOMETRIC is declared by the consuming app (androidApp manifest); the shared
    // library has no manifest, so isolated `:shared:lint` can't see it — suppress the
    // false-positive here rather than duplicate a manifest.
    @SuppressLint("MissingPermission")
    fun isAuthBindingAvailable(context: Context): Boolean {
        // Lever B needs API-30 BiometricPrompt (canAuthenticate(authenticators),
        // setAllowedAuthenticators, setUserAuthenticationParameters). minSdk is 30, so
        // this guard is only a defensive floor: report UNAVAILABLE below API 30 — Private/Hardened grey out there, like a
        // device with no secure element; Casual + Maximum are unaffected. This is also the
        // guard that keeps the canAuthenticate() call below off pre-API-30 devices.
        if (android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.R) return false
        return try {
            val bm = context.getSystemService(BiometricManager::class.java) ?: return false
            // STRONG biometric ONLY — no DEVICE_CREDENTIAL. Matches the key's
            // setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG): if this said
            // "or DEVICE_CREDENTIAL" we would advertise Lever B on passcode-only phones
            // where the biometric-only key can't be created or used.
            bm.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
                BiometricManager.BIOMETRIC_SUCCESS
        } catch (_: Exception) {
            false
        }
    }

    /**
     * True when this device HAS the hardware for a biometric-bound Lever B key —
     * API 30+ AND a strong-biometric sensor exists (whether or not anything is
     * enrolled). Distinct from [isAuthBindingAvailable] (which also requires an
     * ENROLLMENT): it separates "no security chip / no biometric hardware here"
     * from "hardware is here, just enroll a fingerprint/face", so the PRIVATE
     * stop-reason can name the right fix (DeviceLockPolicy.stopReason —
     * secureElementPresent). Pure query, no key op.
     */
    @SuppressLint("MissingPermission")
    fun isSecureElementPresent(context: Context): Boolean {
        if (android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.R) return false
        return try {
            val bm = context.getSystemService(BiometricManager::class.java) ?: return false
            // NO_HARDWARE = no strong-biometric sensor → PRIVATE can't be armed at all
            // ("no security chip"). Every other code (SUCCESS / NONE_ENROLLED /
            // HW_UNAVAILABLE / SECURITY_UPDATE_REQUIRED) means the sensor IS present.
            bm.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) !=
                BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE
        } catch (_: Exception) {
            false
        }
    }

    /**
     * True when the persisted auth-bound key resides in StrongBox (the StrongBox notice).
     * Queries the LIVE key's [KeyInfo.securityLevel] rather than a generation-time
     * flag, so it is correct even for a key that already existed. Distinct from
     * [lastKeyBacking]: this asks specifically about StrongBox (vs TEE), which
     * needs securityLevel and so is API 31+ only.
     */
    fun isStrongBoxBacked(): Boolean {
        // KeyInfo.securityLevel is API 31; minSdk is 30. Below API 31 the level can't
        // be read, so StrongBox can't be distinguished from a plain TEE key — report
        // false (best-effort diagnostic; not a protection gate). The hardware-vs-
        // software question is answered across the whole range by [lastKeyBacking].
        if (android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.S) return false
        return try {
            val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
            val key = ks.getKey(ALIAS, null) as? PrivateKey ?: return false
            val info = KeyFactory.getInstance(key.algorithm, KEYSTORE)
                .getKeySpec(key, KeyInfo::class.java) as KeyInfo
            info.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Ensures the auth-bound keypair exists (StrongBox-preferred, TEE fallback)
     * AND verifies it actually landed in secure hardware. Idempotent. Returns
     * false when the key could not be created, or when a key we JUST minted is
     * only SOFTWARE-backed — the caller (AndroidDbKeyProtector.wrap ->
     * setDbKeyAuthBinding) then treats auth-binding as unavailable and stays on
     * the plain layer, so Lever B is never freshly enabled on a key that provides
     * no hardware barrier.
     *
     * A genuine NEW Lever-B enable never meets a PRE-EXISTING alias here: every
     * VaultSelector path that wraps `authBound = true` over a plain blob (the two
     * enable paths, the post-recovery re-establish and the legacy re-mint) calls
     * [AndroidDbKeyProtector.deleteAuthBoundKeyBeforeEnable] first, so a new enable
     * always mints and the freshly-minted-software refusal below gates it. A
     * re-wrap of an EXISTING `ab:` vault (change-PIN, KDF migration, raw-key
     * adoption) finds the alias present and keeps it usable even if software — that
     * path MUST stay non-bricking. Residual (P-8): [deleteKey] swallows a failed
     * `deleteEntry`, so an alias that survived a failed delete is reused rather than
     * re-minted.
     *
     * StrongBox/TEE is only ever REQUESTED (setIsStrongBoxBacked); KeyMint can
     * silently issue a SECURITY_LEVEL_SOFTWARE key when it cannot honour the
     * requested parameter set, so a post-creation KeyInfo probe is the only way
     * to know what we actually got. Whatever the outcome, the verdict is published
     * to [lastKeyBacking] (live in release). Backward-compatible: the unwrap path
     * never calls this, so an existing "ab:" vault is never bricked or blocked
     * from unlocking, and a PRE-EXISTING key (even software-backed) is left usable
     * — surfaced through [lastKeyBacking], not refused — rather than blocking
     * change-PIN or stranding the "ab:" blob wrapped under it.
     */
    fun ensureKey(): Boolean {
        return try {
            val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
            val preexisting = ks.containsAlias(ALIAS)
            if (!preexisting) {
                try {
                    generate(strongBox = true)
                } catch (_: StrongBoxUnavailableException) {
                    generate(strongBox = false)
                } catch (_: Exception) {
                    // Some OEMs signal absent StrongBox with a generic exception;
                    // clean up a half-created alias and fall back to the TEE.
                    // Retry once first — a generic failure is equally consistent
                    // with a transient keystore outage, and this keygen runs only when
                    // Lever B is enabled, so conceding here pins the weaker tier for the
                    // life of the auth-bound key. (Sibling of CryptoManager.ensureMasterKey.)
                    try { ks.deleteEntry(ALIAS) } catch (_: Exception) {}
                    try {
                        generate(strongBox = true)
                    } catch (_: StrongBoxUnavailableException) {
                        generate(strongBox = false)
                    } catch (e: Exception) {
                        try { ks.deleteEntry(ALIAS) } catch (_: Exception) {}
                        LogBuffer.append(
                            "W", "AuthBoundKeyStore",
                            "StrongBox keygen failed twice (${e.javaClass.simpleName}) — using a TEE-backed auth-bound key",
                        )
                        generate(strongBox = false)
                    }
                }
            }
            // Verify the ACTIVE key really landed in secure hardware — a software-backed
            // auth-bound key gives Lever B no barrier the forensic tool can't defeat.
            val backing = probeKeyBacking()
            lastKeyBacking = backing
            if (!preexisting && !KeystoreSecurity.acceptsForNewKey(backing)) {
                // We JUST minted this key and KeyMint issued SECURITY_LEVEL_SOFTWARE
                // despite the StrongBox/TEE request. Delete it and report unavailable
                // → AndroidDbKeyProtector.wrap's check() fails → setDbKeyAuthBinding
                // stays on the plain layer, so Lever B is never enabled (nor the tier
                // promoted) on a key with no hardware barrier. Nothing is persisted yet,
                // so this can't brick anything.
                LogBuffer.append(
                    "W", "AuthBoundKeyStore",
                    "freshly-minted auth-bound key is SOFTWARE-backed — no hardware barrier; refusing to enable Lever B",
                )
                try { ks.deleteEntry(ALIAS) } catch (_: Exception) {}
                return false
            }
            // A PRE-EXISTING software key is left usable (return true): unlock never
            // calls ensureKey, so refusing here would only block change-PIN/re-wrap of
            // a vault that already works. The software condition is still surfaced via
            // [lastKeyBacking] for a higher layer to reconcile the advertised tier —
            // never a silent hardware claim.
            true
        } catch (e: Exception) {
            LogBuffer.append("W", "AuthBoundKeyStore", "ensureKey failed: ${e::class.simpleName}")
            false
        }
    }

    /**
     * Best-effort probe of the LIVE auth-bound key's hardware backing across the
     * whole minSdk-30 range (API 31+ securityLevel; API 30 isInsideSecureHardware).
     * [KeystoreBacking.UNKNOWN] when it can't be read — treated as NOT a reason to
     * refuse (fail toward not-blocking access), while [lastKeyBacking] still records
     * the uncertainty so no layer over-claims hardware.
     */
    private fun probeKeyBacking(): KeystoreBacking = try {
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        val key = ks.getKey(ALIAS, null) as? PrivateKey ?: return KeystoreBacking.UNKNOWN
        val info = KeyFactory.getInstance(key.algorithm, KEYSTORE)
            .getKeySpec(key, KeyInfo::class.java) as KeyInfo
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S) {
            KeystoreSecurity.fromSecurityLevel(info.securityLevel)
        } else {
            @Suppress("DEPRECATION")
            KeystoreSecurity.fromInsideSecureHardware(info.isInsideSecureHardware)
        }
    } catch (_: Exception) {
        KeystoreBacking.UNKNOWN
    }

    private fun generate(strongBox: Boolean) {
        val builder = KeyGenParameterSpec.Builder(
            ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setKeySize(2048)
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
            .setUnlockedDeviceRequired(true)
            .setUserAuthenticationRequired(true)
            // Per-use (timeout 0): a fresh auth is required for EACH private-key op — no
            // window a mere recent device-unlock could satisfy. setUserAuthenticationParameters
            // is API 30 (R). This keygen only runs when Lever B is enabled, which
            // isAuthBindingAvailable gates to API 30+ — so the guard is belt-and-suspenders
            // at minSdk 30 (the SDK_INT check stays live).
            //
            // AUTH_BIOMETRIC_STRONG ONLY (no AUTH_DEVICE_CREDENTIAL): PRIVATE-tier
            // hardening — a cracked device passcode must never release the DB-key wrap.
            // Strong biometric is the sole releaser (mirrors iOS `.biometryCurrentSet`).
            .apply {
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.R) {
                    setUserAuthenticationParameters(
                        0,
                        KeyProperties.AUTH_BIOMETRIC_STRONG
                    )
                }
            }
            // Strict binding: DESTROY the key on any biometric re-enrollment (see
            // class doc). Safe because VaultSelector mandates a verified recovery
            // code before Lever B is enabled — the code, not the key, is the
            // post-re-enrollment way back in, so this is data-loss-proof, not a brick.
            .setInvalidatedByBiometricEnrollment(true)
            .apply { if (strongBox) setIsStrongBoxBacked(true) }
        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, KEYSTORE)
        kpg.initialize(builder.build())
        kpg.generateKeyPair()
    }

    /**
     * Wraps [inner] with the PUBLIC key — NO authentication (public-key op).
     * Returns raw ciphertext (RSA-2048-OAEP, 256 bytes). Throws on failure so
     * the caller can fall back to the plain layer rather than persist a blob it
     * cannot read back.
     */
    fun wrap(inner: ByteArray): ByteArray {
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        val cert = ks.getCertificate(ALIAS) ?: error("auth-bound key certificate missing")
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, cert.publicKey, OAEP_SPEC)
        return cipher.doFinal(inner)
    }

    /**
     * Does the LIVE auth-bound key still allow a DEVICE CREDENTIAL, i.e. is it a
     * LEGACY key (minted AUTH_BIOMETRIC_STRONG|AUTH_DEVICE_CREDENTIAL before the
     * biometric-only hardening), or the new BIOMETRIC-only key? Reads
     * KeyInfo.userAuthenticationType (API 30+; Lever B is API 30+). The
     * [BiometricGate] prompt MIRRORS this: a legacy passcode-only-PRIVATE user is
     * never locked out (their key REQUIRES the credential door), while a new strict
     * key gets a biometric-only prompt with no passcode door. Fail direction:
     * ambiguous → true (offer the credential door — NEVER lock out an existing vault).
     */
    fun currentKeyAllowsDeviceCredential(): Boolean {
        if (android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.R) return true
        return try {
            val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
            val key = ks.getKey(ALIAS, null) as? PrivateKey ?: return true
            val info = KeyFactory.getInstance(key.algorithm, KEYSTORE)
                .getKeySpec(key, KeyInfo::class.java) as KeyInfo
            (info.userAuthenticationType and KeyProperties.AUTH_DEVICE_CREDENTIAL) != 0
        } catch (_: Exception) {
            true   // can't read → assume legacy; keep the credential door (no lockout)
        }
    }

    /**
     * Builds a DECRYPT [Cipher] initialized with the auth-bound PRIVATE key,
     * for a [android.hardware.biometrics.BiometricPrompt.CryptoObject]. The
     * `doFinal` is authorized only AFTER the biometric callback fires. `init`
     * itself does not require auth.
     */
    fun newDecryptCipher(): Cipher {
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        val privateKey = ks.getKey(ALIAS, null) as java.security.PrivateKey
        return Cipher.getInstance(TRANSFORMATION).apply {
            init(Cipher.DECRYPT_MODE, privateKey, OAEP_SPEC)
        }
    }

    /**
     * Is the auth-bound key ALIAS present? Parity with iOS
     * [SecureEnclaveBridge.isKeyPresent]: a CONFIRMED-absent alias means the key is
     * gone for good, so the unwrap path routes to the recovery code rather than an
     * endless deferrable retry. Fail direction: ambiguous (keystore read error) →
     * true (present) — a transient read must NOT mis-route a healthy vault to recovery.
     */
    fun isKeyPresent(): Boolean = try {
        KeyStore.getInstance(KEYSTORE).apply { load(null) }.containsAlias(ALIAS)
    } catch (_: Exception) {
        true
    }

    /** Cryptographic erasure of the auth-bound key (called from the wipe path). */
    fun deleteKey(context: Context) {
        try {
            KeyStore.getInstance(KEYSTORE).apply { load(null) }.deleteEntry(ALIAS)
        } catch (_: Exception) { /* alias absent or keystore unavailable */ }
    }
}

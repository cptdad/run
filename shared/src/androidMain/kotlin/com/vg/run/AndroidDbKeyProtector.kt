package com.vg.run

import android.content.Context

// ---------------------------------------------------------------------------
// AndroidDbKeyProtector — the DB-key OUTER layer for Android, adding the
// hardware AUTH-BOUND path (Lever B) on top of the
// default CryptoProvider (Tink) layer.
//
//   • plain      → CryptoProvider (Tink, non-auth setUnlockedDeviceRequired
//                  master key). Exactly the pre-Lever-B behavior.
//   • auth-bound → AuthBoundKeyStore RSA key; unwrap requires a fresh
//                  biometric (or, for a LEGACY weak key only, the device
//                  credential) via BiometricGate.
// Both are written in the scheme-neutral padded `v:` form ([DbKeyScheme.tagged]);
// the "cp:" / "ab:" prefixes are legacy forms this class still READS only.
//
// Gone auth-bound key: checked BEFORE the unwrap (isKeyPresent), and also mapped
// from KeyPermanentlyInvalidatedException at cipher init. iOS checks AFTER a null
// unwrap — different order, same outcome (KeyPermanentlyInvalidException ⇒ route
// to the recovery code). Parity is by outcome.
//
// Wrapping auth-bound is an unauthenticated public-key op (no prompt); only
// unwrap prompts. The credential verifier and the pre-PIN counters keep using
// CryptoProvider directly (never routed here), so enabling Lever B never
// prompts for a counter read — the key split the plan requires.
// ---------------------------------------------------------------------------

class AndroidDbKeyProtector(
    private val context: Context,
    crypto: CryptoProvider,
) : DbKeyProtector {

    // The plain path is the same CryptoProvider layer used before Lever B —
    // delegate to it verbatim so non-auth blobs stay byte-identical.
    private val plain = CryptoProviderDbKeyProtector(
        crypto, VaultCryptoContexts.DBKEY_INNER.encodeToByteArray()
    )

    override fun supportsAuthBinding(): Boolean =
        AuthBoundKeyStore.isAuthBindingAvailable(context)

    override fun isAuthBoundBlob(stored: String): Boolean = DbKeyScheme.isAuthBound(stored)

    // Enable-path only (blob still plain): drop the stale/invalidated Keystore key
    // so wrap() below re-mints a FRESH biometric-only, strict-invalidate key. Safe
    // because no auth-bound blob depends on it yet (see DbKeyProtector.deleteAuthBoundKeyBeforeEnable).
    override fun deleteAuthBoundKeyBeforeEnable() = AuthBoundKeyStore.deleteKey(context)

    override fun wrap(inner: ByteArray, authBound: Boolean): String {
        if (!authBound) return plain.wrap(inner, authBound = false)
        // Auth-bound wrap: ensure the key exists then public-key encrypt (no
        // prompt). If anything goes wrong, FAIL rather than silently downgrade
        // to plain — a caller that asked for auth-binding must not get a blob
        // that unlocks without fresh auth. (setDbKeyAuthBinding treats the
        // thrown failure as "couldn't enable" and leaves the old blob intact.)
        check(AuthBoundKeyStore.ensureKey()) { "auth-bound key unavailable" }
        val ct = AuthBoundKeyStore.wrap(inner)
        return DbKeyScheme.tagged(DbKeyScheme.TAG_AUTH_BOUND, encodeBase64(ct))
    }

    @Throws(KeyUnavailableException::class)
    override fun unwrap(stored: String): ByteArray {
        if (!DbKeyScheme.isAuthBound(stored)) return plain.unwrap(stored)
        // Parity with iOS (IosDbKeyProtector / SecureEnclaveBridge.isKeyPresent): a
        // CONFIRMED-absent key alias means the auth-bound key is gone for good — route
        // to the recovery code, not an endless deferrable retry. This also nets the
        // legacy-key reconcile window (VaultSelector.maybeReconcileLegacyAuthBoundKey):
        // if the legacy key was deleted but the strict re-mint failed, the vault stays
        // recoverable via its (precondition) recovery code. Ambiguous → treated as
        // present, so a transient keystore read defers rather than mis-routing.
        if (!AuthBoundKeyStore.isKeyPresent()) {
            throw KeyPermanentlyInvalidException("auth-bound key alias is gone — recovery required")
        }
        val ct = decodeBase64(DbKeyScheme.payloadOf(stored))
        // Build the decrypt cipher, gate it behind a fresh biometric /
        // device-credential, then finish the RSA-OAEP decrypt with the
        // now-authorized cipher. Any failure → KeyUnavailableException (defer).
        val cipher = try {
            AuthBoundKeyStore.newDecryptCipher()
        } catch (e: android.security.keystore.KeyPermanentlyInvalidatedException) {
            // The user removed their lock screen (or re-enrolled biometrics), so
            // the auth-bound RSA key is destroyed — retrying can never work. This is
            // the ONE layer that can still see the distinction; collapsing it into
            // KeyUnavailableException (the old behaviour) left the user in an endless
            // "try again" loop with no hint that the recovery code is the way out.
            throw KeyPermanentlyInvalidException("auth-bound key permanently invalidated: ${e.message}")
        } catch (e: Exception) {
            throw KeyUnavailableException("auth-bound decrypt cipher init failed: ${e.message}")
        }
        val authedCipher = BiometricGate.authenticate(
            cipher,
            title = "Unlock Rún",
            subtitle = "Confirm it's you to open your vault",
            // Mirror the LIVE key: a legacy key that still allows a device credential
            // keeps its passcode door on the prompt (a passcode-only-PRIVATE user must
            // not be locked out); a new biometric-only key gets a biometric-only prompt.
            allowDeviceCredential = AuthBoundKeyStore.currentKeyAllowsDeviceCredential(),
        )
        return try {
            authedCipher.doFinal(ct)
        } catch (e: Exception) {
            // A doFinal failure after successful auth is not a wrong-PIN — treat
            // as deferrable so the unlock path retries rather than wipes.
            throw KeyUnavailableException("auth-bound unwrap failed: ${e.message}")
        }
    }
}

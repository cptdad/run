import Foundation
import Security
import LocalAuthentication
import shared

// ---------------------------------------------------------------------------
// SecureEnclaveHelper — Swift side of Lever B (iOS).
//
// A Secure-Enclave EC (P-256) key that ECIES-wraps the DB-key OUTER layer. The
// SE holds EC keys only, so we wrap the symmetric DB-key blob to the SE key via
// ECIES (public-key encrypt = no auth), and unwrap with the SE private key,
// which is gated by a `.biometryCurrentSet` SecAccessControl — BIOMETRY ONLY,
// NO device-passcode fallback. The private key never leaves the Enclave.
//
// Why biometric-only (PRIVATE tier hardening): the earlier `.userPresence`
// flag let a device *passcode* release the key, so a forensic tool that cracked
// the passcode could open a PRIVATE vault — defeating the whole point of the
// hardware barrier. `.biometryCurrentSet` binds the key to biometry alone.
//
// Consequence handled by the shared side (VaultSelector, MANDATORY):
//   • `.biometryCurrentSet` INVALIDATES the key on ANY Face/Touch-ID
//     re-enrollment (adding/removing a face/finger), so re-enrollment makes the
//     recovery code the ONLY way back into the vault. VaultSelector therefore
//     REFUSES to enable Lever B without first minting + read-back-verifying a
//     recovery code (enableDbKeyAuthBindingWithRecovery), and the UI warns the
//     user. This is a deliberate trade-off (data-loss-proof via the code) for a key
//     a cracked passcode can never touch.
//
// Caveats handled:
//   • Simulator has NO Secure Enclave → isAvailable() returns false, so the
//     shared IosDbKeyProtector stays on the plain Keychain path (non-production
//     software fallback is simply "auth-binding unavailable" — we never ship a
//     fake SE).
//   • No biometrics enrolled → `.biometryCurrentSet` key CREATION fails, so
//     isAvailable() (biometrics-gated below) reports false and PRIVATE greys out
//     in the chooser rather than silently falling back to a passcode-openable key.
// ---------------------------------------------------------------------------

@objc public class SecureEnclaveHelper: NSObject, SecureEnclaveBridge {

    @objc public static let shared = SecureEnclaveHelper()

    private let tag = Data("com.vg.run.dbkey.se".utf8)
    private let algorithm: SecKeyAlgorithm = .eciesEncryptionStandardVariableIVX963SHA256AESGCM

    /// True on a real device that has the Secure Enclave AND STRONG BIOMETRICS
    /// enrolled (required by the `.biometryCurrentSet` access control — a
    /// passcode alone no longer qualifies). The Simulator has no SE, so this is
    /// always false there. Drives PRIVATE-tier selectability: the tier greys out
    /// unless a biometric-bound Lever B key can actually be created + used here.
    @objc public func isAvailable() -> Bool {
        #if targetEnvironment(simulator)
        return false
        #else
        var error: NSError?
        // deviceOwnerAuthenticationWithBiometrics succeeds iff BIOMETRY is
        // enrolled — the precondition for a WhenPasscodeSet + `.biometryCurrentSet`
        // SE key. Passcode-only devices intentionally fail here (a cracked passcode
        // must not open PRIVATE); they are steered to CASUAL/MAXIMUM instead.
        return LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
        #endif
    }

    @objc public func ensureKey() -> Bool {
        if loadPrivateKey() != nil { return true }
        return createKey()
    }

    private func createKey() -> Bool {
        // `.biometryCurrentSet` (NOT `.userPresence`): the key is released ONLY by
        // the biometrics enrolled AT CREATION time — no device-passcode fallback,
        // and ANY later Face/Touch-ID re-enrollment invalidates it. That closes the
        // "cracked passcode opens PRIVATE" gap; the shared side guarantees a verified
        // recovery code exists first, so an invalidation is recoverable, never a brick.
        // Kept: kSecAttrTokenIDSecureEnclave (below),
        // kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, `.privateKeyUsage`.
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet],
            nil
        ) else {
            LogBuffer.shared.append(level: "E", tag: "SecureEnclave", message: "SecAccessControl create failed")
            return false
        }
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag,
                kSecAttrAccessControl as String: access,
            ],
        ]
        var error: Unmanaged<CFError>?
        guard SecKeyCreateRandomKey(attributes as CFDictionary, &error) != nil else {
            LogBuffer.shared.append(level: "E", tag: "SecureEnclave", message: "SecKeyCreateRandomKey failed")
            return false
        }
        return true
    }

    /// Raw `SecItemCopyMatching` probe for the SE key item: returns the key when it
    /// was handed to us AND the unmodified OSStatus. Split out so callers can
    /// tell a DEFINITE "the item is not there" (`errSecItemNotFound`) from "securityd
    /// could not answer right now" (`errSecInteractionNotAllowed` on a locked keybag,
    /// the `-34018`-class glitches documented in `KeychainHelper.kvGet`'s doc, an
    /// interrupted auth session) — two states the old `!= errSecSuccess` collapsed
    /// into one. No authentication, no prompt: `kSecReturnRef` hands back a key
    /// reference; only USING the private key hits the `.biometryCurrentSet` gate.
    private func copyPrivateKey() -> (status: OSStatus, key: SecKey?) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let item else { return (status, nil) }
        // Force-cast is safe: kSecReturnRef on a key query yields a SecKey.
        return (status, (item as! SecKey))
    }

    /// Thin wrapper for the wrap/unwrap paths, which only care whether they got a
    /// usable key — the status discrimination is isKeyPresent()'s business.
    private func loadPrivateKey() -> SecKey? {
        return copyPrivateKey().key
    }

    /// ECIES-encrypt to the SE public key. No authentication (public-key op).
    @objc public func wrap(data: Data) -> Data? {
        guard let priv = loadPrivateKey(), let pub = SecKeyCopyPublicKey(priv) else { return nil }
        guard SecKeyIsAlgorithmSupported(pub, .encrypt, algorithm) else {
            LogBuffer.shared.append(level: "E", tag: "SecureEnclave", message: "ECIES encrypt unsupported")
            return nil
        }
        var error: Unmanaged<CFError>?
        guard let cipherText = SecKeyCreateEncryptedData(pub, algorithm, data as CFData, &error) else {
            LogBuffer.shared.append(level: "E", tag: "SecureEnclave", message: "SecKeyCreateEncryptedData failed")
            return nil
        }
        return cipherText as Data
    }

    /// ECIES-decrypt with the SE private key. TRIGGERS the BIOMETRY prompt (via
    /// `.biometryCurrentSet` — no passcode fallback) and BLOCKS the calling thread.
    /// Returns nil on cancel / lockout / invalidation / failure. The shared side
    /// (IosDbKeyProtector) then checks isKeyPresent(): item CONFIRMED gone → permanent
    /// (KeyPermanentlyInvalidException → recovery-code path); anything else (present,
    /// or the Keychain could not answer — see the fail direction below) → deferrable
    /// (KeyUnavailableException → retry). Never a wipe. Must be called off the main
    /// thread. NOTE: a biometric RE-ENROLLMENT invalidates a `.biometryCurrentSet`
    /// key; if the system leaves the item PRESENT-but-unusable it maps to deferrable
    /// (retry) rather than recovery — see IosDbKeyProtector.
    @objc public func unwrap(data: Data) -> Data? {
        guard let priv = loadPrivateKey() else { return nil }
        guard SecKeyIsAlgorithmSupported(priv, .decrypt, algorithm) else {
            LogBuffer.shared.append(level: "E", tag: "SecureEnclave", message: "ECIES decrypt unsupported")
            return nil
        }
        var error: Unmanaged<CFError>?
        guard let plainText = SecKeyCreateDecryptedData(priv, algorithm, data as CFData, &error) else {
            // Includes user-cancel and lockout — logged sparsely, no secret content.
            LogBuffer.shared.append(level: "W", tag: "SecureEnclave", message: "SE decrypt failed/cancelled")
            return nil
        }
        return plainText as Data
    }

    /// Does the SE key item still exist? `unwrap` returns nil for both a
    /// user-cancelled/transient prompt and a key that no longer exists (removing the
    /// device passcode purges the `WhenPasscodeSet` key). The shared side
    /// (IosDbKeyProtector) maps item-GONE → permanent (KeyPermanentlyInvalidException →
    /// recovery-code path) and item-PRESENT-but-failing → deferrable
    /// (KeyUnavailableException → retry). Pure `SecItemCopyMatching` — no auth, no prompt.
    ///
    /// FAIL DIRECTION: "present" unless the status is EXACTLY
    /// `errSecItemNotFound`. The two errors are not symmetric:
    ///   • a false "absent" is IRREVERSIBLE — it routes a healthy vault into the
    ///     recovery-code path, which commits the plain (non-auth-bound) DB-key wrap and
    ///     deletes the recovery blob, silently dropping Lever B with no way back and no
    ///     notice to the user;
    ///   • a false "present" is merely RETRYABLE — the unlock returns the neutral,
    ///     non-counting Error and the user tries again; and the unlock screen offers
    ///     "Use recovery code" unconditionally whenever a recovery code exists
    ///     (PinEntryView's `use_recovery_code_button` row), so even a genuinely dead key still has an exit.
    /// The old `!= errSecSuccess` test made every transient securityd condition —
    /// backgrounding with the Face ID sheet up, `errSecInteractionNotAllowed` on a
    /// locked keybag, the `-34018` class — look like permanent key loss.
    /// This matches the Android sibling, which already fails toward true
    /// (`AuthBoundKeyStore.isKeyPresent`, keystore read error → present).
    @objc public func isKeyPresent() -> Bool {
        return copyPrivateKey().status != errSecItemNotFound
    }

    @objc public func deleteKey() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
        ]
        SecItemDelete(query as CFDictionary)
    }
}

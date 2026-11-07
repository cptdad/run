package com.vg.run

// ---------------------------------------------------------------------------
// IosDbKeyProtector — the DB-key OUTER layer for iOS, adding the Secure-Enclave
// auth-bound path (Lever B) on top of the default
// Keychain (CryptoProvider) layer.
//
// Both schemes are written in the scheme-neutral padded `v:` form
// ([DbKeyScheme.tagged]); "cp:" / "ab:" are legacy forms this class still READS only.
//   • plain                 → CryptoProvider (Keychain device key). Exactly the
//                             pre-Lever-B behavior; byte-identical stored form.
//   • auth-bound            → SecureEnclaveBridge ECIES; unwrap requires fresh
//                             BIOMETRY via the SE `.biometryCurrentSet` gate —
//                             the device passcode is NOT an accepted factor.
//                             `.userPresence` (which would accept it) was
//                             deliberately removed and must not come back: this
//                             threat model assumes the passcode can be cracked,
//                             and Lever B's whole promise is that doing so still
//                             does not release a PRIVATE vault's DB key. See
//                             SecureEnclaveHelper.swift:14-18.
//
// Wrapping auth-bound is an unauthenticated public-key ECIES op (no prompt);
// only unwrap prompts. The credential verifier + pre-PIN counters keep using
// CryptoProvider directly (never routed here), so enabling Lever B never
// prompts for a counter read. Mirrors Android's [AndroidDbKeyProtector].
//
// Gone SE key: checked AFTER a null unwrap (isKeyPresent); Android checks BEFORE
// the unwrap. Different order, same outcome — parity is by outcome.
//
// No backing probe: SE keys are hardware by construction, so Android's
// KeystoreBacking / AuthBoundKeyStore.lastKeyBacking has no iOS twin.
//
// Legacy SE keys: an SE key minted before the strict scheme (`.userPresence`,
// passcode-accepting) has no prompt-side handling here — the SE access control is
// fixed at key creation, so the prompt is whatever that key demands. The strict
// re-mint is VaultSelector.maybeReconcileLegacyAuthBoundKey (gated on biometrics +
// a PROVEN recovery blob), not this class.
//
// On the Simulator (no Secure Enclave) [SecureEnclaveBridge.isAvailable] is
// false, so [supportsAuthBinding] is false and everything stays on the plain
// path — the e2e/simulator suites are unaffected.
// ---------------------------------------------------------------------------

class IosDbKeyProtector(crypto: CryptoProvider) : DbKeyProtector {

    private val plain = CryptoProviderDbKeyProtector(
        crypto, VaultCryptoContexts.DBKEY_INNER.encodeToByteArray()
    )

    private val se: SecureEnclaveBridge? get() = SecureEnclaveBridgeHolder.bridge

    override fun supportsAuthBinding(): Boolean = se?.isAvailable() == true

    override fun isAuthBoundBlob(stored: String): Boolean = DbKeyScheme.isAuthBound(stored)

    // Enable-path only (blob still plain): drop the stale/invalidated Secure-Enclave
    // key so wrap() below re-mints a FRESH `.biometryCurrentSet` key bound to the
    // CURRENT enrollment. Safe because no auth-bound blob depends on it yet (see
    // DbKeyProtector.deleteAuthBoundKeyBeforeEnable). No-op if the bridge is absent.
    override fun deleteAuthBoundKeyBeforeEnable() { se?.deleteKey() }

    override fun wrap(inner: ByteArray, authBound: Boolean): String {
        if (!authBound) return plain.wrap(inner, authBound = false)
        val bridge = se ?: error("Secure Enclave bridge unavailable")
        check(bridge.ensureKey()) { "Secure Enclave key unavailable" }
        // Same shape as PlatformCrypto.ios.kt
        // aesGcmEncrypt): `inner` is the PIN-layer ciphertext
        // aesGcmEncrypt(DbKeyPayload, kek, DBKEY_INNER) — 61 B (passphrase payload)
        // or 93 B (raw-adopted), NOT the raw 32-byte DB key, but secret-equivalent
        // together with the KEK, so the copy is still scrubbed. toNSData() copies it into a fresh NSData for the bridge that ARC then
        // frees WITHOUT zeroing — commonMain can only scrub the ByteArray it owns.
        // The copy is a private +[NSData dataWithBytes:length:] allocation minted
        // here and referenced by nothing else once the synchronous bridge call has
        // returned, so the memset can never reach shared storage. (The RETURN value
        // is ECIES ciphertext — not secret — so it is not wiped.)
        val innerData = inner.toNSData()
        val wrapped = try {
            bridge.wrap(innerData)
        } finally {
            innerData.secureWipeBytes()
        }
        val ct = (wrapped ?: error("Secure Enclave wrap failed")).toByteArray()
        return DbKeyScheme.tagged(DbKeyScheme.TAG_AUTH_BOUND, encodeBase64(ct))
    }

    @Throws(KeyUnavailableException::class)
    override fun unwrap(stored: String): ByteArray {
        if (!DbKeyScheme.isAuthBound(stored)) return plain.unwrap(stored)
        val bridge = se ?: throw KeyUnavailableException("Secure Enclave bridge unavailable")
        val ct = decodeBase64(DbKeyScheme.payloadOf(stored))
        // Prompts (biometry only — `.biometryCurrentSet`, see the header) and BLOCKS until authenticated; null means
        // cancel/lockout/failure → deferrable, never a wrong-PIN wipe.
        val ptData = bridge.unwrap(ct.toNSData())
            ?: throw if (!bridge.isKeyPresent()) {
                // (Android sibling: KeyPermanentlyInvalidatedException): the SE key
                // ITEM is gone — removing the device passcode purges it — so no amount
                // of retrying brings it back. Surface it as permanent so the unlock UI
                // can send the user to their recovery code instead of an endless
                // "try again". A present-but-failing key stays deferrable below.
                KeyPermanentlyInvalidException("Secure Enclave key is gone (passcode removed?)")
            } else {
                KeyUnavailableException("Secure Enclave unwrap failed or cancelled")
            }
        // Lever B path: `ptData` holds the
        // unwrapped INNER blob — the PIN-layer ciphertext that, with the KEK, yields
        // the SQLCipher key (secret-equivalent, so it is scrubbed) — and used to be
        // dropped to ARC unzeroed on every auth-bound unlock, leaving it in a freed
        // heap block after the biometric gate had already been satisfied. Copy out
        // FIRST, wipe in the finally: a wipe before the copy would hand the vault an
        // all-zero DB key.
        // Uniqueness (mandatory before any memset): SecureEnclaveHelper.unwrap
        // (SecureEnclaveHelper.swift:164) returns `SecKeyCreateDecryptedData(...) as
        // Data` — a Create-Rule CFData allocated fresh per call, not an alias of the
        // input ciphertext and not a cached/singleton object — and the Swift frame
        // that held it is gone by the time we get here, so this reference is the sole
        // owner and the memset cannot corrupt live data.
        // Inline-representation caveat (see PlatformCrypto.ios.kt aesGcmDecrypt): a
        // payload small enough for Data's inline storage (<= 14 bytes on 64-bit) is
        // COPIED across the Swift→ObjC bridge, so a memset would zero only the copy.
        // The inner blob is 61 B (passphrase payload) or 93 B (raw-adopted payload),
        // comfortably ABOVE that threshold, so the value stays heap-backed and the
        // bytes zeroed here are the real ones.
        return try {
            ptData.toByteArray()
        } finally {
            ptData.secureWipeBytes()
        }
    }
}

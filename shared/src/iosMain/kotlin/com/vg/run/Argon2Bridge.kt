package com.vg.run

import platform.Foundation.NSData

// ---------------------------------------------------------------------------
// Argon2Bridge — interface fulfilled by the Swift layer (SwiftArgon2) over the
// vendored PHC reference Argon2 C implementation (iosApp/Argon2).
//
// iOS has no system Argon2 (CryptoKit/CommonCrypto don't provide it), so the
// vault's KDF_VERSION_3 credential KDF routes through this bridge. Registered by
// `AppState.registerBridges()` (called from `RunApp.init()`, then again at the
// top of `AppState.init()`), BEFORE `IosAppController()` is created — same load-bearing order as
// AesGcmBridgeHolder (Kotlin calls it synchronously on unlock).
// ---------------------------------------------------------------------------

interface Argon2Bridge {
    /**
     * Argon2id (RFC 9106, version 0x13) raw derivation. Returns [keyLength]
     * bytes, or null on failure (invalid params / allocation failure) — the
     * Kotlin caller converts null into a catchable exception.
     */
    fun argon2id(
        password: NSData,
        salt: NSData,
        memoryKiB: Int,
        iterations: Int,
        parallelism: Int,
        keyLength: Int
    ): NSData?
}

object Argon2BridgeHolder {
    var bridge: Argon2Bridge? = null
}

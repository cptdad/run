package com.vg.run

import platform.Foundation.NSData

// ---------------------------------------------------------------------------
// AesGcmBridge — interface fulfilled by the Swift layer using CryptoKit.
//
// This avoids the CommonCrypto private SPI (CCCryptorGCMOneshotEncrypt) which
// is unreliable on newer simulator runtimes. CryptoKit.AES.GCM is the public
// iOS 13+ API. The bridge is registered by `AppState.registerBridges()` (called from `RunApp.init()`, then again at the
// top of `AppState.init()`),
// before `IosAppController()` is constructed and so before any crypto call.
// ---------------------------------------------------------------------------

interface AesGcmBridge {
    // Returns IV(12) + ciphertext + tag(16)
    fun encrypt(plaintext: NSData, key: NSData, aad: NSData): NSData
    // Expects IV(12) + ciphertext + tag(16), returns plaintext
    fun decrypt(ciphertext: NSData, key: NSData, aad: NSData): NSData?
}

object AesGcmBridgeHolder {
    var bridge: AesGcmBridge? = null
}

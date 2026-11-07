package com.vg.run

import platform.Foundation.NSData

// ---------------------------------------------------------------------------
// X25519Bridge — interface fulfilled by the Swift layer using CryptoKit's
// Curve25519.KeyAgreement (iOS 13+). CommonCrypto (the runcrypto cinterop) has
// no X25519, so the referral key agreement (see referral.md) is bridged to
// Swift, exactly like AesGcmBridge. Registered by `AppState.registerBridges()` (called from `RunApp.init()`, then again at the
// top of `AppState.init()`),
// BEFORE `IosAppController()` is constructed (load-bearing order).
// ---------------------------------------------------------------------------

interface X25519Bridge {
    /** Fresh keypair as privateKey(32) ++ publicKey(32) = 64 bytes; empty on failure. */
    fun generateKeypair(): NSData
    /** Raw 32-byte X25519 shared point (RFC 7748, no hashing); null on failure. */
    fun ecdh(privateKey: NSData, peerPublicKey: NSData): NSData?
}

object X25519BridgeHolder {
    var bridge: X25519Bridge? = null
}

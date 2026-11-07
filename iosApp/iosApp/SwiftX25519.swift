import CryptoKit
import Foundation
import shared

// ---------------------------------------------------------------------------
// SwiftX25519 — CryptoKit implementation of X25519Bridge (referral key
// agreement; see referral.md). CommonCrypto has no X25519, so this bridges to
// CryptoKit's Curve25519.KeyAgreement. Registered in AppState.init() BEFORE
// IosAppController is constructed (load-bearing — see AppState.registerBridges).
//
// The shared secret returned is the RAW X25519 scalar-mult output (no hashing),
// matching Tink's X25519.computeSharedSecret on Android. Callers run it through
// hkdfSha256 (commonMain) to derive a usable key.
// ---------------------------------------------------------------------------

final class SwiftX25519: NSObject, X25519Bridge {

    func generateKeypair() -> Data {
        let priv = Curve25519.KeyAgreement.PrivateKey()
        // Copy the 32-byte private key into a buffer we own, then scrub it on
        // every exit path. `rawPriv` is our own Data (rawRepresentation returns a
        // fresh serialization each access), so zeroing it does NOT disturb `priv`,
        // and the concatenation below allocates its own buffer — so at defer time
        // `rawPriv` uniquely owns its storage and memset_s zeros the private-key
        // bytes IN PLACE. memset_s survives -O dead-store elimination, matching
        // SwiftDatabaseBridge's PRAGMA-key wipe.
        var rawPriv = priv.rawRepresentation
        defer { rawPriv.withUnsafeMutableBytes { _ = memset_s($0.baseAddress, $0.count, 0, $0.count) } }
        // privateKey(32) ++ publicKey(32). Irreducible residuals: the returned
        // Data holds the private key in bytes 0..31 until ARC frees it after the
        // Kotlin actual's toByteArray() copies it (a value-returning bridge cannot
        // wipe its own return value); and CryptoKit's `priv` keeps the key in
        // storage we cannot reach to zero.
        return rawPriv + priv.publicKey.rawRepresentation
    }

    func ecdh(privateKey: Data, peerPublicKey: Data) -> Data? {
        do {
            let priv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey)
            let pub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerPublicKey)
            let shared = try priv.sharedSecretFromKeyAgreement(with: pub)
            // Raw 32-byte X25519 output (CryptoKit's SharedSecret wraps it).
            return shared.withUnsafeBytes { Data($0) }
        } catch {
            // Non-throwing bridge: signal failure as nil rather than trapping.
            return nil
        }
    }
}

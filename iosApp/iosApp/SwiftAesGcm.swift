import CryptoKit
import Foundation
import shared

// ---------------------------------------------------------------------------
// SwiftAesGcm — CryptoKit implementation of AesGcmBridge.
//
// Registered in AppState.init() so Kotlin crypto calls route through here
// instead of the CommonCrypto private SPI (CCCryptorGCMOneshotEncrypt).
//
// Wire format: IV(12 bytes) | ciphertext | tag(16 bytes)
// ---------------------------------------------------------------------------

final class SwiftAesGcm: NSObject, AesGcmBridge {

    func encrypt(plaintext: Data, key: Data, aad: Data) -> Data {
        let symmetricKey = SymmetricKey(data: key)
        do {
            let nonce = AES.GCM.Nonce()
            let sealed = try AES.GCM.seal(plaintext, using: symmetricKey, nonce: nonce, authenticating: aad)
            return Data(sealed.nonce) + sealed.ciphertext + sealed.tag
        } catch {
            // #24: the AesGcmBridge protocol method is non-throwing, and `try!`
            // would fatalError → SIGABRT (NOT catchable by the Kotlin caller),
            // crashing the app instead of failing the send gracefully. A
            // successful seal always returns >= 28 bytes (12B nonce + 16B tag),
            // so an empty Data is an unambiguous failure marker that
            // PlatformCrypto.ios.kt.aesGcmEncrypt turns into a catchable Kotlin
            // exception. This still surfaces the failure (no silent empty
            // ciphertext is ever sent) without trapping the process.
            return Data()
        }
    }

    func decrypt(ciphertext: Data, key: Data, aad: Data) -> Data? {
        guard ciphertext.count >= 28 else { return nil }
        let iv  = ciphertext.prefix(12)
        let ct  = ciphertext.dropFirst(12).dropLast(16)
        let tag = ciphertext.suffix(16)
        let symmetricKey = SymmetricKey(data: key)
        do {
            let nonce = try AES.GCM.Nonce(data: iv)
            let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ct, tag: tag)
            return try AES.GCM.open(sealedBox, using: symmetricKey, authenticating: aad)
        } catch {
            return nil
        }
    }
}

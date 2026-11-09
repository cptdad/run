import XCTest
import CryptoKit
import Foundation
import UIKit
@testable import Run

// ---------------------------------------------------------------------------
// RunCryptoTests — executing KAT + negative-case coverage for the PRODUCTION
// iOS crypto backend: CryptoKit AES-256-GCM
// (SwiftAesGcm), CryptoKit X25519 (SwiftX25519), and the vendored PHC Argon2id
// (SwiftArgon2). These bridges cannot be exercised from the Kotlin/Native test
// target (they're only registered by the running Swift app), which is why the
// commonTest bodies skip on iOS. This target hosts the Run app and drives the
// real Swift impls directly.
//
// The Argon2id and X25519 vectors are the SAME ones the JVM suite pins
// (shared/src/commonTest/.../VaultKdfTest.kt, X25519Test.kt), so a byte-level
// divergence between the iOS and Android crypto backends fails HERE — which is
// the real risk this closes (AAD/IV layout, endianness, Argon2 param mapping).
// ---------------------------------------------------------------------------

final class RunCryptoTests: XCTestCase {

    private func hexData(_ s: String) -> Data {
        precondition(s.count % 2 == 0)
        var d = Data(capacity: s.count / 2)
        var i = s.startIndex
        while i < s.endIndex {
            let j = s.index(i, offsetBy: 2)
            d.append(UInt8(s[i..<j], radix: 16)!)
            i = j
        }
        return d
    }
    private func hexString(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

    // MARK: - AES-256-GCM  (wire format: IV(12) ‖ ciphertext ‖ tag(16))

    func test_aesgcm_roundtrip() {
        let g = SwiftAesGcm()
        let key = Data((0..<32).map { UInt8($0) })
        let pt  = Data("attack at dawn — the runes are cast".utf8)
        let aad = Data("message-aead".utf8)
        let blob = g.encrypt(plaintext: pt, key: key, aad: aad)
        XCTAssertGreaterThanOrEqual(blob.count, 28, "IV(12) + tag(16) minimum")
        XCTAssertEqual(g.decrypt(ciphertext: blob, key: key, aad: aad), pt)
    }

    /// THE negative property the e2e can't observe: any tamper must reject (return nil).
    func test_aesgcm_tamper_is_rejected() {
        let g = SwiftAesGcm()
        let key = Data((0..<32).map { UInt8($0) })
        let pt  = Data("the beloved trusted to keep it".utf8)
        let aad = Data("ctx".utf8)
        let blob = g.encrypt(plaintext: pt, key: key, aad: aad)

        var flippedCt = blob; flippedCt[13] ^= 0x01           // a ciphertext byte (past the 12-byte IV)
        XCTAssertNil(g.decrypt(ciphertext: flippedCt, key: key, aad: aad), "ciphertext tamper must reject")

        var flippedTag = blob; flippedTag[flippedTag.count - 1] ^= 0x01
        XCTAssertNil(g.decrypt(ciphertext: flippedTag, key: key, aad: aad), "tag tamper must reject")

        var flippedIv = blob; flippedIv[0] ^= 0x01
        XCTAssertNil(g.decrypt(ciphertext: flippedIv, key: key, aad: aad), "IV tamper must reject")

        XCTAssertNil(g.decrypt(ciphertext: blob, key: key, aad: aad + Data([0x00])), "AAD change must reject")

        var wrongKey = key; wrongKey[0] ^= 0x01
        XCTAssertNil(g.decrypt(ciphertext: blob, key: wrongKey, aad: aad), "wrong key must reject")

        XCTAssertNil(g.decrypt(ciphertext: blob.prefix(20), key: key, aad: aad), "truncated blob must reject")
    }

    func test_aesgcm_nonce_is_fresh_per_seal() {
        let g = SwiftAesGcm()
        let key = Data(count: 32)
        let pt  = Data("same plaintext, twice".utf8)
        let a = g.encrypt(plaintext: pt, key: key, aad: Data())
        let b = g.encrypt(plaintext: pt, key: key, aad: Data())
        XCTAssertNotEqual(a.prefix(12), b.prefix(12), "IV must be random per seal (no reuse)")
        XCTAssertNotEqual(a, b)
    }

    /// AES-256-GCM known-answer (GCM spec Test Case 14): decrypt a fixed
    /// (key, IV‖ct‖tag, empty-AAD) vector → the 16×0x00 plaintext. Pins the exact
    /// IV(12)‖ct‖tag(16) layout + empty-AAD handling against the published spec.
    func test_aesgcm_known_answer_vector() {
        let g = SwiftAesGcm()
        let key  = Data(count: 32)                                // 32 × 0x00
        let iv   = Data(count: 12)                                // 12 × 0x00
        let ct   = hexData("cea7403d4d606b6e074ec5d3baf39d18")
        let tag  = hexData("d0d1c8a799996bf0265b98b5d48ab919")
        let pt   = g.decrypt(ciphertext: iv + ct + tag, key: key, aad: Data())
        XCTAssertEqual(pt, Data(count: 16), "GCM Test Case 14 plaintext = 16 × 0x00")
    }

    // MARK: - X25519  (raw scalar-mult output, matching Tink on Android) — RFC 7748 §6.1

    func test_x25519_rfc7748_known_answer() {
        let x = SwiftX25519()
        let alicePriv = hexData("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        let alicePub  = hexData("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        let bobPriv   = hexData("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        let bobPub    = hexData("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        let expected  = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        XCTAssertEqual(hexString(x.ecdh(privateKey: alicePriv, peerPublicKey: bobPub)!), expected)
        XCTAssertEqual(hexString(x.ecdh(privateKey: bobPriv, peerPublicKey: alicePub)!), expected)
    }

    func test_x25519_keypair_layout_and_agreement() {
        let x = SwiftX25519()
        let a = x.generateKeypair(); let b = x.generateKeypair()
        XCTAssertEqual(a.count, 64, "keypair is priv(32) ‖ pub(32)")
        let ab = x.ecdh(privateKey: Data(a.prefix(32)), peerPublicKey: Data(b.suffix(32)))
        let ba = x.ecdh(privateKey: Data(b.prefix(32)), peerPublicKey: Data(a.suffix(32)))
        XCTAssertNotNil(ab)
        XCTAssertEqual(ab, ba, "DH agreement: a.priv×b.pub == b.priv×a.pub")
        XCTAssertEqual(ab!.count, 32)
    }

    func test_x25519_bad_input_returns_nil() {
        let x = SwiftX25519()
        XCTAssertNil(x.ecdh(privateKey: Data(count: 5), peerPublicKey: Data(count: 32)), "malformed key → nil, no trap")
    }

    // MARK: - Argon2id  (vendored PHC ref) — the SAME vectors VaultKdfTest pins on the JVM

    func test_argon2id_matches_phc_reference_vectors() {
        let a = SwiftArgon2()
        let pw = Data("password".utf8), salt = Data("somesalt".utf8)
        XCTAssertEqual(hexString(a.argon2id(password: pw, salt: salt, memoryKiB: 65_536, iterations: 2, parallelism: 1, keyLength: 32)!),
                       "09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7")
        XCTAssertEqual(hexString(a.argon2id(password: pw, salt: salt, memoryKiB: 256, iterations: 2, parallelism: 1, keyLength: 32)!),
                       "9dfeb910e80bad0311fee20f9c0e2b12c17987b4cac90c2ef54d5b3021c68bfe")
        XCTAssertEqual(hexString(a.argon2id(password: pw, salt: salt, memoryKiB: 256, iterations: 2, parallelism: 2, keyLength: 32)!),
                       "6d093c501fd5999645e0ea3bf620d7b8be7fd2db59c20d9fff9539da2bf57037")
    }

    func test_argon2id_is_deterministic() {
        let a = SwiftArgon2()
        let pw = Data("111111".utf8), salt = Data((0..<16).map { UInt8($0) })
        let h1 = a.argon2id(password: pw, salt: salt, memoryKiB: 256, iterations: 2, parallelism: 1, keyLength: 32)
        let h2 = a.argon2id(password: pw, salt: salt, memoryKiB: 256, iterations: 2, parallelism: 1, keyLength: 32)
        XCTAssertNotNil(h1); XCTAssertEqual(h1, h2)
    }

    func test_argon2id_param_validation_returns_nil() {
        let a = SwiftArgon2()
        let pw = Data("password".utf8), salt = Data("somesalt".utf8)
        XCTAssertNil(a.argon2id(password: pw,       salt: salt, memoryKiB: 0,   iterations: 2, parallelism: 1, keyLength: 32), "m=0 → nil")
        XCTAssertNil(a.argon2id(password: pw,       salt: salt, memoryKiB: 256, iterations: 0, parallelism: 1, keyLength: 32), "t=0 → nil")
        XCTAssertNil(a.argon2id(password: Data(),   salt: salt, memoryKiB: 256, iterations: 2, parallelism: 1, keyLength: 32), "empty pw → nil")
        XCTAssertNil(a.argon2id(password: pw,       salt: salt, memoryKiB: 256, iterations: 2, parallelism: 1, keyLength: 0),  "len=0 → nil")
    }
}

// ---------------------------------------------------------------------------
// PassphraseFieldTests — the high-risk passphrase must be TYPED by hand,
// character by character, never pasted. PassphraseField
// is backed by PasteBlockedTextField, a secure UITextField that refuses every
// clipboard edit action in canPerformAction. This pins that refusal so a later
// refactor can't quietly re-open the paste path (or a copy-out path — the secret
// must never reach the clipboard a seized-device extraction would read).
// ---------------------------------------------------------------------------
final class PassphraseFieldTests: XCTestCase {

    func test_passphraseField_refusesEveryClipboardAction() {
        let field = PasteBlockedTextField()
        for action in [
            #selector(UIResponderStandardEditActions.paste(_:)),
            #selector(UIResponderStandardEditActions.copy(_:)),
            #selector(UIResponderStandardEditActions.cut(_:)),
            #selector(UIResponderStandardEditActions.select(_:)),
            #selector(UIResponderStandardEditActions.selectAll(_:)),
        ] {
            XCTAssertFalse(
                field.canPerformAction(action, withSender: nil),
                "\(action) must be refused — the passphrase is typed by hand, never pasted in or copied out"
            )
        }
    }
}

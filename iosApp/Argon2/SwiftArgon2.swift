import Foundation
import shared

// ---------------------------------------------------------------------------
// SwiftArgon2 — Argon2Bridge over the vendored PHC reference implementation
// (argon2id_hash_raw, exposed through Run-Bridging-Header.h).
//
// Registered in AppState.init() before IosAppController is created, like every
// other bridge. Used by the vault's KDF_VERSION_3 credential derivation
// (PlatformCrypto.ios.kt argon2id actual).
// ---------------------------------------------------------------------------

final class SwiftArgon2: NSObject, Argon2Bridge {

    func argon2id(password: Data, salt: Data,
                  memoryKiB: Int32, iterations: Int32, parallelism: Int32,
                  keyLength: Int32) -> Data? {
        guard !password.isEmpty, !salt.isEmpty, keyLength > 0,
              memoryKiB > 0, iterations > 0, parallelism > 0 else { return nil }
        var out = Data(count: Int(keyLength))
        // Scrub our working KDF buffer on EVERY exit path (success or failure).
        // At defer time `out` uniquely owns its storage — the value returned on
        // success is an INDEPENDENT copy, never a COW alias of `out` — so this
        // memset_s zeros the real derived-key bytes IN PLACE rather than a forked
        // throwaway. memset_s (not a loop) survives -O dead-store elimination,
        // matching SwiftDatabaseBridge's PRAGMA-key wipe.
        defer { out.withUnsafeMutableBytes { _ = memset_s($0.baseAddress, $0.count, 0, $0.count) } }
        let rc: Int32 = out.withUnsafeMutableBytes { outBuf in
            password.withUnsafeBytes { pwdBuf in
                salt.withUnsafeBytes { saltBuf in
                    argon2id_hash_raw(
                        UInt32(iterations), UInt32(memoryKiB), UInt32(parallelism),
                        pwdBuf.baseAddress, password.count,
                        saltBuf.baseAddress, salt.count,
                        outBuf.baseAddress, Int(keyLength)
                    )
                }
            }
        }
        // ARGON2_OK == 0. On any failure return nil — the Kotlin actual turns
        // that into a catchable exception (the bridge method is non-throwing,
        // mirroring SwiftAesGcm's failure-marker pattern).
        guard rc == 0 else { return nil }
        // Return an INDEPENDENT copy so `out` (scrubbed by the defer above) is not
        // the buffer handed across the bridge. Irreducible residual: this returned
        // Data still holds the derived key until ARC frees it right after the
        // Kotlin actual's toByteArray() copies it out — a value-returning bridge
        // cannot wipe its own return value from within itself.
        return out.withUnsafeBytes { Data(bytes: $0.baseAddress!, count: $0.count) }
    }
}

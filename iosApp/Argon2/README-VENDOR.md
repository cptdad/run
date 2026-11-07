# Vendored Argon2 (PHC reference implementation)

Upstream: https://github.com/P-H-C/phc-winner-argon2
Commit:   f57e61e19229e23c4445b85494dbf7c07de721cb (master, 2021-06-25;
          release 20190702 plus upstream fixes)
License:  CC0 1.0 / Apache 2.0 dual (see LICENSE)

Files: `include/argon2.h` + the portable subset of `src/` — `argon2.c core.c
encoding.c ref.c thread.c` and `blake2/` (reference blake2b + blamka round).
`opt.c` (SSE), `genkat.*`, `bench.c`, `run.c`, `test.c` are intentionally NOT
vendored; `core.c`'s `#include "genkat.h"` is `#ifdef GENKAT`-guarded and we
never define GENKAT. ONE local modification: `blake2/blake2.h` prefixes the
exported blake2b symbols (`#define blake2b_init argon2_blake2b_init` etc.) so
they don't collide at link time with the identically-named blake2b in
SQLCipher's bundled libtomcrypt ("duplicate symbol _blake2b_init" — the same
collision family that forced Tor into a dynamic framework). Re-apply it when
updating the vendored copy.

Why vendored: the vault's KDF_VERSION_3 credential KDF is Argon2id
(`PlatformCrypto.argon2id` expect). iOS has no system Argon2 — CryptoKit and
CommonCrypto don't provide it, and the OpenSSL inside tor.xcframework keeps
its EVP_KDF symbols local (not linkable, verified via nm).

TWO CONSUMERS, ONE COPY (2026-10-07): Android compiles these SAME files, in
place (never copied), into `librunargon2.so` — `shared/src/androidMain/cpp/
CMakeLists.txt` lists `argon2.c core.c ref.c encoding.c thread.c
blake2/blake2b.c` by relative path, built with `-DARGON2_NO_THREADS` and
`-fvisibility=hidden` (A2_VISCTL undefined, so no argon2/blake2 symbol is
exported; only the JNI entry point in `argon2_jni.c`, which calls the same
`argon2id_hash_raw` as SwiftArgon2.swift). So `verify-argon2-src.sh` now pins
the crypto core of BOTH apps; a re-vendor must rebuild and re-test both. The
blake2 rename is harmless on Android (its own .so, no SQLCipher collision).
BouncyCastle's Argon2BytesGenerator stays on Android only as the fallback when
the .so cannot load. Android vaults written by BouncyCastle must keep
unlocking, so native == BouncyCastle byte-for-byte is a hard gate:
`Argon2BouncyCastleKatTest` (JVM, :shared) pins BouncyCastle to RFC 9106 + PHC
+ the vault release/debug cost vectors, and `Argon2NativeEquivalenceTest`
(on-device, :androidApp) proves the .so equal to it. Both platforms are also
pinned to the PHC reference vectors in VaultKdfTest.

Exposed to Swift via `Tor/Run-Bridging-Header.h` (`argon2id_hash_raw`), called
from `SwiftArgon2.swift`, registered as `Argon2BridgeHolder.shared.bridge` in
`AppState.init` BEFORE `IosAppController` is created (load-bearing order, like
every other *BridgeHolder).

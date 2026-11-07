//
//  Run-Bridging-Header.h
//  Exposes the iCepa Tor.framework Objective-C wrapper (vendored from source,
//  Tor 0.4.9.13) to Swift. Replaces the SwiftTor SPM package (Tor 0.4.4.6, EOL).
//
#import "TORController.h"
#import "TORConfiguration.h"
#import "TORThread.h"
#import "TORLogging.h"
#import "TORCircuit.h"
#import "TORNode.h"
#import "TORControlCommand.h"
#import "TORControlReplyCode.h"

// Vendored PHC reference Argon2 (../Argon2) — argon2id_hash_raw for the vault
// credential KDF (KDF_VERSION_3). See Argon2/README-VENDOR.md for provenance.
#import "../Argon2/argon2.h"

// SQLCipher codec API — the ONE entry point SwiftDatabaseBridge.rekey(key:) needs.
//
// Why it has to be declared here: swift-sqlcipher declares sqlite3_rekey_v2 in its
// sqlite3.h behind `#ifdef SQLITE_HAS_CODEC`, and SwiftPM does not propagate a
// dependency target's cSettings defines to dependents. The package's own SQLCipher
// target DOES define it (so the function is compiled into the library we link, and
// the `PRAGMA key` path already reaches it), but the Run target does not — so the
// declaration is invisible to our Swift and `sqlite3_rekey_v2` is "not in scope".
// Declaring the single prototype is narrower than defining SQLITE_HAS_CODEC
// app-wide, which would also expose sqlite3_key/sqlite3_rekey/sqlite3_activate_see
// and change how every TU imports the module.
//
// `db` is spelled `void *` rather than `sqlite3 *` on purpose: the sqlite3 type only
// exists once the SQLCipher clang module is imported, which this header is parsed
// before. The two are ABI-identical in C, and Swift imports `void *` as
// UnsafeMutableRawPointer, which the bridge builds from its OpaquePointer handle.
// If SQLITE_HAS_CODEC is ever defined for this target, the two declarations will
// CONFLICT and the build will fail loudly — delete this line then, don't silence it.
int sqlite3_rekey_v2(void *db, const char *zDbName, const void *pKey, int nKey);

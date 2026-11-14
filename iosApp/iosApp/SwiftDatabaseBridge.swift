import Foundation
import SQLCipher
import shared

// ---------------------------------------------------------------------------
// SwiftDatabaseBridge — SQLCipher implementation of DatabaseBridge.
//
// Opens an AES-256 encrypted SQLite database. All vault data is encrypted
// at rest, matching Android's SQLCipher implementation. Deleted rows are
// unrecoverable after VACUUM.
// ---------------------------------------------------------------------------

final class SwiftDatabaseBridgeFactory: NSObject, DatabaseBridgeFactory {
    func create() -> any DatabaseBridge { SwiftDatabaseBridge() }
}

final class SwiftDatabaseBridge: NSObject, DatabaseBridge {

    private var db: OpaquePointer?

    // Returns 0 (SQLITE_OK) on success, else the SQLite result code so the
    // Kotlin side can tell a genuine wrong-key/corrupt file (SQLITE_NOTADB) from
    // a transient failure that must not delete a real vault.
    func open(path: String, key: KotlinByteArray) -> Int32 {
        let rc = sqlite3_open(path, &db)
        guard rc == SQLITE_OK else {
            // Do NOT log the path (it can leak DB filenames) or sqlite3_errmsg text:
            // the numeric result code is the whole diagnostic.
            LogBuffer.shared.append(level: "E", tag: "SwiftDB", message: "sqlite3_open failed (\(rc))")
            // sqlite3_open leaves a handle allocated even on a
            // non-OK return — close it before bailing, or it (and the NOTADB-recreate
            // overwriting &db) leaks the connection.
            sqlite3_close(db); db = nil
            return rc
        }

        // M13-a: scrub SQLite's heap on free, so a locked-but-alive process holds
        // no decrypted vault residue. Issued as the FIRST statement on the
        // connection — before keying — for two reasons: the flag is consulted at
        // FREE time (blocks still allocated when it flips are covered when later
        // freed; only blocks both allocated AND freed before the flip are missed),
        // and it is safe here because SQLCipher claims this PRAGMA inside
        // sqlcipher_codec_pragma and jumps straight to pragma_out, BEFORE the
        // pragma table lookup and before any PragFlg_NeedSchema schema read. So it
        // never touches a page and cannot fail on a not-yet-keyed database.
        //
        // What it does and does NOT scrub — the non-obvious part:
        //   • DOES, continuously: the decrypted page cache and every other
        //     allocation reaching sqlite3Malloc (SQLCipher wraps it via
        //     SQLITE_CONFIG_MALLOC, overwriting with xoshiro_randomness on free).
        //   • Does NOT, per-free: the two copies of the 67-byte x'<hex>' keyspec
        //     this function's PRAGMA text creates — Vdbe.zSql (~84 B) and the
        //     dequoted zRight (68 B). Both are sqlite3DbStrNDup'd, both fit the
        //     128-byte LOOKASIDE small-slot region, and sqlite3DbFreeNN returns
        //     lookaside slots to a free list WITHOUT zeroing (the 0xaa trash fill
        //     is SQLITE_DEBUG-only).
        //   • DOES, at close(): the lookaside pool is ONE sqlite3Malloc block,
        //     freed via sqlite3_free when the connection closes, so the whole
        //     48 KB — keyspec residue included — is randomised then. That is the
        //     boundary IosAppController.lock() already relies on when it closes
        //     the vault so "a locked-but-alive process should hold no vault key
        //     material"; without this PRAGMA that invariant did not actually hold.
        //
        // Process-global and ONE-WAY (SQLCipher offers no "off"), so it also
        // covers every later vault re-open in this process. mlock() failures are
        // logged at INFO and ignored — never fatal to an open — and the
        // zero-on-free runs BEFORE the munlock, so the property we want does not
        // depend on the lock succeeding. Deliberately unchecked: a failure here
        // must not block opening the vault.
        // Mirrored on Android in DatabaseManager's init (the same PRAGMA, set Kotlin-side).
        sqlite3_exec(db, "PRAGMA cipher_memory_security = ON;", nil, nil, nil)

        // Build  PRAGMA key = "x'<hex>'";  directly in a MUTABLE C buffer so the
        // 64-hex-char key never lives in an immutable, unwipeable Swift String /
        // NSString (recoverable under RAM capture). The textual
        // x'...' raw-key format is preserved byte-for-byte, so existing databases
        // stay readable. Both the raw-key copy and the hex pragma buffer are
        // zeroed immediately after sqlite3_exec.
        let n = Int(key.size)
        var raw = [UInt8](repeating: 0, count: n)
        for i in 0..<n { raw[i] = UInt8(bitPattern: key.get(index: Int32(i))) }

        let hexDigits: [CChar] = Array("0123456789abcdef".utf8).map { CChar(bitPattern: $0) }
        var pragma: [CChar] = Array("PRAGMA key = \"x'".utf8).map { CChar(bitPattern: $0) }
        pragma.reserveCapacity(16 + n * 2 + 4)
        for b in raw {
            pragma.append(hexDigits[Int(b >> 4)])
            pragma.append(hexDigits[Int(b & 0x0F)])
        }
        pragma.append(contentsOf: Array("'\";".utf8).map { CChar(bitPattern: $0) })
        pragma.append(0)                                    // NUL terminator
        // memset_s, not a plain loop — a plain store to a buffer
        // that's never read again is a DEAD STORE the optimizer can eliminate under -O,
        // leaving the plaintext DB key in freed memory. memset_s is guaranteed to run.
        raw.withUnsafeMutableBytes { _ = memset_s($0.baseAddress, $0.count, 0, $0.count) }

        let keyRc = sqlite3_exec(db, pragma, nil, nil, nil)
        pragma.withUnsafeMutableBytes { _ = memset_s($0.baseAddress, $0.count, 0, $0.count) }  // memset_s (see above)

        if keyRc != SQLITE_OK {
            let code = sqlite3_errcode(db)
            LogBuffer.shared.append(level: "E", tag: "SwiftDB", message: "PRAGMA key failed (\(code))")
            sqlite3_close(db); db = nil
            return code != SQLITE_OK ? code : SQLITE_ERROR
        }

        // Verify key is correct. A wrong key surfaces here as SQLITE_NOTADB.
        var stmt: OpaquePointer?
        let prepRc = sqlite3_prepare_v2(db, "SELECT count(*) FROM sqlite_master;", -1, &stmt, nil)
        if prepRc != SQLITE_OK {
            LogBuffer.shared.append(level: "E", tag: "SwiftDB", message: "verify query failed (\(prepRc))")
            sqlite3_finalize(stmt); sqlite3_close(db); db = nil
            return prepRc
        }
        let stepRc = sqlite3_step(stmt)
        sqlite3_finalize(stmt)
        if stepRc != SQLITE_ROW && stepRc != SQLITE_DONE {
            LogBuffer.shared.append(level: "E", tag: "SwiftDB", message: "verify step failed (\(stepRc))")
            sqlite3_close(db); db = nil
            return stepRc
        }

        // RUN-02 (2026-11-12): ROLLBACK journal in TRUNCATE mode, NOT WAL.
        //
        // In WAL mode every committed version of a page stays in the -wal until a
        // checkpoint RESETS the log, and nothing here ever forced one; even then a
        // reset only rewrites the log from the front, so older frames survive in the
        // tail. The Double Ratchet state is one `_meta` row rewritten on every step,
        // so an image of run.db + run.db-wal plus the CURRENT db key let an attacker
        // replay a WAL prefix, rebuild an earlier committed view and read a chain key
        // the live ratchet had already deleted (auditor repro, SQLCipher 4.19.0).
        //
        // A rollback journal holds page PRE-images of the transaction in flight only,
        // i.e. the LAST COMMITTED state, never an older one, and TRUNCATE empties the
        // file at every commit. TRUNCATE rather than DELETE: the 0-byte file keeps its
        // inode, so the NSFileProtectionComplete + backup exclusion protectDbFiles
        // sets on it persist. NEVER PERSIST (it only zeroes the header and leaves the
        // pre-images readable) and never OFF/MEMORY (no crash safety).
        //
        // Leaving WAL also checkpoints and unlinks a -wal / -shm an older build or an
        // unclean exit left behind, at this open. Issued here — after the key is
        // proven — because the key PROBE opens through this same function and must
        // not flip the shared file back to WAL. Deliberately unchecked: a refused
        // switch (another connection holds the file) leaves the vault in WAL and must
        // never fail an open; IosVaultDatabase reads the mode back and retries at its
        // write boundaries.
        //
        // busy_timeout: a rollback journal makes a reader and the writer's commit
        // mutually exclusive (WAL did not), so the short-lived probe connection and
        // the live one now wait for each other briefly instead of failing on SQLITE_BUSY.
        // journal_size_limit=0: belt for the WAL-fallback case (a reset log is
        // truncated to 0 bytes instead of being kept at its high-water mark).
        //
        // Truncation is NOT physical erasure: freed flash blocks are not overwritten,
        // and nothing can revoke an image captured earlier.
        sqlite3_busy_timeout(db, 2500)
        sqlite3_exec(db, "PRAGMA journal_mode=TRUNCATE;", nil, nil, nil)
        sqlite3_exec(db, "PRAGMA journal_size_limit=0;", nil, nil, nil)
        return 0  // SQLITE_OK
    }

    // Re-encrypts the whole database under `key` on THIS already-open handle.
    // Returns the sqlite3_rekey_v2 result code (0 = SQLITE_OK), or SQLITE_MISUSE
    // when there is no open handle.
    //
    // ** THE RETURN CODE IS NOT PROOF. ** sqlite3_rekey_v2 returns SQLITE_OK on
    // BOTH of its terminal branches: the page-rewrite/commit result is assigned
    // to a local `rc` and then discarded, and the rollback branch falls through
    // to the same unconditional `return SQLITE_OK`. Worse, it installs the new
    // key in the codec's WRITE context (codec_set_pass_key(..., CIPHER_WRITE_CTX))
    // BEFORE the rewrite and never undoes it, so after a rolled-back re-key this
    // handle writes pages under the new key onto a file still on the old one. The
    // Kotlin caller MUST prove the outcome by re-opening the file with the
    // candidate key (VaultFactory.probeKey), never by trusting this value.
    //
    // ENCODING: the 67-byte  x'<64 hex>'  raw-key form — byte for byte what
    // `PRAGMA key = "x'…'"` in open(_:key:) yields after SQLite dequotes it
    // (zRight, n = strlen(zRight) = 67), which is what makes SQLCipher take its
    // raw-key branch instead of PBKDF2. NO trailing NUL: nKey is a length, and 68
    // bytes would silently fall through to the PBKDF2 branch and orphan the file.
    // Android keys with RAW BYTES instead (its own open path's convention) — the
    // two derive different encryption keys, so never share one encoding.
    //
    // Built in a MUTABLE C buffer and memset_s'd, exactly as in open(_:key:): a
    // `PRAGMA rekey = "x'…'"` routed through execute(sql:params:) would leave the
    // 64 hex chars in an immutable, unwipeable Swift String / NSString.
    func rekey(key: KotlinByteArray) -> Int32 {
        guard let db else { return SQLITE_MISUSE }

        let n = Int(key.size)
        var raw = [UInt8](repeating: 0, count: n)
        for i in 0..<n { raw[i] = UInt8(bitPattern: key.get(index: Int32(i))) }

        let hexDigits: [CChar] = Array("0123456789abcdef".utf8).map { CChar(bitPattern: $0) }
        var keyspec: [CChar] = []
        keyspec.reserveCapacity(n * 2 + 3)
        keyspec.append(contentsOf: Array("x'".utf8).map { CChar(bitPattern: $0) })
        for b in raw {
            keyspec.append(hexDigits[Int(b >> 4)])
            keyspec.append(hexDigits[Int(b & 0x0F)])
        }
        keyspec.append(CChar(bitPattern: UInt8(ascii: "'")))
        // memset_s, not a plain loop: a store to a buffer that is never read again
        // is a dead store the optimizer may delete under -O.
        raw.withUnsafeMutableBytes { _ = memset_s($0.baseAddress, $0.count, 0, $0.count) }

        // sqlite3_rekey_v2 is declared in Run-Bridging-Header.h (SwiftPM does not
        // propagate the package's SQLITE_HAS_CODEC define to dependents, so the
        // module's own declaration is invisible here) — hence the raw-pointer form.
        let rc = keyspec.withUnsafeBufferPointer { buf in
            sqlite3_rekey_v2(UnsafeMutableRawPointer(db), "main", buf.baseAddress, Int32(buf.count))
        }
        keyspec.withUnsafeMutableBytes { _ = memset_s($0.baseAddress, $0.count, 0, $0.count) }

        if rc != SQLITE_OK {
            // Result code only — never the key, the path or the errmsg text.
            LogBuffer.shared.append(level: "E", tag: "SwiftDB", message: "rekey failed (\(rc))")
        }
        return rc
    }

    func execute(sql: String, params: [Any]) -> Bool {
        guard let db else { return false }
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return false }
        bindParams(stmt: stmt, params: params)
        let rc = sqlite3_step(stmt)
        sqlite3_finalize(stmt)
        // SQLITE_DONE = write completed; SQLITE_ROW for a rare row-returning
        // statement. Anything else (FULL/IOERR/BUSY/CONSTRAINT/CORRUPT/...) is a
        // failure the caller MUST see, so fail-closed write guards can trigger
        // (previously this return code was discarded).
        return rc == SQLITE_DONE || rc == SQLITE_ROW
    }

    func query(sql: String, params: [Any]) -> [Any] {
        guard let db else { return [] }
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return [] }
        bindParams(stmt: stmt, params: params)

        var rows: [[String: Any]] = []
        let colCount = sqlite3_column_count(stmt)

        while sqlite3_step(stmt) == SQLITE_ROW {
            var row: [String: Any] = [:]
            for i in 0..<colCount {
                let name = String(cString: sqlite3_column_name(stmt, i))
                switch sqlite3_column_type(stmt, i) {
                case SQLITE_INTEGER:
                    row[name] = NSNumber(value: sqlite3_column_int64(stmt, i))
                case SQLITE_TEXT:
                    if let text = sqlite3_column_text(stmt, i) {
                        row[name] = String(cString: text) as NSString
                    }
                case SQLITE_BLOB:
                    let bytes = sqlite3_column_blob(stmt, i)
                    let len = sqlite3_column_bytes(stmt, i)
                    if let bytes, len > 0 {
                        row[name] = Data(bytes: bytes, count: Int(len)).base64EncodedString() as NSString
                    }
                default: break
                }
            }
            rows.append(row)
        }
        sqlite3_finalize(stmt)
        return rows as [Any]
    }

    func close() {
        if let db { sqlite3_close(db); self.db = nil }
    }

    // MARK: - Private

    private func bindParams(stmt: OpaquePointer?, params: [Any]) {
        for (i, param) in params.enumerated() {
            let idx = Int32(i) + 1
            switch param {
            case let v as NSString:
                sqlite3_bind_text(stmt, idx, v.utf8String, -1, unsafeBitCast(-1, to: sqlite3_destructor_type.self))
            case let v as NSNumber:
                // Check if it's a boolean (CFBoolean) or integer
                if CFGetTypeID(v) == CFBooleanGetTypeID() {
                    sqlite3_bind_int(stmt, idx, v.boolValue ? 1 : 0)
                } else {
                    sqlite3_bind_int64(stmt, idx, v.int64Value)
                }
            case is NSNull:
                sqlite3_bind_null(stmt, idx)
            default:
                sqlite3_bind_null(stmt, idx)
            }
        }
    }
}

// MARK: - Data ↔ KotlinByteArray (shared by every Swift caller of the Kotlin bridge)

/// Bytes → Kotlin/Native `KotlinByteArray`, one element at a time straight into the
/// Kotlin array (no intermediate Swift buffer), so callers that zeroize their own
/// `Data` afterwards keep exactly the copies they had before this was shared.
func kotlinByteArray<C: Collection>(from bytes: C) -> KotlinByteArray where C.Element == UInt8 {
    let array = KotlinByteArray(size: Int32(bytes.count))
    for (i, b) in bytes.enumerated() { array.set(index: Int32(i), value: Int8(bitPattern: b)) }
    return array
}

/// UTF-8 bytes of [string] → `KotlinByteArray`.
func kotlinByteArray(from string: String) -> KotlinByteArray {
    kotlinByteArray(from: Array(string.utf8))
}

/// `KotlinByteArray` → `Data` (one `[UInt8]` staging copy, as every former private
/// copy of this helper did).
func dataFromKotlin(_ bytes: KotlinByteArray) -> Data {
    var arr = [UInt8](repeating: 0, count: Int(bytes.size))
    for i in 0..<Int(bytes.size) { arr[i] = UInt8(bitPattern: bytes.get(index: Int32(i))) }
    return Data(arr)
}

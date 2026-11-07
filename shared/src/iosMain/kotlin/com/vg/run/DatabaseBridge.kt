package com.vg.run

import platform.Foundation.NSArray

// ---------------------------------------------------------------------------
// DatabaseBridge — interface fulfilled by the Swift layer using SQLCipher.
//
// Each IosVaultDatabase gets its own bridge instance (separate db handle).
// The factory creates new instances on demand.
// ---------------------------------------------------------------------------

interface DatabaseBridge {
    /**
     * Opens + keys the DB. [key] is the RAW 32-byte SQLCipher passphrase; the
     * implementation hex-encodes it into a wipeable buffer immediately before
     * keying and zeroes that buffer afterwards (it must NOT retain the key in an
     * unwipeable String). Returns 0 (SQLITE_OK) on success, otherwise the SQLite
     * result code so the caller can distinguish a genuine wrong-key / corrupt
     * file (SQLITE_NOTADB = 26 — destructive recreate may be warranted at
     * provision) from a TRANSIENT failure (SQLITE_BUSY=5, IOERR=10, CANTOPEN=14,
     * …) that must NEVER trigger deletion of a real vault.
     */
    fun open(path: String, key: ByteArray): Int

    /**
     * Re-encrypts the whole database under [key] on THIS already-open handle, via
     * `sqlite3_rekey_v2`. [key] is the RAW 32-byte SQLCipher passphrase; the
     * implementation builds the 67-byte `x'<64 hex>'` raw-key keyspec in a
     * WIPEABLE C buffer — the same encoding, byte for byte, that [open]'s
     * `PRAGMA key` produces after SQLite dequotes it — and zeroes that buffer with
     * `memset_s` afterwards. It must NOT go through [execute]: a
     * `PRAGMA rekey = "x'…'"` string would put an immutable, unwipeable copy of
     * the DB key in the Kotlin/NSString heap, which is exactly the hygiene [open]
     * was rewritten to avoid.
     *
     * Returns the `sqlite3_rekey_v2` result code (0 = SQLITE_OK), or SQLITE_MISUSE
     * when there is no open handle. **That code is NOT proof of anything** —
     * `sqlite3_rekey_v2` returns SQLITE_OK on both its commit and its rollback
     * branch; see [VaultDatabase.rekey].
     */
    fun rekey(key: ByteArray): Int

    /** Returns true iff the statement executed successfully (SQLITE_DONE/ROW). */
    fun execute(sql: String, params: NSArray): Boolean
    fun query(sql: String, params: NSArray): NSArray  // Returns NSArray of NSDictionary
    fun close()
}

fun interface DatabaseBridgeFactory {
    fun create(): DatabaseBridge
}

object DatabaseBridgeHolder {
    var factory: DatabaseBridgeFactory? = null
}

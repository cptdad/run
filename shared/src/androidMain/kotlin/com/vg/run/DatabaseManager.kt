package com.vg.run

import android.content.ContentValues
import android.content.Context
import android.database.Cursor
import net.zetetic.database.sqlcipher.SQLiteDatabase
import net.zetetic.database.sqlcipher.SQLiteOpenHelper

// Data classes (ContactRecord, InboxIdRecord) are defined in
// commonMain/DataModels.kt and shared across all platforms.

// ---------------------------------------------------------------------------
// DatabaseManager
// ---------------------------------------------------------------------------

/**
 * DatabaseManager owns the single SQLCipher-encrypted SQLite database for the app.
 *
 * Security model:
 *   • The on-disk database file is encrypted by SQLCipher using AES-256-CBC.
 *   • The 32-byte passphrase is supplied per-open by VaultSelector, which
 *     unwraps it from (user PIN + device Keystore key). It is never stored
 *     by this class.
 *   • Sensitive column values (sharedSecret above all) are protected ONLY
 *     by SQLCipher's whole-DB encryption (single layer, PIN-wrapped key). Callers do
 *     NOT additionally app-encrypt them — sharedSecret is stored and read RAW (see
 *     the corrected note near insertContact; MessageManager uses sha256(sharedSecret)
 *     directly). The old "doubly protected" wording was inaccurate.
 *   • MESSAGES ARE NEVER PERSISTED. There is no message table and no message
 *     method on [VaultDatabase]; conversations live in RAM only. Schema v9
 *     (2026-09-15) DROPs the legacy `Messages` table that pre-2026-05-24 builds
 *     wrote every message into — see the onUpgrade step and the VACUUM in init.
 *
 * CR-1: the SQLCipher passphrase ([dbKey]) is supplied by VaultSelector,
 * which derives it from the user PIN + device key. This class no longer
 * derives or stores its own key.
 *
 * File protection (parity, by design): iOS additionally sets
 * NSFileProtectionComplete + backup exclusion on the file and every sidecar
 * (IosVaultDatabase.protectDbFiles); Android relies on `allowBackup="false"` + FBE.
 *
 * @param context     Application context.
 * @param dbKey       32-byte SQLCipher passphrase (PIN-wrapped by VaultSelector).
 * @param rawKey      True when [dbKey] is the adopted raw SQLCipher key K'
 *   (2026-10-07 raw-key adoption) rather than the passphrase; see the companion.
 * @param isProvision True ONLY when this open is the one-time vault provision
 *   (VaultSelector passes `true` at provision, `false` on every unlock). Gates
 *   the destructive delete-and-recreate of a "not a database" file: allowed at
 *   provision (no real data yet), NEVER on unlock (where a corrupt header sits
 *   on a vault full of the user's real data). Mirrors the iOS gate. Defaults to
 *   false so any caller that forgets fails CLOSED.
 */
class DatabaseManager(
    context: Context,
    dbKey: ByteArray,
    isProvision: Boolean = false,
    rawKey: Boolean = false,
) : VaultDatabase {

    // -----------------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------------

    internal companion object {
        const val DATABASE_NAME    = "run.db"
        // v9 (2026-09-15): the legacy `Messages` table is DROPped. Nothing has
        // written to it since a933616e (2026-05-24), but a vault provisioned by an
        // older build and never wiped still holds its rows. Bumping the version is
        // what runs that DROP; `MigrationBundleCodec.CURRENT_SCHEMA` moves with it
        // (pinned by MigrationSchemaPinTest).
        //
        // v10 (2026-09-24): the GROUP-text channel's anti-replay counter space
        // (`ContactRecord.outboundGrpCounter` / `inboundGrpCounter`, the third
        // pairwise inbox pair). Purely additive — two `ALTER TABLE … DEFAULT 0`
        // statements, no table rewrite, no drop: every existing contact survives
        // and reads 0, which is the establish-on-read baseline the v4 and v7
        // counters already use.
        const val DATABASE_VERSION = 10

        /**
         * True when the vault database file exists — the provision guard's probe
         * (see [VaultFactory.vaultFileExists]). Same path the constructor opens
         * and the same path the isProvision+NOTADB branch below would delete, so
         * the guard and the destructive branch can never disagree about which
         * file they mean.
         *
         * Only the main DB file is checked: a lone `-wal`/`-shm` sidecar without
         * it is debris from an aborted create, not a vault worth protecting.
         */
        fun vaultFileExists(context: Context): Boolean =
            context.getDatabasePath(DATABASE_NAME).exists()

        /**
         * PROVISION-1: unlink the vault file and every sidecar at the SAME path
         * [vaultFileExists] probes and the constructor opens — the Android half of
         * [VaultFactory.deleteVaultFileAfterFailedProvision]. See that kdoc for the
         * one legal caller; this is only how it is met here.
         *
         * Also the `isProvision && NOTADB` recreate branch below (it used to inline
         * the identical loop). The suffix list is [VaultFiles.SIDECAR_SUFFIXES]
         * (`-journal` included: a journal_mode fallback or an interrupted
         * transaction can leave one holding pre-image ciphertext pages). Never
         * throws: `File.delete()` returns false for an absent file rather than raising.
         */
        fun deleteVaultFiles(context: Context) {
            val base = context.getDatabasePath(DATABASE_NAME).path
            // `-journal` is the rollback-journal sidecar both platforms now use
            // (Android DELETE mode, iOS TRUNCATE mode since RUN-02); `-wal`/`-shm` are
            // what a pre-RUN-02 iOS build left. Both platforms sweep all of them.
            VaultFiles.SIDECAR_SUFFIXES.forEach { sfx ->
                java.io.File(base + sfx).delete()
            }
        }

        /**
         * The Android half of [VaultFactory.probeKey] — see that kdoc for the
         * contract; this is only how it is met here.
         *
         * Opens the SAME file [vaultFileExists] probes and the constructor opens,
         * with the SAME raw-byte key encoding the constructor uses, and runs the
         * same cheap `sqlite_master` verify the normal open path performs
         * (`getWritableDatabase` reads `PRAGMA user_version` off page 1, which is
         * what makes a wrong key fail there too). Then closes.
         *
         * Why not simply construct a [DatabaseManager] with `isProvision = false`
         * and let its guards do the work: the constructor WRITES (schema DDL, the
         * `_meta('seeded')` upsert, two PRAGMAs). A probe must be able to answer
         * "does this key open the vault?" without mutating the vault it is asked
         * about — especially while a live handle is open on the same file.
         *
         * Non-destructive by construction:
         *  - flags = [SQLiteDatabase.OPEN_READWRITE] with NO `CREATE_IF_NECESSARY`,
         *    so the open cannot manufacture the file (and the size guard below
         *    rejects a truncated stub before we get there, matching the
         *    constructor's guard);
         *  - a wrong key raises SQLiteDatabaseCorruptException, which
         *    `SQLiteDatabase.open()` routes to the error handler before retrying.
         *    The handler is `DefaultDatabaseErrorHandler` (the null argument is
         *    replaced by one in the ctor, exactly as `SecureDbHelper` gets), and
         *    its very first action after logging is `if (hasCodec()) return;` — so
         *    it never reaches `deleteDatabaseFile`. The retry then throws again and
         *    we report `false` with the file untouched.
         *
         * Read-write rather than read-only on purpose: this must answer `true`
         * whenever a real unlock would succeed, and a read-only connection cannot
         * roll back a hot journal, so it could answer `false` for a vault the app
         * itself opens fine. In a re-key flow that false negative is not a safe
         * failure (see [VaultFactory.probeKey]). The only writes it can perform are
         * the journal-mode/page-size pragmas the ordinary open performs anyway.
         */
        fun probeKey(context: Context, dbKey: ByteArray, rawKey: Boolean = false): Boolean {
            // Same reason as the constructor: sqlcipher-android does not auto-load
            // its .so, and a probe may run before any vault has been opened.
            // Idempotent — the JVM loads a library once per classloader.
            System.loadLibrary("sqlcipher")
            val dbFile = context.getDatabasePath(DATABASE_NAME)
            // isProvision=false semantics: absent / truncated is "no", never "make one".
            if (!dbFile.exists() || dbFile.length() < MIN_VALID_VAULT_DB_BYTES) return false
            // SQLiteDatabaseConfiguration retains the key array BY REFERENCE, so
            // hand it a private copy and zero that copy once the handle is closed
            // (the same idiom as the constructor's `dbPassword`). Raw-key mode
            // (2026-10-07) hands it the 67-byte `x'<hex>'` keyspec instead — also a
            // private buffer, wiped the same way.
            val keyCopy = if (rawKey) rawKeySpec(dbKey) else dbKey.copyOf()
            var probe: SQLiteDatabase? = null
            return try {
                probe = SQLiteDatabase.openDatabase(
                    dbFile.path,
                    keyCopy,
                    null,                              // no CursorFactory
                    SQLiteDatabase.OPEN_READWRITE,     // deliberately NOT CREATE_IF_NECESSARY
                    null,                              // → DefaultDatabaseErrorHandler (cannot delete, see above)
                    null,                              // no SQLiteDatabaseHook
                )
                // A real vault always has tables; a database that was created out
                // from under us would report 0. Requiring > 0 closes the
                // check-then-open gap without a second stat.
                probe.rawQuery("SELECT count(*) FROM sqlite_master", null).use { c ->
                    c.moveToFirst() && c.getLong(0) > 0L
                }
            } catch (_: Throwable) {
                // Wrong key (SQLITE_NOTADB), busy, I/O error — all "no", never a throw.
                false
            } finally {
                try { probe?.close() } catch (_: Throwable) { }
                keyCopy.secureWipe()
            }
        }

        // -------------------------------------------------------------------
        // Raw-key ADOPTION (2026-10-07) — skip SQLCipher's per-open PBKDF2.
        //
        // Every Android vault was created in SQLCipher's PASSPHRASE mode: the 32
        // random bytes VaultSelector unwraps (`dbKey`) go through
        // PBKDF2-HMAC-SHA512 × 256 000 with the 16-byte salt in the file header
        // on EVERY open — measured 2.08 s per unlock on a Dimensity 700 (A13),
        // against 5 ms for a raw-key open. Stretching a uniformly random 256-bit
        // key adds no security, so the stretch is pure cost.
        //
        // Adoption does NOT rekey and does NOT touch a page. It computes, once,
        // the very key SQLCipher itself derives in passphrase mode —
        //     K' = PBKDF2-HMAC-SHA512(dbKey, fileSalt, 256000, 32)
        // — and opens with the raw keyspec `x'<hex K'>'`. In raw mode SQLCipher
        // takes K' as the encryption key verbatim, reads the salt from the same
        // file header, and derives the page-HMAC key from (K', salt) exactly as it
        // does after the passphrase stretch, so both modes open the byte-identical
        // file and every page either mode writes is readable by the other.
        // Proven on a real device by androidTest `RawKeyAdoptionTest` before any
        // vault was ever opened this way. The caller (VaultSelector) additionally
        // refuses to rely on K' until `probeKey(K', rawKey = true)` has opened the
        // REAL file — the computation here is never trusted on its own.
        //
        // The parameters are SQLCipher 4's defaults; nothing in this app has ever
        // issued a `cipher_*`/`kdf_iter` PRAGMA or a compatibility mode, so they are
        // the ones every vault was created with. If that ever stopped being true,
        // K' would simply fail the probe and the vault would stay in passphrase
        // mode — slower, never unopenable.
        // -------------------------------------------------------------------

        /** SQLCipher 4 default PBKDF2 iteration count (`kdf_iter`). */
        internal const val SQLCIPHER_KDF_ITER = 256_000
        /** SQLCipher file-header salt length (`kdf_salt_sz`). */
        internal const val SQLCIPHER_SALT_LEN = 16
        /** SQLCipher AES-256 key length (`key_sz`). */
        internal const val SQLCIPHER_KEY_LEN = 32

        /**
         * The 67-byte raw keyspec `x'<64 lowercase hex>'` for a 32-byte [rawKey],
         * as ASCII bytes — the only form SQLCipher's `sqlite3_key` treats as a raw
         * key (anything else is a passphrase and gets stretched). Returned in a
         * fresh buffer the caller owns and must wipe.
         */
        internal fun rawKeySpec(rawKey: ByteArray): ByteArray {
            require(rawKey.size == SQLCIPHER_KEY_LEN) { "raw SQLCipher key must be $SQLCIPHER_KEY_LEN bytes" }
            val hex = "0123456789abcdef"
            val out = ByteArray(3 + rawKey.size * 2)
            out[0] = 'x'.code.toByte(); out[1] = '\''.code.toByte()
            for (i in rawKey.indices) {
                val v = rawKey[i].toInt() and 0xFF
                out[2 + 2 * i] = hex[v ushr 4].code.toByte()
                out[3 + 2 * i] = hex[v and 0x0F].code.toByte()
            }
            out[out.size - 1] = '\''.code.toByte()
            return out
        }

        /**
         * The 16-byte KDF salt SQLCipher keeps in plaintext at offset 0 of the
         * vault file, or null when the file is absent / shorter than one page
         * (the same "no vault here" answer [probeKey] gives). Never throws.
         */
        internal fun readFileSalt(context: Context): ByteArray? = try {
            val f = context.getDatabasePath(DATABASE_NAME)
            if (!f.exists() || f.length() < MIN_VALID_VAULT_DB_BYTES) null
            else java.io.FileInputStream(f).use { input ->
                val salt = ByteArray(SQLCIPHER_SALT_LEN)
                var off = 0
                while (off < salt.size) {
                    val n = input.read(salt, off, salt.size - off)
                    if (n < 0) break
                    off += n
                }
                if (off == salt.size) salt else null
            }
        } catch (_: Throwable) {
            null
        }

        /**
         * K' for the vault file's own salt — the raw key SQLCipher derives from
         * [dbKey] in passphrase mode. Null when the salt cannot be read. ~0.5–1 s of
         * CPU on a low-end phone: run it once, at adoption, never per unlock.
         */
        internal fun deriveAdoptedRawKey(context: Context, dbKey: ByteArray): ByteArray? {
            val salt = readFileSalt(context) ?: return null
            return pbkdf2HmacSha512(dbKey, salt, SQLCIPHER_KDF_ITER, SQLCIPHER_KEY_LEN)
        }

        /**
         * PBKDF2-HMAC-SHA512 over RAW password bytes (RFC 8018). Hand-rolled on
         * `javax.crypto.Mac` because `PBKDF2WithHmacSHA512` takes a `char[]` and
         * re-encodes it, which cannot represent 32 random bytes. Only one output
         * block is ever needed (dkLen ≤ 64). The working buffers are wiped; the
         * HMAC key copy inside the provider's `Mac` state is not reachable to wipe
         * and is left to the GC — the same live-RAM exposure the open SQLCipher
         * handle already has for this key.
         */
        internal fun pbkdf2HmacSha512(password: ByteArray, salt: ByteArray, iterations: Int, dkLen: Int): ByteArray {
            require(dkLen in 1..64) { "single-block PBKDF2 only" }
            require(iterations >= 1)
            val mac = javax.crypto.Mac.getInstance("HmacSHA512")
            mac.init(javax.crypto.spec.SecretKeySpec(password, "HmacSHA512"))
            val u = ByteArray(64)
            val t = ByteArray(64)
            try {
                mac.update(salt)
                mac.update(byteArrayOf(0, 0, 0, 1))
                mac.doFinal(u, 0)
                u.copyInto(t)
                for (i in 1 until iterations) {
                    mac.update(u)
                    mac.doFinal(u, 0)
                    for (j in 0 until 64) t[j] = (t[j].toInt() xor u[j].toInt()).toByte()
                }
                return t.copyOf(dkLen)
            } finally {
                u.fill(0); t.fill(0)
                try { mac.reset() } catch (_: Throwable) { }
            }
        }

        // Table and column names
        const val TABLE_CONTACTS          = "Contacts"
        const val COL_CONTACT_ID          = "contactId"
        const val COL_SHARED_SECRET       = "sharedSecret"
        const val COL_TRUST_LEVEL         = "trustLevel"
        const val COL_ALIAS               = "alias"
        const val COL_ALIAS_LAST_ROTATED  = "aliasLastRotated"
        const val COL_MNEMONIC            = "mnemonic"
        const val COL_OUTBOUND_COUNTER    = "outboundCounter"
        const val COL_INBOUND_COUNTER     = "inboundCounter"
        const val COL_INBOUND_EPOCH       = "inboundEpoch"
        // v7 — control-channel counter space (see ContactRecord docs).
        const val COL_OUTBOUND_CTL_COUNTER = "outboundCtlCounter"
        const val COL_INBOUND_CTL_COUNTER  = "inboundCtlCounter"
        // v10 — group-text-channel counter space (see ContactRecord docs). Third
        // and last counter pair; still scoped by the single COL_INBOUND_EPOCH.
        const val COL_OUTBOUND_GRP_COUNTER = "outboundGrpCounter"
        const val COL_INBOUND_GRP_COUNTER  = "inboundGrpCounter"
        // v8 — referral/vouching provenance (referral.md). NULL/0 for QR pairs.
        const val COL_VOUCHED_BY          = "vouchedByContactId"
        const val COL_VOUCHED_AT          = "vouchedAt"

        const val TABLE_INBOX_IDS         = "InboxIds"
        const val COL_INBOX_ID            = "inboxId"
        const val COL_CREATED_AT          = "createdAt"
        const val COL_EXPIRES_AT          = "expiresAt"
        const val COL_DIRECTION           = "direction"
        // v5 — relay capability protocol. NULL for pre-migration rows; those
        // are surfaced as "re-pair required" by the migration UX.
        const val COL_CAP                 = "cap"

        // NOTE: there is deliberately no message table or message column here.
        // The legacy `Messages` table (messageId / contactId / encryptedContent /
        // timestamp / isRead) is DROPped by the v8 → v9 migration below and must
        // never be reintroduced — messages live in RAM only.

        // v6 — group chat. "ContactGroups", not "Groups": GROUPS is an SQLite
        // keyword (window functions) — avoid relying on its identifier-context
        // parsing.
        const val TABLE_GROUPS            = "ContactGroups"
        const val COL_GROUP_ID            = "groupId"
        const val COL_GROUP_NAME          = "name"
        const val COL_GROUP_EPOCH         = "epoch"
        const val COL_ADMIN_MEMBER_ID     = "adminMemberId"
        const val COL_MY_MEMBER_ID        = "myMemberId"

        const val TABLE_GROUP_MEMBERS     = "GroupMembers"
        const val COL_MEMBER_ID           = "memberId"
        const val COL_ADDED_AT            = "addedAt"
        const val COL_TAGS                = "tags"

        // Shared DDL strings so onCreate and the v5→v6 migration cannot drift apart.
        val DDL_GROUPS = """
            CREATE TABLE IF NOT EXISTS $TABLE_GROUPS (
                $COL_GROUP_ID        TEXT PRIMARY KEY NOT NULL,
                $COL_GROUP_NAME      TEXT NOT NULL,
                $COL_GROUP_EPOCH     INTEGER NOT NULL DEFAULT 1,
                $COL_ADMIN_MEMBER_ID TEXT NOT NULL,
                $COL_MY_MEMBER_ID    TEXT NOT NULL,
                $COL_CREATED_AT      INTEGER NOT NULL
            )
        """.trimIndent()
        val DDL_GROUP_MEMBERS = """
            CREATE TABLE IF NOT EXISTS $TABLE_GROUP_MEMBERS (
                $COL_GROUP_ID   TEXT NOT NULL,
                $COL_MEMBER_ID  TEXT NOT NULL,
                $COL_CONTACT_ID TEXT,
                $COL_ADDED_AT   INTEGER NOT NULL,
                $COL_TAGS       TEXT NOT NULL DEFAULT '',
                PRIMARY KEY ($COL_GROUP_ID, $COL_MEMBER_ID)
            )
        """.trimIndent()
    }

    // -----------------------------------------------------------------------
    // Initialisation
    // -----------------------------------------------------------------------

    // The single writable database handle, opened once and reused.
    private val db: SQLiteDatabase

    init {
        // Load SQLCipher's native library. net.zetetic:sqlcipher-android does not
        // auto-load its .so — System.loadLibrary must be called before any database
        // operation, otherwise nativeOpen throws UnsatisfiedLinkError.
        System.loadLibrary("sqlcipher")

        // Pass the supplied passphrase to SecureDbHelper via the 9-parameter
        // constructor (the only SQLiteOpenHelper ctor accepting a byte[] key).
        // Use a private copy so the caller can wipe its own array; this copy
        // is zeroed once the DB is open.
        //
        // [rawKey] (2026-10-07): [dbKey] is the ADOPTED raw key K' (see the
        // companion's raw-key adoption block) and is handed to SQLCipher as the
        // 67-byte `x'<hex>'` keyspec, which skips the 256 000-round PBKDF2. Never
        // combined with isProvision: a raw open only ever re-opens a file a
        // passphrase-mode provision created (VaultSelector never asks otherwise).
        require(!(rawKey && isProvision)) { "raw-key mode never provisions" }
        val dbPassword = if (rawKey) rawKeySpec(dbKey) else dbKey.copyOf()

        // v9: set by the helper below when THIS open ran the v8 → v9 migration and
        // dropped the legacy `Messages` table. Declared out here (not inside the
        // try) because the VACUUM it calls for is issued at the very end of init,
        // after the key-wiping `finally` — see there.
        var reclaimAfterLegacyMessagesDrop = false

        // Parity with the iOS guard. On the UNLOCK path
        // (isProvision=false) a MISSING db file is NOT an exception —
        // SQLiteOpenHelper.getWritableDatabase() CREATES it (runs createTables) and
        // returns a valid EMPTY DB, so a correct PIN would silently open a
        // brand-new empty vault, masking data loss / tampering (e.g. a root actor
        // deletes run.db while shared_prefs + the Keystore key survive). Fail
        // CLOSED before the open — VaultSelector.unlock maps the throw to the
        // neutral, retryable UnlockResult.Error, never a silently-empty Opened.
        // (Provisioning legitimately creates the file, so it is exempt.)
        // finally so the plaintext SQLCipher key copy is ALWAYS
        // zeroed — including the transient-open re-throw path below (a BUSY/IOERR/
        // CANTOPEN on unlock previously left it resident in the heap, the live-RAM-on-
        // seized-device threat we otherwise wipe against; iOS wipes on every path).
        try {
        // Existence alone is insufficient — a present-but-empty/truncated
        // run.db (0 bytes, e.g. an examiner truncating instead of deleting) passes
        // .exists(), and SQLiteOpenHelper opens a 0-length file as a fresh empty DB,
        // silently masking the loss. Require a real (>= one page) file so a
        // truncated stub is treated as "missing" and fails closed. No false
        // positive: a legitimate SQLCipher vault is always >= one page.
        val dbFile = context.getDatabasePath(DATABASE_NAME)
        if (!isProvision && (!dbFile.exists() || dbFile.length() < MIN_VALID_VAULT_DB_BYTES)) {
            throw IllegalStateException("vault database missing or empty at unlock — refusing to open an empty vault")
        }

        db = try {
            val helper = SecureDbHelper(context, dbPassword)
            helper.writableDatabase.also {
                reclaimAfterLegacyMessagesDrop = helper.droppedLegacyMessagesTable
            }
        } catch (e: Exception) {
            // Re-provision (delete + recreate, data loss accepted) ONLY when BOTH:
            // (a) this is a PROVISION open (isProvision; VaultSelector passes true
            //     only at provision and false on every unlock), where no real user
            //     data exists yet, AND
            // (b) the failure means the existing file is "not a database" for this
            //     key — a pre-CR-1 file keyed the old way, or a corrupt header.
            // On the UNLOCK path the credential + dbKey are already verified, so a
            // NOTADB there is a corrupt header on a vault FULL OF REAL DATA; and a
            // TRANSIENT failure (disk I/O, SQLITE_BUSY, CANTOPEN, out of space) is
            // recoverable. Either way, NEVER delete on unlock — re-throw so the
            // unlock fails CLOSED and the user can retry with their data intact.
            // Now matches the iOS gate exactly, which deletes only on
            // (isProvision && SQLITE_NOTADB).
            if (!isProvision || !isNotADatabaseFailure(e)) throw e
            // (isProvision && SQLITE_NOTADB) — matches the iOS gate exactly.
            deleteVaultFiles(context)
            val helper = SecureDbHelper(context, dbPassword)
            helper.writableDatabase.also {
                reclaimAfterLegacyMessagesDrop = helper.droppedLegacyMessagesTable
            }
        }
        } finally {
            // Always zero the in-memory password copy — on success AND on any throw.
            dbPassword.fill(0)
        }

        // Scrub SQLite's heap on free, so a locked-but-alive process holds
        // no decrypted vault residue. Issued FIRST on this connection (before
        // secure_delete below) because the flag is consulted at FREE time: every
        // block still allocated when it flips is covered when it is later freed,
        // and only blocks both allocated AND freed before the flip are missed.
        //
        // What it does and does NOT scrub — the non-obvious part:
        //   • DOES, continuously: the decrypted page cache and every other
        //     allocation that reaches sqlite3Malloc (pcache1Alloc falls through
        //     to it; SQLCipher wraps it via SQLITE_CONFIG_MALLOC and overwrites
        //     with xoshiro_randomness on free).
        //   • Does NOT, per-free: anything served from the per-connection
        //     LOOKASIDE pool (< 128 B / < 1200 B DbMalloc'd strings and structs).
        //     sqlite3DbFreeNN returns those to a free list WITHOUT zeroing — the
        //     0xaa trash fill is SQLITE_DEBUG-only, which release builds lack.
        //   • DOES, at close(): the lookaside pool is ONE sqlite3Malloc block,
        //     freed via sqlite3_free when the connection closes, so the whole
        //     48 KB — including that un-zeroed lookaside residue — is randomised
        //     then. close() is the boundary vault lock and wipe both rely on,
        //     which is exactly why this is worth issuing.
        //
        // Cost/safety: process-global and ONE-WAY (SQLCipher offers no "off"), so
        // it also covers every later vault re-open in this process. mlock()
        // failures (RLIMIT_MEMLOCK is small on some OEM kernels) are logged at
        // INFO and ignored — SQLCipher never fails an open over them, and the
        // zero-on-free we actually want runs BEFORE the munlock, independent of
        // whether the lock ever succeeded.
        //
        // Unlike secure_delete below, the assignment form of this PRAGMA returns
        // NO result row (SQLCipher's handler only emits one for the no-argument
        // read-back form), so execSQL is correct here and does not hit the
        // "returns results" refusal.
        // iOS sets the same PRAGMA in SwiftDatabaseBridge.swift's open, not in Kotlin.
        db.execSQL("PRAGMA cipher_memory_security = ON")

        // Overwrite freed pages on delete/update instead of just marking them
        // free (VACUUM alone doesn't zero residual ciphertext). Deleted
        // rows' on-disk bytes are zeroed eagerly, so a disk image taken after a
        // delete can't recover stale encrypted content. Per-connection PRAGMA;
        // set once per open. Crypto-erase on wipe is still the primary control —
        // this is defense-in-depth for non-wipe deletes.
        //
        // The assignment form returns the new value as a result row, which
        // SQLCipher's execSQL refuses ("returns results"), so run it as a query
        // and consume the row — executing the statement still applies the PRAGMA.
        db.rawQuery("PRAGMA secure_delete = ON", null).use { it.moveToFirst() }

        // Historical `_meta('seeded','1')` marker. It once provided schema parity
        // with the (now-removed) decoy vault; it is retained as an inert,
        // already-present table so existing real vaults are not forced through a
        // schema diff. The app never reads it. Runs every open (cheap, idempotent).
        db.execSQL("CREATE TABLE IF NOT EXISTS _meta (key TEXT PRIMARY KEY, value TEXT)")
        db.execSQL("INSERT OR IGNORE INTO _meta (key, value) VALUES ('seeded', '1')")

        // v9 (2026-09-15) — the deferred half of the legacy-`Messages` DROP.
        //
        // `onUpgrade` runs inside SQLiteOpenHelper's transaction and SQLite forbids
        // VACUUM inside one, so the reclaim lands HERE: the first point after the
        // helper's open has fully committed, on the same connection, outside any
        // transaction (nothing above opens one). secure_delete has already zeroed
        // those pages as they were freed; VACUUM rewrites the file so they are
        // returned to the OS instead of sitting in the freelist.
        //
        // BRICK SAFETY: wrapped, and deliberately the LAST thing init does. A vault
        // that opened is a vault that opened — a failed VACUUM (BUSY, no temp space)
        // must never turn a successful unlock into an error. Cost of that failure is
        // only unreclaimed free pages; the rows themselves are already gone.
        if (reclaimAfterLegacyMessagesDrop) {
            try { db.execSQL("VACUUM") } catch (_: Throwable) { }
        }
    }


    // -----------------------------------------------------------------------
    // Inner class: schema creation and migration
    // -----------------------------------------------------------------------

    /**
     * SQLiteOpenHelper subclass that creates the database schema and handles version upgrades.
     *
     * The [password] ByteArray is passed to the 9-parameter SQLiteOpenHelper constructor,
     * which is the only constructor in sqlcipher-android that accepts a raw byte[] key.
     * Parameters after [version]: minimumSupportedVersion=0, errorHandler=null,
     * hook=null, enableWriteAheadLogging=false.
     *
     * RUN-02 (2026-11-12): `enableWriteAheadLogging=false` is LOAD-BEARING for
     * forward secrecy, not a default. Without the WAL open flag, sqlcipher-android
     * 4.19.0's `SQLiteConnection.setWalModeFromConfiguration` applies
     * `SQLiteGlobal.getDefaultJournalMode()` = "delete" on every connection (checked
     * in the AAR's bytecode), i.e. a ROLLBACK journal: `run.db-journal` holds the
     * pre-images of the transaction in flight — the last COMMITTED state, never an
     * older one — and is unlinked at commit. Under WAL every superseded Double
     * Ratchet state (one `_meta` row rewritten per step) would stay in `run.db-wal`
     * until a checkpoint reset, and db + wal imaged together plus the current db key
     * rebuild an earlier view and an old chain key — the iOS finding RUN-02 fixed by
     * leaving WAL there. Never pass `true`, never call `enableWriteAheadLogging()`,
     * never set `journal_mode` to WAL or PERSIST on this file
     * (`VaultJournalModeSourceGuardTest`, `VaultJournalResidueTest`). The unlink is
     * not physical erasure on flash.
     */
    private class SecureDbHelper(
        context: Context,
        password: ByteArray
    ) : SQLiteOpenHelper(context, DATABASE_NAME, password, null, DATABASE_VERSION, 0, null, null, false) {

        /**
         * True once the v8 → v9 step has DROPped the legacy `Messages` table on THIS
         * open, i.e. this vault really did carry pre-2026-05-24 message rows.
         *
         * Read by [DatabaseManager]'s init **after** `writableDatabase` returns:
         * `onUpgrade` runs inside SQLiteOpenHelper's own transaction and SQLite
         * forbids VACUUM inside a transaction, so the reclaim cannot happen there.
         * Instance state rather than a companion flag so two concurrent opens (the
         * probe path constructs its own helper) cannot steal each other's answer.
         */
        var droppedLegacyMessagesTable: Boolean = false
            private set

        override fun onCreate(db: SQLiteDatabase) {
            // Contacts — one row per known contact.
            // sharedSecret is a BLOB stored under SQLCipher's whole-database
            // encryption (single layer). The SQLCipher key is itself PIN-wrapped
            // (CR-1: an inner AES-GCM layer under the PIN-derived KEK, inside an
            // outer device-key AEAD wrap — the device key is never a KDF input),
            // so recovering the secret always requires the PIN. NOTE: callers do NOT additionally
            // CryptoManager-encrypt it — an earlier comment here claimed it was
            // "doubly protected (Keystore + SQLCipher)", which was inaccurate.
            db.execSQL("""
                CREATE TABLE $TABLE_CONTACTS (
                    $COL_CONTACT_ID         TEXT PRIMARY KEY NOT NULL,
                    $COL_SHARED_SECRET      BLOB NOT NULL,
                    $COL_TRUST_LEVEL        INTEGER NOT NULL DEFAULT 0,
                    $COL_ALIAS              TEXT NOT NULL,
                    $COL_ALIAS_LAST_ROTATED INTEGER NOT NULL,
                    $COL_MNEMONIC           TEXT NOT NULL DEFAULT '',
                    $COL_OUTBOUND_COUNTER   INTEGER NOT NULL DEFAULT 0,
                    $COL_INBOUND_COUNTER    INTEGER NOT NULL DEFAULT 0,
                    $COL_INBOUND_EPOCH      TEXT NOT NULL DEFAULT '',
                    $COL_OUTBOUND_CTL_COUNTER INTEGER NOT NULL DEFAULT 0,
                    $COL_INBOUND_CTL_COUNTER  INTEGER NOT NULL DEFAULT 0,
                    $COL_VOUCHED_BY         TEXT,
                    $COL_VOUCHED_AT         INTEGER NOT NULL DEFAULT 0,
                    $COL_OUTBOUND_GRP_COUNTER INTEGER NOT NULL DEFAULT 0,
                    $COL_INBOUND_GRP_COUNTER  INTEGER NOT NULL DEFAULT 0
                )
            """.trimIndent())

            // InboxIds — inboxes linked to contacts. Under the capability
            // protocol, [cap] holds the X-Read-Capability on inbound rows
            // (our own, kept private) and the peer's X-Write-Capability on
            // outbound rows (received via the IRL pairing QR).
            db.execSQL("""
                CREATE TABLE $TABLE_INBOX_IDS (
                    $COL_INBOX_ID   TEXT PRIMARY KEY NOT NULL,
                    $COL_CONTACT_ID TEXT NOT NULL,
                    $COL_CREATED_AT INTEGER NOT NULL,
                    $COL_EXPIRES_AT INTEGER NOT NULL,
                    $COL_DIRECTION  TEXT NOT NULL DEFAULT 'outbound',
                    $COL_CAP        TEXT
                )
            """.trimIndent())

            // NO message table (v9, 2026-09-15). Messages are never written to
            // disk — a fresh vault must not even have somewhere to put them.

            // v6 — group chat (client-side only; the relay never sees groups).
            db.execSQL(DDL_GROUPS)
            db.execSQL(DDL_GROUP_MEMBERS)
        }

        override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
            // Migration v1 → v2: add direction column to InboxIds.
            // Existing rows default to "outbound" which is the safe assumption —
            // legacy inboxes were used for sending (getInboxIdForContact picked
            // the most recent one regardless of direction).
            if (oldVersion < 2) {
                db.execSQL(
                    "ALTER TABLE $TABLE_INBOX_IDS ADD COLUMN $COL_DIRECTION TEXT NOT NULL DEFAULT 'outbound'"
                )
            }
            if (oldVersion < 3) {
                db.execSQL(
                    "ALTER TABLE $TABLE_CONTACTS ADD COLUMN $COL_MNEMONIC TEXT NOT NULL DEFAULT ''"
                )
            }
            // v3 → v4: per-contact anti-replay state. Additive —
            // existing contacts keep their rows; counters default to 0 and
            // epoch to '' so the first received message establishes the
            // baseline. Contacts persist across this upgrade (requirement
            // 2026-05-17).
            if (oldVersion < 4) {
                db.execSQL("ALTER TABLE $TABLE_CONTACTS ADD COLUMN $COL_OUTBOUND_COUNTER INTEGER NOT NULL DEFAULT 0")
                db.execSQL("ALTER TABLE $TABLE_CONTACTS ADD COLUMN $COL_INBOUND_COUNTER INTEGER NOT NULL DEFAULT 0")
                db.execSQL("ALTER TABLE $TABLE_CONTACTS ADD COLUMN $COL_INBOUND_EPOCH TEXT NOT NULL DEFAULT ''")
            }
            // v4 → v5: relay capability protocol. The new column stays NULL
            // on legacy rows so the migration UX can flag those contacts as
            // "re-pair required" and refuse sends/polls on them.
            if (oldVersion < 5) {
                db.execSQL("ALTER TABLE $TABLE_INBOX_IDS ADD COLUMN $COL_CAP TEXT")
            }
            // v5 → v6: group chat tables. Purely additive — existing data
            // untouched. Same DDL strings as onCreate so fresh installs and
            // upgrades produce an identical schema.
            if (oldVersion < 6) {
                db.execSQL(DDL_GROUPS)
                db.execSQL(DDL_GROUP_MEMBERS)
            }
            // v6 → v7: control-channel anti-replay counters. Additive;
            // defaults 0 so the first control message establishes a baseline.
            if (oldVersion < 7) {
                db.execSQL("ALTER TABLE $TABLE_CONTACTS ADD COLUMN $COL_OUTBOUND_CTL_COUNTER INTEGER NOT NULL DEFAULT 0")
                db.execSQL("ALTER TABLE $TABLE_CONTACTS ADD COLUMN $COL_INBOUND_CTL_COUNTER INTEGER NOT NULL DEFAULT 0")
            }
            // v7 → v8: referral provenance. Additive; vouchedBy stays NULL and
            // vouchedAt 0 on existing (QR-paired) rows.
            if (oldVersion < 8) {
                db.execSQL("ALTER TABLE $TABLE_CONTACTS ADD COLUMN $COL_VOUCHED_BY TEXT")
                db.execSQL("ALTER TABLE $TABLE_CONTACTS ADD COLUMN $COL_VOUCHED_AT INTEGER NOT NULL DEFAULT 0")
            }
            // v8 → v9: DROP the legacy per-message table (2026-09-15).
            //
            // Nothing has inserted into `Messages` since a933616e (2026-05-24) — the
            // app keeps conversations in RAM, which is what the store listing claims.
            // But that commit removed only the WRITER, so a vault provisioned by an
            // older build and never wiped still holds every message it ever received,
            // encrypted under a key one compelled PIN recovers. Destroying the table
            // is the only way that residue leaves the file.
            //
            // Two things ride along, in this order:
            //  - secure_delete is turned on FIRST, because it is consulted at FREE
            //    time: the pages the DROP puts on the freelist are then zeroed as they
            //    are freed rather than merely unlinked. init sets the same PRAGMA on
            //    this connection a moment later (idempotent); it is issued here too
            //    because onUpgrade runs BEFORE that. Wrapped: the reclaim is a bonus,
            //    never a reason to fail an upgrade. rawQuery, not execSQL — the
            //    assignment form returns a row, which SQLCipher's execSQL refuses.
            //  - the VACUUM that returns those pages to the OS canNOT run here
            //    (SQLite forbids VACUUM inside a transaction and SQLiteOpenHelper
            //    wraps onUpgrade in one), so it is deferred to init via
            //    [droppedLegacyMessagesTable].
            if (oldVersion < 9) {
                try {
                    db.rawQuery("PRAGMA secure_delete = ON", null).use { it.moveToFirst() }
                } catch (_: Throwable) { /* best-effort; init re-issues it */ }
                db.execSQL("DROP TABLE IF EXISTS Messages")
                droppedLegacyMessagesTable = true
            }
            // v9 → v10: the GROUP-text channel's anti-replay counter space (the
            // third pairwise inbox pair — MessageManager.Chan.GRP). Additive, in
            // the exact shape of the v6 → v7 step above: defaults 0, so an existing
            // contact reads 0 and the first group blob on that channel establishes
            // the baseline (the same establish-on-read the v4 and v7 counters use).
            // Nothing is dropped and no table is rewritten — a vault provisioned by
            // any earlier build keeps every contact, inbox row and `_meta` row.
            //
            // Appended AFTER the v8 columns so a freshly CREATEd table and an
            // upgraded one carry the columns in the SAME order (onCreate's DDL
            // lists them last for that reason). Both mappers look columns up by
            // NAME, so order is cosmetic — but a divergence here is the kind that
            // only surfaces years later in a fixture.
            if (oldVersion < 10) {
                db.execSQL("ALTER TABLE $TABLE_CONTACTS ADD COLUMN $COL_OUTBOUND_GRP_COUNTER INTEGER NOT NULL DEFAULT 0")
                db.execSQL("ALTER TABLE $TABLE_CONTACTS ADD COLUMN $COL_INBOUND_GRP_COUNTER INTEGER NOT NULL DEFAULT 0")
            }
        }
    }

    // -----------------------------------------------------------------------
    // Contacts
    // -----------------------------------------------------------------------

    /**
     * `insertWithOnConflict(…, CONFLICT_REPLACE)` that fails CLOSED on -1, like
     * putMeta and iOS execChecked, so the commonMain fail-closed guards (replay
     * baseline, cap rotation) that rely on a throw actually fire on Android too.
     * Shared by the four row writers; [failure] is the exception message.
     */
    private fun replaceOrThrow(table: String, values: ContentValues, failure: String): Long {
        val rowId = db.insertWithOnConflict(table, null, values, SQLiteDatabase.CONFLICT_REPLACE)
        if (rowId == -1L) throw RuntimeException(failure)
        return rowId
    }

    /**
     * Inserts or replaces a contact row.
     *
     * @param contact The [ContactRecord] to persist. [ContactRecord.sharedSecret] is
     *                stored RAW — SQLCipher's whole-DB encryption is the only at-rest
     *                layer; the caller does NOT app-encrypt it.
     * @return The SQLite row ID of the inserted row; throws on failure (never -1 — see [replaceOrThrow]).
     */
    override fun insertContact(contact: ContactRecord): Long {
        val values = ContentValues().apply {
            put(COL_CONTACT_ID,         contact.contactId)
            put(COL_SHARED_SECRET,      contact.sharedSecret)
            put(COL_TRUST_LEVEL,        contact.trustLevel)
            put(COL_ALIAS,              contact.alias)
            put(COL_ALIAS_LAST_ROTATED, contact.aliasLastRotated)
            put(COL_MNEMONIC,           contact.mnemonic)
            put(COL_OUTBOUND_COUNTER,   contact.outboundCounter)
            put(COL_INBOUND_COUNTER,    contact.inboundCounter)
            put(COL_INBOUND_EPOCH,      contact.inboundEpoch)
            put(COL_OUTBOUND_CTL_COUNTER, contact.outboundCtlCounter)
            put(COL_INBOUND_CTL_COUNTER,  contact.inboundCtlCounter)
            put(COL_OUTBOUND_GRP_COUNTER, contact.outboundGrpCounter)
            put(COL_INBOUND_GRP_COUNTER,  contact.inboundGrpCounter)
            put(COL_VOUCHED_BY,           contact.vouchedByContactId)
            put(COL_VOUCHED_AT,           contact.vouchedAt)
        }
        // CONFLICT_REPLACE: updating an existing contact overwrites the old row.
        return replaceOrThrow(TABLE_CONTACTS, values, "contact write failed")
    }

    /**
     * Returns the [ContactRecord] for [contactId], or null if not found.
     *
     * The returned [ContactRecord.sharedSecret] is RAW (as stored) — SQLCipher's
     * whole-DB encryption is the only at-rest layer; callers use it directly.
     */
    override fun getContact(contactId: String): ContactRecord? {
        val cursor = db.query(
            TABLE_CONTACTS,
            null,                           // all columns
            "$COL_CONTACT_ID = ?",
            arrayOf(contactId),
            null, null, null
        )
        return cursor.use { if (it.moveToFirst()) it.toContactRecord() else null }
    }

    /**
     * Returns all contacts ordered by alias ascending.
     */
    override fun getAllContacts(): List<ContactRecord> {
        val cursor = db.query(
            TABLE_CONTACTS,
            null,
            null, null, null, null,
            "$COL_ALIAS ASC"
        )
        return cursor.use { c ->
            buildList { while (c.moveToNext()) add(c.toContactRecord()) }
        }
    }

    // -----------------------------------------------------------------------
    // Generic key/value (`_meta`) — see VaultDatabase. Backs the Double Ratchet
    // store + its enablement/bootstrap markers.
    // -----------------------------------------------------------------------

    override fun getMeta(key: String): String? {
        val cursor = db.query("_meta", arrayOf("value"), "key = ?", arrayOf(key), null, null, null)
        return cursor.use { if (it.moveToFirst()) it.getString(0) else null }
    }

    override fun putMeta(key: String, value: String) {
        val values = ContentValues().apply { put("key", key); put("value", value) }
        // -1 == failure; throw so the caller's fail-closed path fires (mirrors
        // insertContact's @Throws contract for ratchet-state persistence).
        if (db.insertWithOnConflict("_meta", null, values, SQLiteDatabase.CONFLICT_REPLACE) == -1L) {
            throw RuntimeException("meta write failed")
        }
    }

    override fun deleteMeta(key: String) {
        db.delete("_meta", "key = ?", arrayOf(key))
    }

    /**
     * Snapshot of every `_meta` KEY, so deleteGroup/deleteContact can
     * classify residue with the shared [isGroupMetaResidueForGroup] /
     * [isGroupMetaResidueForContact] / [isReferralMetaResidueForContact] /
     * [isScreenshotNoticeResidueForContact] predicates and delete the matches.
     * Materialised into a list (not streamed) so we can deleteMeta while iterating. Now also part of the [VaultDatabase] contract —
     * `ReferralManager` scans the `ref_*` namespace from commonMain.
     */
    override fun metaKeys(): List<String> {
        val cursor = db.query("_meta", arrayOf("key"), null, null, null, null, null)
        return cursor.use { c -> buildList { while (c.moveToNext()) add(c.getString(0)) } }
    }

    // Atomic multi-row write: SQLCipher transaction. If [block] throws,
    // setTransactionSuccessful is skipped and endTransaction rolls back, so a torn
    // batch leaves no orphaned rows. Rethrows for the caller's fail-closed path.
    override fun withTransaction(block: () -> Unit) {
        db.beginTransaction()
        try {
            block()
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
        }
    }

    // -----------------------------------------------------------------------
    // InboxIds
    // -----------------------------------------------------------------------

    /**
     * Inserts or replaces an inbox ID record.
     *
     * @return The SQLite row ID, or -1 on failure.
     */
    override fun insertInboxId(record: InboxIdRecord): Long {
        val values = ContentValues().apply {
            put(COL_INBOX_ID,   record.inboxId)
            put(COL_CONTACT_ID, record.contactId)
            put(COL_CREATED_AT, record.createdAt)
            put(COL_EXPIRES_AT, record.expiresAt)
            put(COL_DIRECTION,  record.direction)
            // null is the explicit "legacy / no cap yet" marker.
            put(COL_CAP,        record.cap)
        }
        return replaceOrThrow(TABLE_INBOX_IDS, values, "inbox id write failed")
    }

    /**
     * Returns the [InboxIdRecord] for [inboxId], or null if not found.
     */
    override fun getInboxId(inboxId: String): InboxIdRecord? {
        val cursor = db.query(
            TABLE_INBOX_IDS,
            null,
            "$COL_INBOX_ID = ?",
            arrayOf(inboxId),
            null, null, null
        )
        return cursor.use { if (it.moveToFirst()) it.toInboxIdRecord() else null }
    }

    /**
     * Returns the most recently created inbox for [contactId] matching the given
     * [direction] ("outbound" or "inbound"). Used by
     * [com.vg.run.MessageManager] to resolve which relay inbox to send to /
     * read from for a given contact.
     *
     * The `expiresAt > now` predicate this query used to carry is GONE — the
     * client's absolute 365-day stamp expired healthy, actively-polled inboxes that
     * the relay (whose TTL slides on activity) still held, silently killing send,
     * poll, peek and push for that contact. The choice now lives in the shared
     * [selectOperationalInbox], which both platforms call so the policy cannot
     * drift; see its kdoc. [getInboxId] stays unfiltered as it always was.
     */
    override fun getInboxIdForContact(contactId: String, direction: String): InboxIdRecord? {
        val cursor = db.query(
            TABLE_INBOX_IDS,
            null,
            "$COL_CONTACT_ID = ? AND $COL_DIRECTION = ?",
            arrayOf(contactId, direction),
            null, null,
            "$COL_CREATED_AT DESC",
            INBOX_LOOKUP_CANDIDATE_CAP.toString()
        )
        val rows = cursor.use { c -> buildList { while (c.moveToNext()) add(c.toInboxIdRecord()) } }
        return selectOperationalInbox(rows)
    }

    /**
     * Every inbox row, unfiltered — see [VaultDatabase.getAllInboxIds]. Unlike
     * [getInboxIdForContact] this includes superseded rows a peer's re-announce
     * left behind, which a device-move export needs.
     */
    override fun getAllInboxIds(): List<InboxIdRecord> {
        val cursor = db.query(TABLE_INBOX_IDS, null, null, null, null, null, null)
        return cursor.use { c -> buildList { while (c.moveToNext()) add(c.toInboxIdRecord()) } }
    }

    /**
     * Forward-only re-stamp of one row's informational `expiresAt` (see
     * [VaultDatabase.touchInboxExpiry]). The `expiresAt < ?` predicate makes
     * "never lower it" an SQL-level property, so even a racing caller with an older
     * value cannot walk the stamp backward, and no row means no write (no
     * resurrection).
     */
    override fun touchInboxExpiry(inboxId: String, expiresAt: Long) {
        val values = ContentValues().apply { put(COL_EXPIRES_AT, expiresAt) }
        // Swallowed, like IosVaultDatabase's plain `exec`: the interface documents this
        // as best-effort hygiene ("callers must treat a failure as a no-op"), so a
        // closed handle or SQLite fault must not throw into the poll/send path.
        try {
            db.update(
                TABLE_INBOX_IDS,
                values,
                "$COL_INBOX_ID = ? AND $COL_EXPIRES_AT < ?",
                arrayOf(inboxId, expiresAt.toString()),
            )
        } catch (e: Exception) {
            platformLogWarn("DatabaseManager", "inbox expiry re-stamp skipped: ${e::class.simpleName}")
        }
    }

    // -----------------------------------------------------------------------
    // Groups (v6)
    // -----------------------------------------------------------------------

    override fun insertGroup(group: GroupRecord): Long {
        val values = ContentValues().apply {
            put(COL_GROUP_ID,        group.groupId)
            put(COL_GROUP_NAME,      group.name)
            put(COL_GROUP_EPOCH,     group.epoch)
            put(COL_ADMIN_MEMBER_ID, group.adminMemberId)
            put(COL_MY_MEMBER_ID,    group.myMemberId)
            put(COL_CREATED_AT,      group.createdAt)
        }
        return replaceOrThrow(TABLE_GROUPS, values, "group write failed")
    }

    override fun getGroup(groupId: String): GroupRecord? {
        val cursor = db.query(TABLE_GROUPS, null, "$COL_GROUP_ID = ?", arrayOf(groupId), null, null, null)
        return cursor.use { if (it.moveToFirst()) it.toGroupRecord() else null }
    }

    override fun getAllGroups(): List<GroupRecord> {
        val cursor = db.query(TABLE_GROUPS, null, null, null, null, null, "$COL_GROUP_NAME ASC")
        return cursor.use { c -> buildList { while (c.moveToNext()) add(c.toGroupRecord()) } }
    }

    override fun deleteGroup(groupId: String) {
        // The two deletes are ONE
        // transaction — a crash between them must not leave orphan group_members
        // (memberIds, pairwise HMAC tags, contactId links) as a forensic residual of
        // group membership after a "delete". withTransaction commits all-or-nothing.
        withTransaction {
            db.delete(TABLE_GROUP_MEMBERS, "$COL_GROUP_ID = ?", arrayOf(groupId))
            db.delete(TABLE_GROUPS,        "$COL_GROUP_ID = ?", arrayOf(groupId))
            // The row deletes above don't touch `_meta`,
            // where GroupManager keeps group-scoped state (the admin-side roster
            // throttle `grp_roster_rl:<groupId>:<contactId>`). Left behind, it names
            // exactly which local contacts were members, with timestamps. Purge every
            // matching key via the shared classifier so Android + iOS stay identical.
            // `group_admin:<groupId>` is deliberately RETAINED (anti-eclipse
            // tombstone) — the classifier excludes it.
            //
            // SCREENSHOT NOTICES (same rule, same loop): `ssn:<groupId>:<sender>:<ms>`
            // rows name exactly who screenshotted this group and when. Purged by the
            // shared predicate so Android + iOS stay identical.
            //
            // PARKED INVITES (same rule, same loop): `grp_pinv:<groupId>:<inviter>` —
            // the durable copy of an un-answered invite (GroupInviteStore). This is
            // also the clause that drops a parked invite when the user LEAVES or is
            // removed from the group, since every such path reaches deleteGroup.
            for (key in metaKeys()) {
                if (isGroupMetaResidueForGroup(key, groupId) ||
                    isScreenshotNoticeResidueForGroup(key, groupId) ||
                    isGroupInviteResidueForGroup(key, groupId)
                ) deleteMeta(key)
            }
        }
    }

    override fun insertGroupMember(member: GroupMemberRecord): Long {
        val values = ContentValues().apply {
            put(COL_GROUP_ID,   member.groupId)
            put(COL_MEMBER_ID,  member.memberId)
            put(COL_CONTACT_ID, member.contactId)   // null = unresolved
            put(COL_ADDED_AT,   member.addedAt)
            put(COL_TAGS,       member.tags)
        }
        return replaceOrThrow(TABLE_GROUP_MEMBERS, values, "group member write failed")
    }

    override fun getGroupMembers(groupId: String): List<GroupMemberRecord> {
        val cursor = db.query(
            TABLE_GROUP_MEMBERS, null, "$COL_GROUP_ID = ?", arrayOf(groupId),
            null, null, "$COL_ADDED_AT ASC"
        )
        return cursor.use { c -> buildList { while (c.moveToNext()) add(c.toGroupMemberRecord()) } }
    }

    override fun deleteGroupMember(groupId: String, memberId: String) {
        db.delete(TABLE_GROUP_MEMBERS, "$COL_GROUP_ID = ? AND $COL_MEMBER_ID = ?", arrayOf(groupId, memberId))
    }

    /**
     * Removes a single contact and ALL its dependent state: its inbox
     * ids, its ratchet/session `_meta` keys (the row deletes below don't
     * touch `_meta`), its contact-scoped GROUP `_meta` residue (invite/roster
     * throttles keyed by this contactId), its persisted REFERRAL handshake records
     * ([isReferralMetaResidueForContact]), its persisted SCREENSHOT NOTICES in both id
     * positions ([isScreenshotNoticeResidueForContact]), its durable PARKED GROUP
     * INVITES ([isGroupInviteResidueForContact]), and it unresolves the contact
     * from any group memberships (the membership itself is the group admin's to
     * change, not ours).
     *
     * Must stay byte-identical in effect to `IosVaultDatabase.deleteContact` — the
     * two iterate the same shared enumerations/classifiers for exactly that reason.
     */
    override fun deleteContact(contactId: String) {
        // All deletes in ONE transaction — a crash mid-delete must not leave a
        // torn vault (e.g. the inbox rows gone but the contact row + its live sharedSecret
        // still present, or orphaned ratchet _meta keys). withTransaction commits
        // all-or-nothing. (No message delete: v9 removed the table — messages are RAM-only.)
        withTransaction {
            db.delete(TABLE_INBOX_IDS, "$COL_CONTACT_ID = ?", arrayOf(contactId))
            db.delete(TABLE_CONTACTS,  "$COL_CONTACT_ID = ?", arrayOf(contactId))
            // Erase the contact's ratchet/session state in _meta too —
            // the row deletes above don't touch it, so it would otherwise linger as
            // orphaned key material until a full wipe.
            for (key in ratchetMetaKeysForContact(contactId)) deleteMeta(key)
            // Also purge contact-scoped GROUP residue in
            // `_meta` — `grp_inv_rl:<contactId>` (an invite timeline whose KEY is the
            // deleted contactId) and every `grp_roster_rl:<groupId>:<contactId>` across
            // all groups. Classified by the shared predicate so Android + iOS match.
            //
            // REFERRAL (same rule, value-keyed): a persisted referral handshake record
            // is keyed by introId and names the contact in its BODY, so it needs the
            // value — read only for keys already in the `ref_*` namespace. Leaving one
            // behind would strand an ephemeral X25519 private key + a live inbox
            // capability for a contact the user just deleted.
            //
            // SCREENSHOT NOTICES (key-scoped, both id positions): the deleted
            // contact's own 1:1 notices AND the notices they left in groups the user
            // is still in — `ssn:` rows would otherwise keep naming a deleted contact
            // as the screenshotter until they expired.
            //
            // PARKED INVITES (key-scoped, inviter position): `grp_pinv:<group>:<contactId>`
            // is the durable copy of an invite from THIS contact that the user never
            // answered (GroupInviteStore). It names a group the user is not in and
            // cannot act on any more, so it must go with them.
            for (key in metaKeys()) {
                if (isGroupMetaResidueForContact(key, contactId)) { deleteMeta(key); continue }
                if (isScreenshotNoticeResidueForContact(key, contactId)) { deleteMeta(key); continue }
                if (isGroupInviteResidueForContact(key, contactId)) { deleteMeta(key); continue }
                if (isReferralMetaKey(key) &&
                    isReferralMetaResidueForContact(key, getMeta(key), contactId)
                ) deleteMeta(key)
            }
            // Group members referencing the contact become unresolved — the
            // membership itself is the group admin's to change, not ours.
            val values = ContentValues().apply { putNull(COL_CONTACT_ID) }
            db.update(TABLE_GROUP_MEMBERS, values, "$COL_CONTACT_ID = ?", arrayOf(contactId))
        }
    }

    /**
     * Row-level scrub: deletes every row from every table (+ `_meta`) and VACUUMs to
     * overwrite freed pages on disk.
     *
     * This is NOT the primary Android wipe path. The real Android wipe
     * (WipeRoutine — inactivity / panic / orphan) CRYPTO-ERASES the device key and
     * DELETES the whole DB file, which is strictly stronger (an unrecoverable file
     * beats scrubbed rows in a recoverable one). wipeAllTables is used by the iOS wipe
     * path and by tests; on Android it is otherwise dead. Do NOT describe it as "the
     * inactivity-wipe path". (Per-open PRAGMA secure_delete=ON also covers ordinary
     * row deletes.)
     */
    override fun wipeAllTables() {
        // The row-clears are ONE transaction so a torn wipe can't leave
        // some tables cleared and others intact. VACUUM must run OUTSIDE a transaction
        // (SQLite forbids it inside), so it follows the commit.
        withTransaction {
            db.delete(TABLE_INBOX_IDS,     null, null)
            db.delete(TABLE_CONTACTS,      null, null)
            db.delete(TABLE_GROUP_MEMBERS, null, null)
            db.delete(TABLE_GROUPS,        null, null)
            // _meta backs the Double Ratchet per-contact state (dr/{contact}/{channel}).
            // Clearing it here makes wipeAllTables() match its "every table" contract
            // so a future row-only wipe (e.g. logout) can't leave ratchet keys behind.
            // The 'seeded' marker is recreated on next open.
            db.delete("_meta", null, null)
        }
        // VACUUM rewrites the database file, overwriting deleted page content
        // on disk. This reduces forensic recoverability on flash storage.
        try { db.execSQL("VACUUM") } catch (_: Exception) { }
    }

    /**
     * Re-keys THIS live connection. See [VaultDatabase.rekey] for the
     * return-value warning — a `true` here is "no error we could see", never
     * proof that the file is on [newDbKey]; only [VaultFactory.probeKey] proves
     * that.
     *
     * `SQLiteDatabase.changePassword(byte[])` is the only in-library route to
     * `sqlite3_rekey`: it swaps the password on the OPEN connection's
     * configuration and calls `SQLiteConnectionPool.reconfigure`, which (when the
     * bytes differ from the ones the pool holds) invokes
     * `SQLiteConnection.changePassword` → `nativeReKey` → `sqlite3_rekey_v2` on
     * the pool's PRIMARY connection, and throws `SQLiteException` only when that
     * native call returns non-zero.
     *
     * Two consequences of it being the pool's primary connection:
     *  - it must be called with NO connection checked out — no in-flight
     *    statement, no open [withTransaction] block — because the pool nulls
     *    `mAvailablePrimaryConnection` while a connection is acquired and would
     *    NPE. That NPE is a RuntimeException, so `changePassword` restores the
     *    previous password on the configuration before it propagates, and we
     *    report it as `false` with nothing changed;
     *  - it re-keys the LIVE handle, which is the point: a second connection
     *    re-keying behind this one would leave this one's read context on the old
     *    key and fail every later query.
     *
     * ENCODING: RAW BYTES, exactly as `init` hands them to `SQLiteOpenHelper`'s
     * byte[] constructor. SQLCipher only takes its raw-key branch for an
     * `x'<hex>'`-shaped passphrase; raw bytes go through PBKDF2 with the salt
     * stored in the file header. Passing iOS's hex keyspec here would derive a
     * DIFFERENT encryption key and orphan the file permanently. This holds even
     * when THIS handle was opened in raw-key mode with an adopted K' (2026-10-07):
     * the re-key target is always passphrase mode, which VaultSelector records as
     * a PASSPHRASE payload (proven from a raw handle by RawKeyAdoptionTest).
     *
     * The array is RETAINED BY REFERENCE by `SQLiteDatabaseConfiguration`
     * (`updateParametersFrom` copies the reference, not the bytes), so we pass a
     * private copy rather than the caller's array and zero that copy afterwards —
     * the same idiom, and the same resulting state, as `init`'s `dbPassword.fill(0)`.
     *
     * Concurrency (parity, by design): no quiesce here — a statement in flight makes
     * changePassword throw (a loud `false`); iOS instead serialises under its
     * NSRecursiveLock. The caller decides from probes either way.
     */
    override fun rekey(newDbKey: ByteArray): Boolean {
        val keyCopy = newDbKey.copyOf()
        return try {
            db.changePassword(keyCopy)
            true
        } catch (_: Throwable) {
            false
        } finally {
            keyCopy.secureWipe()
        }
    }

    override val isOpen: Boolean get() = db.isOpen

    override fun close() {
        try { db.close() } catch (_: Exception) { }
    }

    // -----------------------------------------------------------------------
    // Cursor extension helpers — keep mapping logic in one place
    //
    // Strictness (parity, by design): getColumnIndexOrThrow throws on a missing
    // column; IosVaultDatabase's mappers instead drop a row missing a key column and
    // default the rest.
    // -----------------------------------------------------------------------

    private fun Cursor.toContactRecord() = ContactRecord(
        contactId        = getString(getColumnIndexOrThrow(COL_CONTACT_ID)),
        sharedSecret     = getBlob(getColumnIndexOrThrow(COL_SHARED_SECRET)),
        trustLevel       = getInt(getColumnIndexOrThrow(COL_TRUST_LEVEL)),
        alias            = getString(getColumnIndexOrThrow(COL_ALIAS)),
        aliasLastRotated = getLong(getColumnIndexOrThrow(COL_ALIAS_LAST_ROTATED)),
        mnemonic         = getString(getColumnIndexOrThrow(COL_MNEMONIC)),
        outboundCounter  = getLong(getColumnIndexOrThrow(COL_OUTBOUND_COUNTER)),
        inboundCounter   = getLong(getColumnIndexOrThrow(COL_INBOUND_COUNTER)),
        inboundEpoch     = getString(getColumnIndexOrThrow(COL_INBOUND_EPOCH)),
        outboundCtlCounter = getLong(getColumnIndexOrThrow(COL_OUTBOUND_CTL_COUNTER)),
        inboundCtlCounter  = getLong(getColumnIndexOrThrow(COL_INBOUND_CTL_COUNTER)),
        outboundGrpCounter = getLong(getColumnIndexOrThrow(COL_OUTBOUND_GRP_COUNTER)),
        inboundGrpCounter  = getLong(getColumnIndexOrThrow(COL_INBOUND_GRP_COUNTER)),
        vouchedByContactId = getColumnIndexOrThrow(COL_VOUCHED_BY).let { if (isNull(it)) null else getString(it) },
        vouchedAt          = getLong(getColumnIndexOrThrow(COL_VOUCHED_AT)),
    )

    private fun Cursor.toInboxIdRecord(): InboxIdRecord {
        val capIdx = getColumnIndexOrThrow(COL_CAP)
        return InboxIdRecord(
            inboxId   = getString(getColumnIndexOrThrow(COL_INBOX_ID)),
            contactId = getString(getColumnIndexOrThrow(COL_CONTACT_ID)),
            createdAt = getLong(getColumnIndexOrThrow(COL_CREATED_AT)),
            expiresAt = getLong(getColumnIndexOrThrow(COL_EXPIRES_AT)),
            direction = getString(getColumnIndexOrThrow(COL_DIRECTION)),
            cap       = if (isNull(capIdx)) null else getString(capIdx),
        )
    }

    private fun Cursor.toGroupRecord() = GroupRecord(
        groupId       = getString(getColumnIndexOrThrow(COL_GROUP_ID)),
        name          = getString(getColumnIndexOrThrow(COL_GROUP_NAME)),
        epoch         = getLong(getColumnIndexOrThrow(COL_GROUP_EPOCH)),
        adminMemberId = getString(getColumnIndexOrThrow(COL_ADMIN_MEMBER_ID)),
        myMemberId    = getString(getColumnIndexOrThrow(COL_MY_MEMBER_ID)),
        createdAt     = getLong(getColumnIndexOrThrow(COL_CREATED_AT)),
    )

    private fun Cursor.toGroupMemberRecord(): GroupMemberRecord {
        val contactIdx = getColumnIndexOrThrow(COL_CONTACT_ID)
        return GroupMemberRecord(
            groupId   = getString(getColumnIndexOrThrow(COL_GROUP_ID)),
            memberId  = getString(getColumnIndexOrThrow(COL_MEMBER_ID)),
            contactId = if (isNull(contactIdx)) null else getString(contactIdx),
            addedAt   = getLong(getColumnIndexOrThrow(COL_ADDED_AT)),
            tags      = getString(getColumnIndexOrThrow(COL_TAGS)),
        )
    }
}

/**
 * True when a SQLCipher open failure indicates the file is "not a database" for
 * the supplied key — a wrong/legacy key or a corrupt header (SQLITE_NOTADB /
 * "file is not a database" / "file is encrypted or is not a database") — as
 * opposed to a TRANSIENT, recoverable error (disk I/O, SQLITE_BUSY, CANTOPEN,
 * out of space). Only the former justifies deleting and re-provisioning the
 * vault; a transient error must never destroy real user data. net.zetetic
 * surfaces the SQLite (extended) result code in the exception message, so we
 * match on that text. Biased toward re-throw: an unrecognised message is
 * treated as transient (fail closed, no deletion).
 */
internal fun isNotADatabaseFailure(e: Throwable): Boolean {
    val msg = (e.message ?: "").lowercase()
    return "not a database" in msg ||
        "file is encrypted" in msg ||
        "notadb" in msg ||
        "(code 26" in msg
}

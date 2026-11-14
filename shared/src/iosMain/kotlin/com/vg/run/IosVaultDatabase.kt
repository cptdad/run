@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package com.vg.run

import kotlinx.cinterop.convert
import platform.Foundation.*

// ---------------------------------------------------------------------------
// IosVaultDatabase — SQLCipher-backed VaultDatabase for iOS.
//
// All records are stored in an AES-256 encrypted SQLite database via
// the DatabaseBridge (implemented in Swift using SQLCipher).
//
// Database file: {Application Support|Caches}/run.db
// ---------------------------------------------------------------------------

/**
 * Resolves the directory holding the vault DB: Application Support when available
 * (created on demand — iOS does not create it), else Caches.
 *
 * Extracted from [IosVaultDatabase]'s init so the provision guard's existence probe
 * and the actual open resolve through the SAME code. Duplicating the fallback would
 * let the guard check one path while the destructive isProvision+NOTADB recreate
 * deletes another — the guard would pass and the vault would still be destroyed.
 */
internal fun iosVaultBaseDir(): String {
    val fm = NSFileManager.defaultManager
    return (NSSearchPathForDirectoriesInDomains(
        NSApplicationSupportDirectory, NSUserDomainMask, true
    ).firstOrNull() as? String)?.also { dir ->
        // Ensure Application Support exists (not created by default on iOS)
        fm.createDirectoryAtPath(
            dir,
            withIntermediateDirectories = true,
            attributes = null,
            error = null
        )
    } ?: (NSSearchPathForDirectoriesInDomains(
        NSCachesDirectory, NSUserDomainMask, true
    ).firstOrNull() as? String ?: error("Cannot find writable directory"))
}

/** Full path of the vault database file. */
internal fun iosVaultDbPath(): String = "${iosVaultBaseDir()}/${VaultFiles.DB}"

/**
 * True when the vault database file exists — the iOS half of
 * [VaultFactory.vaultFileExists]. Only the main file counts; a stray
 * `-wal`/`-shm`/`-journal` sidecar is debris from an aborted create.
 */
internal fun iosVaultFileExists(): Boolean =
    NSFileManager.defaultManager.fileExistsAtPath(iosVaultDbPath())

/**
 * PROVISION-1: unlink the vault file and every sidecar at the SAME path
 * [iosVaultFileExists] probes and [IosVaultDatabase] opens — the iOS half of
 * [VaultFactory.deleteVaultFileAfterFailedProvision]. See that kdoc for the one
 * legal caller; this is only how it is met here.
 *
 * Also the `isProvision && NOTADB` recreate branch in [IosVaultDatabase]'s init
 * (it used to inline the identical loop). Suffixes: [VaultFiles.SIDECAR_SUFFIXES]
 * (`-journal` included: a journal_mode fallback or an interrupted transaction can
 * leave one holding pre-image ciphertext pages).
 * `removeItemAtPath` reports an absent file through the ignored `error` out-param
 * rather than raising, so this never throws.
 */
internal fun iosDeleteVaultFiles() {
    // `-journal` is iOS's own sidecar since RUN-02 (rollback journal, TRUNCATE mode —
    // a 0-byte file between transactions); `-wal`/`-shm` are what builds before it
    // (WAL mode) leave until the first open converts the file. Both platforms sweep
    // all of them.
    val fm = NSFileManager.defaultManager
    val dbPath = iosVaultDbPath()
    for (suffix in VaultFiles.SIDECAR_SUFFIXES) {
        fm.removeItemAtPath("$dbPath$suffix", null)
    }
}

/**
 * NSFileProtectionComplete + backup exclusion for the vault DB and every sidecar.
 * See [IosVaultDatabase.protectDbFiles] for the full rationale; it lives at top level so the key probe, which never constructs the class, can
 * apply the same protection to any sidecar its open materialises.
 */
internal fun iosProtectVaultDbFiles(dbPath: String) {
    val fm = NSFileManager.defaultManager
    // -journal is included: if a rollback journal is ever
    // materialised (journal_mode fallback / interrupted txn) it holds pre-image
    // ciphertext pages and must be NSFileProtectionComplete + backup-excluded like
    // the other sidecars. setAttributes/setResourceValue on an absent file is a
    // harmless no-op (error ignored), so listing it unconditionally is safe.
    for (suffix in VaultFiles.SIDECAR_SUFFIXES) {
        val path = "$dbPath$suffix"
        fm.setAttributes(
            mapOf<Any?, Any?>(NSFileProtectionKey to NSFileProtectionComplete),
            ofItemAtPath = path,
            error = null
        )
        // Exclude from backups. A no-op on a not-yet-created sidecar (the
        // error is ignored, mirroring setAttributes above).
        NSURL.fileURLWithPath(path).setResourceValue(
            NSNumber.numberWithBool(true),
            forKey = NSURLIsExcludedFromBackupKey,
            error = null
        )
    }
}

/**
 * RUN-02: make sure the rollback journal exists BEFORE SQLite first creates it, so
 * it is born NSFileProtectionComplete instead of inheriting the directory's weaker
 * default class. In TRUNCATE mode SQLite keeps reusing this inode (it empties it at
 * every commit, it never unlinks it), so the class set here — and the backup
 * exclusion [iosProtectVaultDbFiles] adds right after — covers every later
 * transaction's pre-images. Without it, a vault upgraded from the WAL build would
 * hold its first session's journal in the default class until the next open.
 *
 * NEVER touches an existing file: an existing `-journal` may be a HOT journal
 * (unclean exit mid-commit) that SQLite must roll back — overwriting it would tear
 * the vault. A 0-byte journal is ignored by SQLite's hot-journal check (it needs at
 * least one non-zero header byte), so creating an empty one is inert. Only done
 * next to a real db file. Best-effort, never throws.
 */
internal fun iosPrecreateProtectedJournal(dbPath: String) {
    try {
        val fm = NSFileManager.defaultManager
        if (!fm.fileExistsAtPath(dbPath)) return
        val journal = "$dbPath-journal"
        if (fm.fileExistsAtPath(journal)) return
        fm.createFileAtPath(
            journal,
            contents = null,
            attributes = mapOf<Any?, Any?>(NSFileProtectionKey to NSFileProtectionComplete),
        )
    } catch (_: Throwable) {
        // Hygiene only: SQLite creates the file itself if this did not.
    }
}

/** `sqlite3_busy_timeout` SwiftDatabaseBridge.open sets (RUN-02); keep in lockstep. */
private const val BRIDGE_BUSY_TIMEOUT_MS = 2500L

/** SQLite's journal-mode words — the only mode text RUN-02's warning may log. */
private val KNOWN_JOURNAL_MODES = setOf("delete", "truncate", "persist", "memory", "wal", "off")

/** Size of the vault DB file in bytes, 0 when absent. Shared by the #28 guards. */
private fun iosVaultDbFileSize(dbPath: String): Long {
    val fm = NSFileManager.defaultManager
    if (!fm.fileExistsAtPath(dbPath)) return 0L
    return (fm.attributesOfItemAtPath(dbPath, null)?.get(NSFileSize) as? NSNumber)?.longValue ?: 0L
}

/**
 * The iOS half of [VaultFactory.probeKey] — see that kdoc for the contract; this
 * is only how it is met here.
 *
 * Opens a SEPARATE, short-lived bridge handle on the SAME path [IosVaultDatabase]
 * opens, hands it the RAW key bytes exactly as the constructor does (the Swift
 * side turns them into the `x'<hex>'` keyspec in a wipeable buffer), and reuses
 * the bridge's own key verification — `SwiftDatabaseBridge.open` runs
 * `SELECT count(*) FROM sqlite_master` and returns SQLITE_NOTADB for a wrong key.
 * Then closes. It does NOT construct an [IosVaultDatabase]: that would run
 * `createTables()`, the idempotent ALTERs and the `_meta('seeded')` upsert, i.e.
 * it would WRITE to the vault it was merely asked about.
 *
 * Non-destructive by construction: `sqlite3_open` has CREATE semantics, so the
 * `< MIN_VALID_VAULT_DB_BYTES` guard (the same #28 guard the unlock path uses,
 * i.e. `isProvision = false` semantics) is what stops a probe from manufacturing
 * the very file it was asked about; and nothing on this path removes a file — the
 * destructive `removeItemAtPath` loop lives behind `isProvision && NOTADB` in the
 * constructor and is not reachable from here.
 *
 * The non-empty `sqlite_master` requirement closes the residual check-then-open
 * gap: if the file were swapped for a fresh empty database between the size check
 * and the open, the open would "succeed" with zero objects, and that answers
 * `false` rather than blessing an empty vault.
 */
internal fun iosProbeVaultKey(dbKey: ByteArray): Boolean {
    val dbPath = iosVaultDbPath()
    if (iosVaultDbFileSize(dbPath) < MIN_VALID_VAULT_DB_BYTES) return false

    val bridge = DatabaseBridgeHolder.factory?.create() ?: return false
    var ok = false
    try {
        val keyMaterial = dbKey.copyOf()
        try {
            val rc = bridge.open(dbPath, keyMaterial)
            // Unconditional, before anything can return: the open (its hot-journal
            // rollback, its `PRAGMA journal_mode=TRUNCATE` — RUN-02) may have
            // materialised or rewritten a sidecar, and a probe must never leave an
            // unprotected, backed-up sidecar holding vault pages. A no-op on files
            // that already exist / never appeared.
            iosProtectVaultDbFiles(dbPath)
            if (rc == 0) {
                val rows = bridge.query("SELECT count(*) AS n FROM sqlite_master", NSMutableArray())
                val objects = if (rows.count.toInt() > 0)
                    ((rows.objectAtIndex(0.convert()) as? NSDictionary)
                        ?.objectForKey("n") as? NSNumber)?.longLongValue ?: 0L
                else 0L
                ok = objects > 0L
            }
        } finally {
            keyMaterial.secureWipe()
        }
    } catch (_: Throwable) {
        // Wrong key, busy, I/O error — all "no", never a throw (see the contract).
        ok = false
    } finally {
        try { bridge.close() } catch (_: Throwable) { }
    }
    return ok
}

// CR-1: [dbKey] is the 32-byte SQLCipher passphrase supplied by
// VaultSelector (PIN-wrapped). This class no longer derives its own key.
// [isProvision] is true ONLY at the one-time vault-provision open (false on
// every unlock); it gates the destructive recreate of a "not a database" file.
class IosVaultDatabase(dbKey: ByteArray, isProvision: Boolean = false) : VaultDatabase {

    private val bridge: DatabaseBridge = DatabaseBridgeHolder.factory?.create()
        ?: error("DatabaseBridgeFactory not registered")
    // REENTRANT: withTransaction holds this across its block(), whose inner
    // writes re-acquire it — a non-reentrant NSLock would self-deadlock there. Reentrancy
    // is otherwise behaviourally identical for the per-method lock/unlock pairs.
    private val lock = NSRecursiveLock()

    // RUN-02 state, guarded by [lock] (init runs before the instance is shared).
    // DECLARED ABOVE `init` ON PURPOSE: Kotlin runs property initialisers and init
    // blocks in source order, so a field declared below would be reset to its
    // initialiser AFTER init's enforceRollbackJournal() had armed it.
    /** True while this connection is NOT proven to be on a rollback journal. */
    private var rollbackJournalUnproven = false
    /** Open withTransaction depth: a journal-mode switch is refused inside a transaction. */
    private var txnDepth = 0
    /** One warning per unproven episode, so a stuck retry cannot flood the log. */
    private var rollbackJournalWarned = false

    init {
        val dbPath = iosVaultDbPath()
        val baseDir = iosVaultBaseDir()
        val fm = NSFileManager.defaultManager

        // Diagnostic: log dir state (println visible in Console.app even in Release)
        val dirExists = fm.fileExistsAtPath(baseDir)
        val dirWritable = fm.isWritableFileAtPath(baseDir)
        // #28: existence alone is not enough — a present-but-empty/truncated run.db
        // (0 bytes, e.g. an examiner truncating instead of deleting) passes
        // fileExistsAtPath, and SQLCipher opens a 0-length file as a brand-new empty
        // database (PRAGMA key + verify both "succeed"), silently masking the data
        // loss. A valid SQLCipher DB is always at least one page (salt + header,
        // >= 4096B); require a non-trivial size so a truncated stub is treated as
        // "not a real vault" and hits the fail-closed guard below. No false positive:
        // no legitimate provisioned vault is ever this small.
        val dbFileSize: Long = iosVaultDbFileSize(dbPath)
        val dbExists = dbFileSize >= MIN_VALID_VAULT_DB_BYTES
        platformLog("IosVaultDB", "dir=$dirExists writable=$dirWritable dbExists=$dbExists size=$dbFileSize")

        // CR-1: passphrase supplied by VaultSelector (PIN + device key). Pass the
        // RAW key bytes to the bridge; the Swift side hex-encodes them into a
        // wipeable C buffer just before keying SQLCipher (the old hex String lived
        // immutably in the Kotlin/NSString heap, unwipeable under RAM capture).
        // keyMaterial itself is a ByteArray and is secureWipe()d
        // on every exit path below.
        val keyMaterial = dbKey.copyOf()

        // On the UNLOCK path (isProvision=false), a MISSING db file
        // means the vault was lost/deleted (reinstall with surviving keychain — see
        // the purge; an evicted purgeable-Caches fallback; or targeted tampering).
        // sqlite3_open uses OPEN_CREATE, so it would CREATE the file and a correct
        // PIN would silently open a brand-new EMPTY vault, masking the loss. Fail
        // closed BEFORE the open — VaultSelector.unlock maps the throw to the
        // neutral UnlockResult.Error (retryable, never a wipe), so the user sees a
        // recoverable error instead of a silently-empty vault. (A dedicated
        // "vault file missing → re-provision" UX is the follow-up; the safety
        // property — never silently open empty — holds here.)
        if (!isProvision && !dbExists) {
            keyMaterial.secureWipe()
            error("vault database missing or empty at unlock (validSize=false) — refusing to open an empty vault")
        }

        val rc = bridge.open(dbPath, keyMaterial)
        if (rc != 0) {
            // bridge.open returns 0 (OK) or a SQLite result code. A destructive
            // delete-and-recreate is ONLY safe when BOTH: (a) this is a PROVISION
            // open (isProvision is true only at provision; false on every unlock —
            // see VaultSelector) where no real user data exists yet, AND (b) the
            // failure is a genuine "not a database" / wrong-key error (NOTADB).
            // On the UNLOCK path the credential + dbKey are already verified, so
            // any failure is transient (BUSY/IOERR/CANTOPEN/locked sidecar):
            // NEVER delete — fail closed and leave the file intact so the next
            // unlock retries. Deleting here would silently and irrecoverably
            // destroy the real vault.
            val SQLITE_NOTADB = 26
            if (isProvision && rc == SQLITE_NOTADB) {
                platformLogWarn("IosVaultDB", "open failed (not a database) at provision — recreating")
                // Include -journal: a stale rollback journal
                // left by a prior aborted open could otherwise survive the recreate.
                // Same path (iosVaultDbPath) and same suffix list as this call.
                iosDeleteVaultFiles()
                val rc2 = bridge.open(dbPath, keyMaterial)
                if (rc2 != 0) {
                    keyMaterial.secureWipe()
                    error("DB open failed after recreate (rc=$rc2)")
                }
            } else {
                keyMaterial.secureWipe()
                error("DB open failed (rc=$rc); not deleting (provision=$isProvision) to preserve the vault")
            }
        }
        keyMaterial.secureWipe()

        // Prove the linked library is actually SQLCipher
        // before we trust `PRAGMA key` to have encrypted anything. On SQLCipher
        // `PRAGMA cipher_version` returns the version string; on a vanilla-SQLite
        // build it is an unknown pragma and returns NO rows — in which case the
        // earlier keying was a silent no-op and this "vault" is PLAINTEXT on disk.
        // Fail closed on either the provision or unlock path (VaultSelector maps
        // the throw to the neutral UnlockResult.Error — retryable, never a wipe);
        // we throw BEFORE createTables()/seeding so no secret is ever written to a
        // plaintext file. This is a build-integrity guard (it can only fail if the
        // wrong SQLite is linked), so it costs one query and can never
        // false-positive on a correctly-built app.
        val cipherVersion = queryRows("PRAGMA cipher_version")
            .firstOrNull()?.values?.firstOrNull() as? String
        if (cipherVersion.isNullOrBlank()) {
            error("SQLCipher not active (PRAGMA cipher_version empty) — refusing to use a plaintext database")
        }

        // Overwrite freed pages on delete/update instead of just marking them
        // free (VACUUM alone doesn't zero residual ciphertext). Set on the
        // open connection before any write, so deleted rows' on-disk bytes are
        // zeroed eagerly. Crypto-erase on wipe remains the primary control; this
        // is defense-in-depth for ordinary (non-wipe) deletes.
        exec("PRAGMA secure_delete = ON")

        // RUN-02: prove the connection is on the rollback journal the bridge asked
        // for (SwiftDatabaseBridge.open — see the rationale there) BEFORE the first
        // write of this session. The bridge's switch is unchecked by design; this is
        // the read-back. Leaving WAL is also what checkpoints + unlinks a -wal that a
        // pre-RUN-02 build or an unclean exit left on disk, so on success no older
        // committed view survives this open. A refused switch (SQLITE_BUSY: another
        // connection holds the file) never fails the open — it empties the WAL as far
        // as it can, verified, and arms the retry at every later write boundary.
        enforceRollbackJournal()
        iosPrecreateProtectedJournal(dbPath)

        // Protect the DB file and its journal sidecars at rest with
        // NSFileProtectionComplete (inaccessible whenever the device is locked)
        // as early as possible — immediately after open, before any schema or
        // seeding writes. The main file exists now; the -journal (RUN-02: pre-created
        // just above when absent; SQLite's own on first write otherwise) is covered
        // here or by the re-application after createTables()/seeding below — as are
        // a WAL-fallback's -wal/-shm. Background DB access no longer exists (no
        // background reader remains), so Complete (vs the weaker default
        // CompleteUntilFirstUserAuthentication, which stays readable while the
        // device is locked) cannot break a background read.
        protectDbFiles(dbPath)

        createTables()

        // Historical `_meta('seeded','1')` marker. It once provided schema parity
        // with the (now-removed) decoy vault; it is retained as an inert,
        // already-present row so existing vaults are not forced through a schema
        // diff. The app never reads it.
        exec("INSERT OR IGNORE INTO _meta (key, value) VALUES ('seeded', '1')")

        // Re-apply protection now that createTables() has materialised the
        // journal sidecar (and the pages it held during those writes) — or, in the
        // WAL-fallback case, the -wal/-shm.
        protectDbFiles(dbPath)
    }

    // -----------------------------------------------------------------------
    // RUN-02 — no superseded vault state may stay recoverable from the journal.
    //
    // The Double Ratchet state (root key, DH private key, chain keys, skipped
    // message keys) is ONE `_meta` row replaced on every step. Under WAL every
    // replaced version sat in run.db-wal until a checkpoint reset the log (never
    // forced), so db + wal imaged together, plus the current db key, rebuilt an
    // earlier committed view and an old chain key — undoing forward secrecy for
    // recorded ciphertext. The bridge now opens in rollback-journal TRUNCATE mode,
    // whose sidecar only ever holds the pre-images of the transaction in flight
    // (= the last COMMITTED state, never an older one) and is emptied at commit.
    //
    // This class only VERIFIES that and retries when it is not true. Boundaries:
    // init (after the open, before any write), after every top-level write that
    // persists `_meta` (putMeta / deleteMeta, outside a transaction), after the
    // outermost withTransaction, after a re-key, and before close. Steady state
    // (proven at init) costs one Boolean read per boundary — nothing is issued.
    //
    // Honest limit: truncation/unlink is not physical erasure on flash, and nothing
    // here can revoke an image an attacker already holds.
    // -----------------------------------------------------------------------

    /**
     * Ask for the rollback journal and READ BACK the answer. `truncate`/`delete` are
     * proof (both empty the sidecar at commit); anything else — `wal` because the
     * switch out of WAL needs the file to itself and got SQLITE_BUSY, an empty row
     * set, a throw — is not. While unproven, also run a TRUNCATE checkpoint and
     * verify it (busy == 0 and an emptied log) so the superseded frames leave the
     * WAL now rather than at the next successful switch; a busy / partial checkpoint
     * is NOT treated as done — the flag stays armed and the next boundary retries
     * both. Never throws, never fails an open (brick safety: a vault that opened is
     * a vault that opened). Runs through [bridge]'s `query` (PRAGMAs that return a
     * row), never `execute`.
     *
     * [blocking] = false (every write boundary) runs the attempt with the
     * connection's busy timeout at 0 and restores it afterwards: a retry that cannot
     * get the file must cost a failed PRAGMA, not the bridge's 2.5 s busy wait (twice)
     * under [lock] on every ratchet write. Only the open-time attempt waits.
     */
    private fun enforceRollbackJournal(blocking: Boolean = true) {
        if (blocking) { enforceRollbackJournalAttempt(); return }
        val savedTimeoutMs = try {
            (queryRows("PRAGMA busy_timeout").firstOrNull()?.values?.firstOrNull() as? NSNumber)?.longLongValue
        } catch (_: Throwable) { null }
        try { queryRows("PRAGMA busy_timeout = 0") } catch (_: Throwable) { }
        try {
            enforceRollbackJournalAttempt()
        } finally {
            // Restore what the bridge set (unreadable ⇒ the bridge's own value).
            val restore = savedTimeoutMs?.takeIf { it in 0L..60_000L } ?: BRIDGE_BUSY_TIMEOUT_MS
            try { queryRows("PRAGMA busy_timeout = $restore") } catch (_: Throwable) { }
        }
    }

    private fun enforceRollbackJournalAttempt() {
        val mode = try {
            (queryRows("PRAGMA journal_mode = TRUNCATE").firstOrNull()?.values?.firstOrNull() as? String)
                ?.lowercase()
        } catch (_: Throwable) { null }
        if (mode == "truncate" || mode == "delete") {
            if (rollbackJournalUnproven) platformLog("IosVaultDB", "rollback journal now in effect")
            rollbackJournalUnproven = false
            rollbackJournalWarned = false
            return
        }
        rollbackJournalUnproven = true
        val walEmptied = walCheckpointTruncateProven()
        if (!rollbackJournalWarned) {
            rollbackJournalWarned = true
            // Fixed vocabulary only: SQLite's own mode word (or "unknown"), a boolean.
            val shown = if (mode != null && mode in KNOWN_JOURNAL_MODES) mode else "unknown"
            platformLogWarn(
                "IosVaultDB",
                "rollback journal not in effect (mode=$shown, wal emptied=$walEmptied) - retrying at write boundaries",
            )
        }
    }

    /**
     * `PRAGMA wal_checkpoint(TRUNCATE)` with its result row checked: proven only
     * when `busy == 0` and `log == 0` (the log was reset AND truncated). A
     * `busy == 1`, a non-zero `log` (frames still in the file), a missing row or a
     * throw all answer false. Not in WAL mode at all (`log == -1`) answers true —
     * there is no WAL to hold anything.
     */
    private fun walCheckpointTruncateProven(): Boolean = try {
        val row = queryRows("PRAGMA wal_checkpoint(TRUNCATE)").firstOrNull()
        val busy = (row?.get("busy") as? NSNumber)?.longLongValue
        val log = (row?.get("log") as? NSNumber)?.longLongValue
        busy == 0L && (log == 0L || log == -1L)
    } catch (_: Throwable) { false }

    /**
     * A write boundary: retry [enforceRollbackJournal] while it is unproven and no
     * transaction is open (the switch is refused inside one; the outermost
     * withTransaction calls this after its COMMIT/ROLLBACK). A no-op in the steady
     * state. Caller holds [lock].
     */
    private fun afterWriteBoundary() {
        if (rollbackJournalUnproven && txnDepth == 0) enforceRollbackJournal(blocking = false)
    }

    /**
     * Set NSFileProtectionComplete on the DB file and its WAL/SHM
     * sidecars so their contents are inaccessible whenever the device is
     * locked. setAttributes on a not-yet-created sidecar is a harmless no-op
     * (error ignored), so this is safe to call both immediately after open
     * (protects the main file ASAP) and again after the first writes have
     * created the sidecars.
     *
     * The same files are ALSO excluded from
     * iCloud/iTunes backups. Application Support is backed up by default (unlike
     * Caches), so without this the encrypted DB + metadata would leave the device
     * in backups and survive an on-device wipe — contradicting Android's
     * allowBackup=false. The SQLCipher key is device-only
     * (WhenPasscodeSetThisDeviceOnly), so a restored copy is undecryptable
     * regardless; this stops the ciphertext leaving the device at all.
     *
     * Body extracted to the top-level [iosProtectVaultDbFiles] so [iosProbeVaultKey]
     * — which opens a bridge handle WITHOUT constructing this class — re-applies the
     * identical set. Its open can roll back a hot journal or (on a not-yet-converted
     * pre-RUN-02 vault) touch a `-wal`/`-shm`, outside this guard otherwise.
     */
    private fun protectDbFiles(dbPath: String) = iosProtectVaultDbFiles(dbPath)

    private fun createTables() {
        exec("CREATE TABLE IF NOT EXISTS contacts (contact_id TEXT PRIMARY KEY, shared_secret TEXT NOT NULL, trust_level INTEGER NOT NULL DEFAULT 0, alias TEXT NOT NULL DEFAULT '', alias_last_rotated INTEGER NOT NULL DEFAULT 0, mnemonic TEXT NOT NULL DEFAULT '', outbound_counter INTEGER NOT NULL DEFAULT 0, inbound_counter INTEGER NOT NULL DEFAULT 0, inbound_epoch TEXT NOT NULL DEFAULT '', outbound_ctl_counter INTEGER NOT NULL DEFAULT 0, inbound_ctl_counter INTEGER NOT NULL DEFAULT 0, vouched_by_contact_id TEXT, vouched_at INTEGER NOT NULL DEFAULT 0, outbound_grp_counter INTEGER NOT NULL DEFAULT 0, inbound_grp_counter INTEGER NOT NULL DEFAULT 0)")
        exec("CREATE TABLE IF NOT EXISTS inbox_ids (inbox_id TEXT PRIMARY KEY, contact_id TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, direction TEXT NOT NULL, cap TEXT)")
        // NO message table (v9, 2026-09-15) — messages are never written to disk.
        // The line that used to stand here CREATEd one; it is now the DROP that
        // erases what pre-2026-05-24 builds put in it. See [dropLegacyMessagesTable].
        dropLegacyMessagesTable()
        // v6 — group chat (client-side only). "contact_groups" not "groups":
        // GROUPS is an SQLite keyword (window functions). Created unconditionally
        // here, like the rest.
        exec("CREATE TABLE IF NOT EXISTS contact_groups (group_id TEXT PRIMARY KEY, name TEXT NOT NULL, epoch INTEGER NOT NULL DEFAULT 1, admin_member_id TEXT NOT NULL, my_member_id TEXT NOT NULL, created_at INTEGER NOT NULL)")
        exec("CREATE TABLE IF NOT EXISTS group_members (group_id TEXT NOT NULL, member_id TEXT NOT NULL, contact_id TEXT, added_at INTEGER NOT NULL, tags TEXT NOT NULL DEFAULT '', PRIMARY KEY (group_id, member_id))")
        exec("CREATE TABLE IF NOT EXISTS _meta (key TEXT PRIMARY KEY, value TEXT)")
        migrateContactsSchema()
    }

    /**
     * v9 (2026-09-15) — destroy the legacy per-message table.
     *
     * Nothing has inserted into `messages` since a933616e (2026-05-24): the app keeps
     * conversations in RAM, which is what the store listing claims. That commit removed
     * the WRITER only, so a vault provisioned by an older build and never wiped still
     * holds every message it ever received, encrypted under a key one compelled PIN
     * recovers. This is where that residue leaves the file.
     *
     * iOS has no `user_version` counter — the schema is idempotent-create — so the DROP
     * IS the migration and is a no-op on a fresh vault. The `sqlite_master` probe is
     * what makes it one: it decides whether this vault ever HAD the table, and hence
     * whether the VACUUM is worth its whole-file rewrite (a fresh or already-migrated
     * vault pays nothing). The reclaim matters because `PRAGMA secure_delete` zeroes
     * pages at FREE time while VACUUM is what returns them to the OS; it runs here,
     * outside any transaction (SQLite forbids VACUUM inside one, and `createTables` is
     * called from `init`, never from `withTransaction`), and before `init`'s second
     * `protectDbFiles`, which re-protects the sidecars the rewrite materialises.
     *
     * BRICK SAFETY: nothing in here may fail an open. Every step is wrapped — a vault
     * that opened is a vault that opened. If the DROP itself did not land, the probe
     * simply finds the table again on the next open and retries; that self-healing is
     * the payoff of having no version counter.
     */
    private fun dropLegacyMessagesTable() {
        try {
            val present = queryRows(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'messages'"
            ).isNotEmpty()
            if (!present) return
            exec("DROP TABLE IF EXISTS messages")
            exec("VACUUM")
        } catch (_: Throwable) {
            // Best-effort residue cleanup; never a reason to refuse the vault.
        }
    }

    /**
     * Additive anti-replay migration. iOS has no schema-version
     * system — for an install created before these columns the
     * CREATE TABLE IF NOT EXISTS above is a no-op, so add the columns
     * explicitly. Each ALTER is idempotent: on a fresh install (columns
     * already in the CREATE) it errors with "duplicate column" which is
     * expected and ignored; on an upgrade it adds the column. Existing
     * contacts are preserved (requirement 2026-05-17).
     */
    private fun migrateContactsSchema() {
        for (col in listOf(
            "outbound_counter INTEGER NOT NULL DEFAULT 0",
            "inbound_counter INTEGER NOT NULL DEFAULT 0",
            "inbound_epoch TEXT NOT NULL DEFAULT ''",
            // v7 — control-channel counter space.
            "outbound_ctl_counter INTEGER NOT NULL DEFAULT 0",
            "inbound_ctl_counter INTEGER NOT NULL DEFAULT 0",
            // v8 — referral/vouching provenance (referral.md).
            "vouched_by_contact_id TEXT",
            "vouched_at INTEGER NOT NULL DEFAULT 0",
            // v10 — the GROUP-text channel's counter space (the third pairwise
            // inbox pair, MessageManager.Chan.GRP). Same idempotent ALTER: on a
            // vault created by a build that already has them in the CREATE above
            // it raises "duplicate column" and is ignored; on an older vault it
            // adds them with DEFAULT 0, which is the establish-on-read baseline.
            // Existing contacts are preserved — nothing is dropped or rewritten.
            "outbound_grp_counter INTEGER NOT NULL DEFAULT 0",
            "inbound_grp_counter INTEGER NOT NULL DEFAULT 0",
        )) {
            try { exec("ALTER TABLE contacts ADD COLUMN $col") } catch (_: Throwable) { /* already present */ }
        }
        // v4 → v5: relay capability protocol. Same idempotent ALTER pattern
        // — fresh installs already have `cap` from the CREATE; upgrades add
        // it with NULL on legacy rows so the migration UX can flag them.
        try { exec("ALTER TABLE inbox_ids ADD COLUMN cap TEXT") } catch (_: Throwable) { /* already present */ }
    }

    // -- Helpers to convert params to NSArray and results from NSArray --

    private fun exec(sql: String, vararg params: Any?) {
        bridge.execute(sql, params.toNSArray())
    }

    /**
     * Like [exec] but THROWS if the underlying write did not succeed. Used for
     * the anti-replay-critical persists (insertContact) so MessageManager's
     * fail-closed guards — the inbound-baseline persist and the outbound
     * counter bump — actually trigger on iOS. The Swift bridge previously
     * discarded sqlite3_step's result and reported success unconditionally,
     * making those guards unreachable on iOS.
     */
    private fun execChecked(sql: String, vararg params: Any?) {
        if (!bridge.execute(sql, params.toNSArray())) {
            // SQL omitted from the message — it may carry contact data.
            throw RuntimeException("vault write failed")
        }
    }

    private fun queryRows(sql: String, vararg params: Any?): List<Map<String, Any?>> {
        val result = bridge.query(sql, params.toNSArray())
        val list = mutableListOf<Map<String, Any?>>()
        for (i in 0 until result.count.toInt()) {
            val dict = result.objectAtIndex(i.convert()) as? NSDictionary ?: continue
            val map = mutableMapOf<String, Any?>()
            for (key in dict.allKeys) {
                val k = key as? String ?: continue
                map[k] = dict.objectForKey(k)
            }
            list.add(map)
        }
        return list
    }

    private fun Array<out Any?>.toNSArray(): NSArray {
        val arr = NSMutableArray()
        for (v in this) {
            when (v) {
                null   -> arr.addObject(NSNull())
                is String -> arr.addObject(v as NSString)
                is Int    -> arr.addObject(NSNumber.numberWithInt(v))
                is Long   -> arr.addObject(NSNumber.numberWithLongLong(v))
                is Boolean -> arr.addObject(NSNumber.numberWithBool(v))
                else      -> arr.addObject(v.toString() as NSString)
            }
        }
        return arr
    }

    // -----------------------------------------------------------------------
    // VaultDatabase — generic key/value (`_meta`), backs the Double Ratchet
    // store + its enablement/bootstrap markers (see VaultDatabase).
    // -----------------------------------------------------------------------

    override fun getMeta(key: String): String? {
        lock.lock()
        return try {
            queryRows("SELECT value FROM _meta WHERE key = ?", key)
                .firstOrNull()?.get("value") as? String
        } finally { lock.unlock() }
    }

    override fun putMeta(key: String, value: String) {
        lock.lock()
        try {
            // execChecked: a lost ratchet-state persist must THROW (fail-closed).
            execChecked("INSERT OR REPLACE INTO _meta (key, value) VALUES (?, ?)", key, value)
            // RUN-02 boundary: this is the ratchet-secret write. No-op once proven.
            afterWriteBoundary()
        } finally { lock.unlock() }
    }

    override fun deleteMeta(key: String) {
        lock.lock()
        // execChecked (Android parity: SQLiteDatabase.delete throws): every caller is
        // already a swallowing best-effort helper or sits inside a try / withTransaction,
        // so a failed DELETE now rolls a transaction back instead of committing around it.
        try {
            execChecked("DELETE FROM _meta WHERE key = ?", key)
            afterWriteBoundary()   // RUN-02 boundary (no-op once proven)
        } finally { lock.unlock() }
    }

    /**
     * Snapshot of every `_meta` KEY, so deleteGroup/deleteContact can classify
     * residue with the shared [isGroupMetaResidueForGroup] /
     * [isGroupMetaResidueForContact] / [isReferralMetaResidueForContact] /
     * [isScreenshotNoticeResidueForContact] predicates and delete the matches. No
     * lock of its own — callers already hold the (reentrant)
     * lock inside withTransaction, and the [NSRecursiveLock] makes the standalone
     * `VaultDatabase` call safe too. On the interface since `ReferralManager` scans the
     * `ref_*` namespace from commonMain.
     */
    override fun metaKeys(): List<String> {
        lock.lock()
        return try {
            queryRows("SELECT key FROM _meta").mapNotNull { it["key"] as? String }
        } finally { lock.unlock() }
    }

    // Atomic multi-row write: sqlite BEGIN/COMMIT, ROLLBACK on any throw.
    // Holds the (reentrant) lock across the whole transaction so no other thread can
    // interleave a write onto the shared connection between BEGIN and COMMIT.
    override fun withTransaction(block: () -> Unit) {
        lock.lock()
        txnDepth++
        try {
            execChecked("BEGIN")
            try {
                block()
                execChecked("COMMIT")
            } catch (e: Throwable) {
                try { exec("ROLLBACK") } catch (_: Throwable) {}
                throw e
            }
        } finally {
            txnDepth--
            // RUN-02 boundary, AFTER the COMMIT/ROLLBACK (a journal-mode switch is
            // refused inside a transaction). Never throws, so it cannot mask the
            // block's own exception. No-op once proven.
            afterWriteBoundary()
            lock.unlock()
        }
    }

    // -----------------------------------------------------------------------
    // VaultDatabase — contacts
    // -----------------------------------------------------------------------

    override fun insertContact(contact: ContactRecord): Long {
        lock.lock()
        try {
            // execChecked: a failed persist must THROW so MessageManager's
            // fail-closed replay guards fire — not silently
            // report success like the old swallowing bridge.
            execChecked("INSERT OR REPLACE INTO contacts (contact_id, shared_secret, trust_level, alias, alias_last_rotated, mnemonic, outbound_counter, inbound_counter, inbound_epoch, outbound_ctl_counter, inbound_ctl_counter, vouched_by_contact_id, vouched_at, outbound_grp_counter, inbound_grp_counter) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                contact.contactId, encodeBase64(contact.sharedSecret), contact.trustLevel,
                contact.alias, contact.aliasLastRotated, contact.mnemonic,
                contact.outboundCounter, contact.inboundCounter, contact.inboundEpoch,
                contact.outboundCtlCounter, contact.inboundCtlCounter,
                contact.vouchedByContactId, contact.vouchedAt,
                contact.outboundGrpCounter, contact.inboundGrpCounter)
        } finally { lock.unlock() }
        return 1L
    }

    override fun getContact(contactId: String): ContactRecord? {
        lock.lock()
        return try {
            queryRows("SELECT * FROM contacts WHERE contact_id = ?", contactId)
                .firstOrNull()?.toContact()
        } finally { lock.unlock() }
    }

    override fun getAllContacts(): List<ContactRecord> {
        lock.lock()
        return try {
            queryRows("SELECT * FROM contacts ORDER BY alias").mapNotNull { it.toContact() }
        } finally { lock.unlock() }
    }

    override fun deleteContact(contactId: String) {
        // All deletes in ONE transaction so a crash mid-delete can't leave a
        // torn vault (the inbox rows gone but the contact row + its live sharedSecret
        // still present, or orphaned ratchet _meta keys). withTransaction holds the
        // reentrant lock across BEGIN..COMMIT and ROLLBACKs on any throw (replaces the
        // plain lock). No message delete: v9 removed the table — messages are RAM-only.
        //
        // execChecked on EVERY statement (P-4, Android parity): a statement the bridge
        // reports as failed now THROWS, so withTransaction ROLLS BACK the whole delete
        // and rethrows — exactly what Android's db.delete/db.update do. Before, `exec`
        // discarded the result and a failed DELETE still COMMITTED the rest: e.g. the
        // contact row gone but its ratchet `_meta` keys left behind, reported as a
        // successful delete. The success path is byte-identical (same statements, same
        // order, same bridge call). Every column used here (contact_id on contacts /
        // inbox_ids / group_members, key on _meta) is in its table's base CREATE since
        // the table was introduced, so no older schema makes a statement fail.
        // Callers already handle the throw (deleteContactAndPurgeRelay → false).
        withTransaction {
            execChecked("DELETE FROM contacts WHERE contact_id = ?", contactId)
            execChecked("DELETE FROM inbox_ids WHERE contact_id = ?", contactId)
            // Erase the contact's ratchet/session state in _meta too
            // (the row deletes above don't touch it). exec directly rather than via
            // deleteMeta — keeps all deletes on this path.
            for (key in ratchetMetaKeysForContact(contactId)) {
                execChecked("DELETE FROM _meta WHERE key = ?", key)
            }
            // Also purge contact-scoped GROUP residue in
            // _meta — grp_inv_rl:<contactId> and every grp_roster_rl:<groupId>:<contactId>.
            // Same shared classifier as Android, so both platforms purge the identical set.
            //
            // REFERRAL (same rule, value-keyed): a persisted referral handshake record is
            // keyed by introId and names the contact in its BODY, so the value is read —
            // only for keys already in the `ref_*` namespace. Leaving one behind would
            // strand an ephemeral X25519 private key + a live inbox capability for a
            // contact the user just deleted. Mirrors DatabaseManager.deleteContact
            // statement-for-statement.
            //
            // SCREENSHOT NOTICES (key-scoped, both id positions): the deleted
            // contact's own 1:1 notices AND the ones they left in groups the user is
            // still in. Mirrors DatabaseManager.deleteContact statement-for-statement.
            //
            // PARKED INVITES (key-scoped, inviter position): `grp_pinv:<group>:<contactId>`
            // is the durable copy of an invite from THIS contact that the user never
            // answered (GroupInviteStore). Mirrors DatabaseManager.deleteContact
            // statement-for-statement.
            for (key in metaKeys()) {
                if (isGroupMetaResidueForContact(key, contactId)) {
                    execChecked("DELETE FROM _meta WHERE key = ?", key)
                    continue
                }
                if (isScreenshotNoticeResidueForContact(key, contactId)) {
                    execChecked("DELETE FROM _meta WHERE key = ?", key)
                    continue
                }
                if (isGroupInviteResidueForContact(key, contactId)) {
                    execChecked("DELETE FROM _meta WHERE key = ?", key)
                    continue
                }
                if (isReferralMetaKey(key) &&
                    isReferralMetaResidueForContact(key, getMeta(key), contactId)
                ) {
                    execChecked("DELETE FROM _meta WHERE key = ?", key)
                }
            }
            // Group members referencing the contact become unresolved — the
            // membership itself is the group admin's to change, not ours.
            execChecked("UPDATE group_members SET contact_id = NULL WHERE contact_id = ?", contactId)
        }
    }

    // -----------------------------------------------------------------------
    // VaultDatabase — inbox IDs
    // -----------------------------------------------------------------------

    override fun insertInboxId(record: InboxIdRecord): Long {
        lock.lock()
        try {
            // execChecked: surface a failed inbox/cap persist (fail-closed) so a
            // silently-lost row can't break send/poll or anti-replay.
            execChecked("INSERT OR REPLACE INTO inbox_ids (inbox_id, contact_id, created_at, expires_at, direction, cap) VALUES (?, ?, ?, ?, ?, ?)",
                record.inboxId, record.contactId, record.createdAt, record.expiresAt, record.direction, record.cap)
        } finally { lock.unlock() }
        return 1L
    }

    override fun getInboxId(inboxId: String): InboxIdRecord? {
        lock.lock()
        return try {
            queryRows("SELECT * FROM inbox_ids WHERE inbox_id = ?", inboxId)
                .firstOrNull()?.toInboxId()
        } finally { lock.unlock() }
    }

    /**
     * The `expires_at > ?` predicate this query used to carry is GONE — the
     * client's absolute 365-day stamp expired healthy, actively-polled inboxes that
     * the relay (whose TTL slides on activity) still held, silently killing send,
     * poll, peek and push for that contact. The choice now lives in the shared
     * [selectOperationalInbox], which Android calls too so the policy cannot drift;
     * see its kdoc. [getInboxId] stays unfiltered as it always was.
     */
    override fun getInboxIdForContact(contactId: String, direction: String): InboxIdRecord? {
        lock.lock()
        return try {
            selectOperationalInbox(
                queryRows(
                    "SELECT * FROM inbox_ids WHERE contact_id = ? AND direction = ? " +
                        "ORDER BY created_at DESC LIMIT $INBOX_LOOKUP_CANDIDATE_CAP",
                    contactId, direction,
                ).mapNotNull { it.toInboxId() }
            )
        } finally { lock.unlock() }
    }

    /**
     * Every inbox row, unfiltered — see [VaultDatabase.getAllInboxIds]. Unlike
     * [getInboxIdForContact] this includes superseded rows a peer's re-announce
     * left behind, which a device-move export needs.
     */
    override fun getAllInboxIds(): List<InboxIdRecord> {
        lock.lock()
        return try {
            queryRows("SELECT * FROM inbox_ids").mapNotNull { it.toInboxId() }
        } finally { lock.unlock() }
    }

    /**
     * Forward-only re-stamp of one row's informational `expires_at` (see
     * [VaultDatabase.touchInboxExpiry]). `exec`, not `execChecked`: this is
     * best-effort hygiene and must never throw into a poll/send path (the interface
     * contract; DatabaseManager swallows its throw for the same reason). The
     * `expires_at < ?` predicate makes "never lower it" an SQL-level property, and
     * a missing row simply matches nothing (no resurrection).
     */
    override fun touchInboxExpiry(inboxId: String, expiresAt: Long) {
        lock.lock()
        try {
            exec(
                "UPDATE inbox_ids SET expires_at = ? WHERE inbox_id = ? AND expires_at < ?",
                expiresAt, inboxId, expiresAt,
            )
        } finally { lock.unlock() }
    }

    // -----------------------------------------------------------------------
    // VaultDatabase — groups (v6)
    // -----------------------------------------------------------------------

    override fun insertGroup(group: GroupRecord): Long {
        lock.lock()
        try {
            // execChecked: a silently-lost epoch update would break roster
            // gating (stale rosters re-accepted) — fail closed like contacts.
            execChecked("INSERT OR REPLACE INTO contact_groups (group_id, name, epoch, admin_member_id, my_member_id, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                group.groupId, group.name, group.epoch, group.adminMemberId, group.myMemberId, group.createdAt)
        } finally { lock.unlock() }
        return 1L
    }

    override fun getGroup(groupId: String): GroupRecord? {
        lock.lock()
        return try {
            queryRows("SELECT * FROM contact_groups WHERE group_id = ?", groupId)
                .firstOrNull()?.toGroup()
        } finally { lock.unlock() }
    }

    override fun getAllGroups(): List<GroupRecord> {
        lock.lock()
        return try {
            queryRows("SELECT * FROM contact_groups ORDER BY name").mapNotNull { it.toGroup() }
        } finally { lock.unlock() }
    }

    override fun deleteGroup(groupId: String) {
        // Both deletes in ONE
        // transaction — a crash between them must not leave orphan group_members
        // (memberIds, pairwise HMAC tags, contactId links) as a forensic residual of
        // group membership after a "delete". withTransaction holds the reentrant lock
        // across BEGIN..COMMIT and ROLLBACKs on any throw. execChecked on every
        // statement for the same reason, and with the same schema argument, as
        // deleteContact (P-4); GroupManager's callers already catch the throw.
        withTransaction {
            execChecked("DELETE FROM group_members WHERE group_id = ?", groupId)
            execChecked("DELETE FROM contact_groups WHERE group_id = ?", groupId)
            // Purge group-scoped _meta residue (the admin-side
            // roster throttle grp_roster_rl:<groupId>:<contactId>) — the row deletes above
            // don't touch _meta, leaving a per-member record of a "deleted" group. Same
            // shared classifier as Android; group_admin:<groupId> is deliberately retained
            // (anti-eclipse tombstone) and the classifier excludes it.
            //
            // SCREENSHOT NOTICES (same rule, same loop): `ssn:<groupId>:<sender>:<ms>`
            // rows name exactly who screenshotted this group and when. Same shared
            // predicate as Android, so both platforms purge the identical set.
            //
            // PARKED INVITES (same rule, same loop): `grp_pinv:<groupId>:<inviter>` —
            // the durable copy of an un-answered invite (GroupInviteStore). This is
            // also the clause that drops a parked invite when the user LEAVES or is
            // removed from the group, since every such path reaches deleteGroup.
            // Mirrors DatabaseManager.deleteGroup statement-for-statement.
            for (key in metaKeys()) {
                if (isGroupMetaResidueForGroup(key, groupId) ||
                    isScreenshotNoticeResidueForGroup(key, groupId) ||
                    isGroupInviteResidueForGroup(key, groupId)
                ) {
                    execChecked("DELETE FROM _meta WHERE key = ?", key)
                }
            }
        }
    }

    override fun insertGroupMember(member: GroupMemberRecord): Long {
        lock.lock()
        try {
            execChecked("INSERT OR REPLACE INTO group_members (group_id, member_id, contact_id, added_at, tags) VALUES (?, ?, ?, ?, ?)",
                member.groupId, member.memberId, member.contactId, member.addedAt, member.tags)
        } finally { lock.unlock() }
        return 1L
    }

    override fun getGroupMembers(groupId: String): List<GroupMemberRecord> {
        lock.lock()
        return try {
            queryRows("SELECT * FROM group_members WHERE group_id = ? ORDER BY added_at", groupId)
                .mapNotNull { it.toGroupMember() }
        } finally { lock.unlock() }
    }

    override fun deleteGroupMember(groupId: String, memberId: String) {
        lock.lock()
        try {
            // execChecked (Android parity): all three callers (GroupManager removeMember,
            // roster apply, leave apply) run it inside withTransaction + try, so a failed
            // DELETE rolls back the paired epoch bump instead of committing it alone.
            execChecked("DELETE FROM group_members WHERE group_id = ? AND member_id = ?", groupId, memberId)
        } finally { lock.unlock() }
    }

    override fun wipeAllTables() {
        // The row-clears are ONE transaction so a torn wipe can't leave
        // some tables cleared and others intact. Deliberately plain `exec`, NOT
        // execChecked (unlike deleteContact/deleteGroup): the only caller is
        // emergencyWipe, AFTER the device key is already erased, as row hygiene before
        // the file unlink. A checked failure would ROLL BACK every clear, i.e. scrub
        // NOTHING; unchecked, a failing statement still lets the others commit, which
        // is strictly more scrubbing on the failure path. VACUUM must run OUTSIDE a transaction
        // (SQLite forbids it inside), so it follows the commit under its own lock.
        withTransaction {
            exec("DELETE FROM contacts")
            exec("DELETE FROM inbox_ids")
            exec("DELETE FROM group_members")
            exec("DELETE FROM contact_groups")
            // _meta backs the Double Ratchet per-contact state — clear it so
            // wipeAllTables() matches its "every table" contract and a future
            // row-only wipe can't leave ratchet keys behind.
            exec("DELETE FROM _meta")
        }
        lock.lock()
        try {
            exec("VACUUM")  // Reclaim space, prevent forensic recovery of deleted rows
        } finally { lock.unlock() }
    }

    /**
     * Re-keys THIS live handle. See [VaultDatabase.rekey] for the return-value
     * warning — a `true` here is "no error we could see", never proof that the
     * file is on [newDbKey]; only [VaultFactory.probeKey] proves that.
     *
     * Runs under the same [NSRecursiveLock] every other statement takes: the
     * re-key rewrites every page inside its own write transaction, so a
     * concurrent write on this connection would either be rolled back with it or
     * land under a mixed key. And it deliberately re-keys the LIVE handle rather
     * than a second connection — a second connection re-keying behind this one
     * would leave this one's read context on the old key and fail every later
     * query.
     *
     * ENCODING is the Swift bridge's job and it must stay the OPEN path's
     * convention: the 67-byte `x'<64 hex>'` raw-key text form, built in a wipeable
     * `[CChar]` buffer. iOS's open keys through that form (SQLCipher's raw-key
     * branch, no PBKDF2), Android keys with raw bytes (PBKDF2 branch) — the two
     * derive different encryption keys from the same 32 bytes, so the platforms'
     * conventions must never be swapped or "unified".
     *
     * The transient copy is wiped on every exit path, as at open.
     *
     * Concurrency (parity, by design): Android does not quiesce — its in-flight
     * statement makes changePassword throw instead; the caller decides from probes.
     */
    override fun rekey(newDbKey: ByteArray): Boolean {
        lock.lock()
        return try {
            val keyMaterial = newDbKey.copyOf()
            try {
                bridge.rekey(keyMaterial) == 0
            } finally {
                keyMaterial.secureWipe()
                // RUN-02 boundary: in the WAL fallback a re-key would leave every
                // OLD-key page version in the log. No-op once proven (the rollback
                // journal is emptied by the re-key's own commit). Never throws and
                // never changes this method's return value.
                afterWriteBoundary()
            }
        } catch (_: Throwable) {
            false
        } finally {
            lock.unlock()
        }
    }

    private var closed = false
    override val isOpen: Boolean get() = !closed

    override fun close() {
        lock.lock()
        try {
            // RUN-02 boundary: one last switch / verified checkpoint attempt while the
            // handle still exists (sqlite3_close also checkpoints a WAL, but only when
            // it is the last connection and gets the lock). No-op once proven; never
            // throws, so the close below always runs.
            if (!closed) afterWriteBoundary()
            closed = true
            bridge.close()
        } finally { lock.unlock() }
    }

    // -----------------------------------------------------------------------
    // Row mapping
    //
    // Strictness (parity, by design): a row missing a key column is dropped (null)
    // and the rest default; DatabaseManager's Cursor mappers throw on a missing column.
    // -----------------------------------------------------------------------

    private fun Map<String, Any?>.toContact(): ContactRecord? {
        return ContactRecord(
            contactId = str("contact_id") ?: return null,
            sharedSecret = str("shared_secret")?.let { decodeBase64(it) } ?: return null,
            trustLevel = num("trust_level")?.toInt() ?: 0,
            alias = str("alias") ?: "",
            aliasLastRotated = num("alias_last_rotated") ?: 0L,
            mnemonic = str("mnemonic") ?: "",
            outboundCounter = num("outbound_counter") ?: 0L,
            inboundCounter = num("inbound_counter") ?: 0L,
            inboundEpoch = str("inbound_epoch") ?: "",
            outboundCtlCounter = num("outbound_ctl_counter") ?: 0L,
            inboundCtlCounter = num("inbound_ctl_counter") ?: 0L,
            // v10: absent on a row read before the ALTER landed (or from a legacy
            // fixture) ⇒ 0, the establish-on-read baseline. Never a failed read.
            outboundGrpCounter = num("outbound_grp_counter") ?: 0L,
            inboundGrpCounter = num("inbound_grp_counter") ?: 0L,
            vouchedByContactId = str("vouched_by_contact_id"),
            vouchedAt = num("vouched_at") ?: 0L,
        )
    }

    private fun Map<String, Any?>.toInboxId(): InboxIdRecord? {
        return InboxIdRecord(
            inboxId = str("inbox_id") ?: return null,
            contactId = str("contact_id") ?: return null,
            createdAt = num("created_at") ?: 0L,
            expiresAt = num("expires_at") ?: 0L,
            direction = str("direction") ?: "outbound",
            cap = str("cap"),
        )
    }

    private fun Map<String, Any?>.toGroup(): GroupRecord? {
        return GroupRecord(
            groupId       = str("group_id") ?: return null,
            name          = str("name") ?: "",
            epoch         = num("epoch") ?: 1L,
            adminMemberId = str("admin_member_id") ?: return null,
            myMemberId    = str("my_member_id") ?: return null,
            createdAt     = num("created_at") ?: 0L,
        )
    }

    private fun Map<String, Any?>.toGroupMember(): GroupMemberRecord? {
        return GroupMemberRecord(
            groupId   = str("group_id") ?: return null,
            memberId  = str("member_id") ?: return null,
            contactId = str("contact_id"),
            addedAt   = num("added_at") ?: 0L,
            tags      = str("tags") ?: "",
        )
    }

    private fun Map<String, Any?>.str(key: String): String? = this[key] as? String
    private fun Map<String, Any?>.num(key: String): Long? = (this[key] as? NSNumber)?.longLongValue
}

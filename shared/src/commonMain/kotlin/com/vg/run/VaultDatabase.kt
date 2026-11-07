package com.vg.run

// ---------------------------------------------------------------------------
// VaultDatabase — common interface for the encrypted vault.
//
// Implemented per platform (DatabaseManager on Android, IosVaultDatabase on
// iOS) so commonMain code can operate on the vault without referencing
// platform-specific SQLCipher classes.
// ---------------------------------------------------------------------------

/**
 * Minimum byte size for a run.db file to count as a real vault at unlock.
 * A valid SQLCipher database is always at least one page (salt + header, >= 4096
 * bytes); a present-but-empty/truncated file (0 bytes) otherwise passes a bare
 * fileExists check and SQLCipher opens it as a fresh empty DB, silently masking
 * data loss. Both platform open-guards (DatabaseManager / IosVaultDatabase) treat
 * a file below this size as "missing" and fail closed. 512 = one minimal SQLite
 * page — safely below any legitimate vault, so it never false-positives.
 */
const val MIN_VALID_VAULT_DB_BYTES: Long = 512L

/**
 * How many candidate rows [VaultDatabase.getInboxIdForContact] materialises
 * before [selectOperationalInbox] picks. Both actuals order by `created_at DESC`
 * and cap the fetch here, so the winner (the newest row) is always inside the
 * window while the mapping cost stays bounded — old rows for one (contact,
 * direction) accumulate whenever a peer announces a NEW inbox id (a distinct
 * primary key, so nothing replaces the previous row) and nothing prunes them.
 */
internal const val INBOX_LOOKUP_CANDIDATE_CAP = 8

/**
 * The SINGLE place the operational inbox lookup decides which row wins — both
 * `VaultDatabase` actuals and the commonTest in-memory double route
 * `getInboxIdForContact` through it, so Android, iOS and the tests cannot drift.
 *
 * Two rules, and the SECOND one is the fix:
 *
 *  - **Newest by `createdAt` wins.** A peer's in-band inbox announce inserts a row
 *    under a NEW primary key, leaving the superseded one behind, so the pick order
 *    is load-bearing routing, not a tie-break.
 *  - **`expiresAt` is NOT consulted.** Every row is stamped `createdAt + 365 d` at
 *    pairing and nothing ever refreshed it, while the RELAY's TTL SLIDES on every
 *    authenticated operation (see `MintedInbox.expiresAt`, which already calls the
 *    value informational). Enforcing the client's absolute stamp therefore stranded
 *    a perfectly healthy, actively-polled pairing on day 366: polling returned empty
 *    without ever contacting the relay, peek returned null, push registration
 *    dropped the inbox, sending refused — while the peer's sends kept getting 2xx
 *    and piling up undrained. Recovery meant a fresh pairing (new contactId, reset
 *    ratchet, orphaned history). The client cannot know an inbox's real lifetime;
 *    the relay is the authority, and the client already has an EVIDENCE-BASED
 *    detector for "the inbox is really gone" — the persistent-404 streak that flags
 *    the contact for re-pair (`MessageManager.noteRelay404`). This removes the
 *    second, always-wrong oracle; it does not remove the re-pair signal.
 *
 * Do not re-introduce a client-side expiry filter here or in either actual's SQL.
 * The column is retained (informational, and lazily re-stamped by
 * [VaultDatabase.touchInboxExpiry] once the relay has proven the inbox alive).
 *
 * NOTE: [VaultDatabase.getInboxId] — the PRIMARY-KEY lookup behind the inbox
 * ownership gate — was never expiry-filtered and must stay that way: an expired row
 * still occupies the primary key and would still be silently overwritten by an
 * INSERT-OR-REPLACE, so it must still block a claim (see `InboxOwnership`).
 */
internal fun selectOperationalInbox(candidates: List<InboxIdRecord>): InboxIdRecord? =
    candidates.maxByOrNull { it.createdAt }

/**
 * The vault's row store (SQLCipher on both platforms: Android `DatabaseManager`,
 * iOS IosVaultDatabase). The `insert*` return value is platform-specific — Android
 * the SQLite rowId, iOS a constant `1` — and no caller reads it.
 */
interface VaultDatabase {

    /**
     * Inserts or replaces a contact row. @Throws so a write failure is a
     * catchable error in Swift (do/catch) rather than an uncaught Kotlin
     * exception that SIGABRTs the iOS app — the anti-replay/capability integrity
     * depends on the caller seeing the failure.
     */
    @Throws(Throwable::class)
    fun insertContact(contact: ContactRecord): Long

    /** Returns the contact for [contactId], or null if not found. */
    fun getContact(contactId: String): ContactRecord?

    /** Returns all contacts ordered by alias ascending. */
    fun getAllContacts(): List<ContactRecord>

    /** Inserts or replaces an inbox ID record. @Throws for the same reason as
     *  [insertContact] — a silently-lost inbox/capability row breaks send/poll. */
    @Throws(Throwable::class)
    fun insertInboxId(record: InboxIdRecord): Long

    /** Returns the inbox ID record for [inboxId], or null. */
    fun getInboxId(inboxId: String): InboxIdRecord?

    /**
     * Returns the most recently created inbox for [contactId] matching the given
     * [direction] ("outbound" or "inbound").
     *
     * Security purpose: outbound inboxes are the relay address where we send
     * messages TO a contact. Inbound inboxes are where we poll FOR messages
     * from a contact. Separating them prevents send and poll from hitting the
     * same relay address, which would cause messages to be delivered back to
     * the sender.
     *
     * This is the OPERATIONAL lookup and it no longer filters on `expiresAt` —
     * both actuals delegate the choice to [selectOperationalInbox], which carries
     * the full rationale. Implementations must route through it rather than
     * re-expressing the rule in SQL.
     */
    fun getInboxIdForContact(contactId: String, direction: String): InboxIdRecord?

    /**
     * Returns EVERY inbox row across every contact and direction — unlike
     * [getInboxIdForContact] (which resolves to the single OPERATIONAL row per
     * (contact, direction) via [selectOperationalInbox]), this includes rows a
     * peer's inbox re-announce superseded and left behind ([INBOX_LOOKUP_CANDIDATE_CAP]
     * documents why those accumulate). Added for `VaultSnapshotIo`
     * (docs/device-move.md, "Move to new device") — a device-move export needs the
     * FULL inbox set for a contact, not just the currently-operational row.
     *
     * Default throws: every production [VaultDatabase] actual (Android, iOS) MUST
     * override this with a real query — see `DatabaseManager` / `IosVaultDatabase`.
     * The default exists only so a pre-existing `VaultDatabase` test double that
     * predates this method still compiles without being touched; it must never be
     * relied on silently (loud failure beats a silently-incomplete export).
     */
    fun getAllInboxIds(): List<InboxIdRecord> =
        throw NotImplementedError("getAllInboxIds() must be overridden by every VaultDatabase implementation")

    /**
     * Lazily re-stamps ONE inbox row's informational `expiresAt`, and only ever
     * FORWARD (`WHERE inbox_id = ? AND expires_at < ?`). Called after the relay has
     * PROVEN that inbox alive — a 2xx on that exact id with our own capability — so
     * the stored value becomes "last proven live + one lifetime" instead of a stale
     * absolute stamp from pairing day. Nothing gates on the column any more
     * ([selectOperationalInbox]); this exists so the stored value stops being a lie,
     * including on vaults already past their original stamp.
     *
     * Deliberately a SINGLE-COLUMN UPDATE keyed by the primary key, not a
     * read-modify-write through [insertInboxId]:
     *  - it cannot clobber a `cap` that a concurrent capability rotation just committed;
     *  - it cannot RESURRECT a row (or its contact) that was deleted meanwhile — a
     *    missing row simply matches nothing, per the non-resurrection rule.
     *
     * Best-effort hygiene: NOT `@Throws`, and callers must treat a failure as a
     * no-op. Never call it on a 404/429/unknown response — that would paper over a
     * genuinely reaped inbox.
     */
    fun touchInboxExpiry(inboxId: String, expiresAt: Long)

    // Messages are intentionally never persisted — they are kept in memory
    // only (sent on send, fetched on poll, gone on app exit), so this
    // interface exposes no message read/write methods and MUST NOT grow one.
    //
    // There is no message TABLE either, since schema v9 (2026-09-15). Both
    // actuals used to keep an empty one "so the schema stays stable"; nothing
    // had written to it since 2026-05-24, but a vault provisioned by an older
    // build still held real message rows, so the table is now DROPped on open
    // (Android: the v8 → v9 onUpgrade step + a VACUUM after the open; iOS: a
    // sqlite_master probe + DROP + VACUUM in createTables). Do not re-add it.

    // -----------------------------------------------------------------------
    // Groups — client-side only; the relay never learns groups exist. Group
    // MESSAGES are never persisted (same ephemeral model as 1:1); only the
    // group + membership records below are.
    // -----------------------------------------------------------------------

    /** Inserts or replaces a group row. @Throws for the same reason as
     *  [insertContact] — a silently-lost epoch update breaks roster gating. */
    @Throws(Throwable::class)
    fun insertGroup(group: GroupRecord): Long

    /** Returns the group for [groupId], or null. */
    fun getGroup(groupId: String): GroupRecord?

    /** Returns all groups ordered by name ascending. */
    fun getAllGroups(): List<GroupRecord>

    /** Deletes a group and all its member rows. */
    fun deleteGroup(groupId: String)

    /** Inserts or replaces a group member row (keyed by groupId + memberId). */
    @Throws(Throwable::class)
    fun insertGroupMember(member: GroupMemberRecord): Long

    /** Returns all member rows for [groupId]. */
    fun getGroupMembers(groupId: String): List<GroupMemberRecord>

    /** Deletes one member row. */
    fun deleteGroupMember(groupId: String, memberId: String)

    /** Deletes a contact and all associated inbox IDs and `_meta` residue. Group
     *  member rows referencing the contact become unresolved (contactId
     *  nulled), not deleted — the membership itself is the admin's to change. */
    fun deleteContact(contactId: String)

    /** Deletes every row from all tables. */
    fun wipeAllTables()

    /**
     * Re-encrypts the WHOLE vault under [newDbKey], in place, on THIS live
     * connection. Used by the credential-change flow's DB-key rotation
     * (`VaultSelector.rotateDbKeyAfterUpgrade`).
     *
     * **A `true` return is NOT proof that the file is now under [newDbKey].**
     * Both actuals bottom out in SQLCipher's `sqlite3_rekey_v2`, and that
     * function returns `SQLITE_OK` on BOTH of its terminal branches: the page
     * rewrite's / `sqlite3BtreeCommit`'s own result code is assigned to a local
     * `rc` and then DISCARDED, and the rollback branch falls through to the same
     * unconditional `return SQLITE_OK`. So a re-key whose rewrite or commit
     * failed — and whose file was therefore rolled back, still keyed with the
     * OLD key — reports success. Worse: `codec_set_pass_key(..., CIPHER_WRITE_CTX)`
     * installs the new key in the codec's WRITE context BEFORE the rewrite starts
     * and never undoes it, so after a rolled-back re-key the live handle encrypts
     * new pages under the new key onto a file that is still on the old one.
     *
     * Read `true` as "no error we could see", and nothing more. The caller MUST
     * prove the outcome independently with [VaultFactory.probeKey] before it
     * commits [newDbKey] anywhere durable, and must never treat `true` alone as a
     * licence to discard the old key.
     *
     * `false` means a visible error (Android: `changePassword` threw). It is the
     * cleaner failure — the old key almost certainly still opens the file — but
     * for the same write-context reason it is not a guarantee either. Re-prove
     * with [VaultFactory.probeKey] rather than assuming, and prefer closing and
     * re-opening the vault over continuing to write through a handle whose
     * re-key failed midway.
     *
     * Key ENCODING is per-platform and each actual MUST keep its own convention —
     * Android passes RAW BYTES (SQLCipher's PBKDF2 branch, salt from the file
     * header), iOS the 67-byte `x'<64 hex>'` raw-key TEXT form. The two derive
     * different encryption keys from the same 32 bytes, so "unifying" them
     * permanently orphans the vault file. Never do it.
     *
     * Android raw-key ADOPTION (2026-10-07) does not change this: since then an
     * Android vault is usually OPENED with `x'<K'>'`, where K' =
     * PBKDF2-HMAC-SHA512(dbKey, file salt, 256 000) is exactly the key the
     * passphrase branch derives — but a re-key's TARGET is still passphrase mode
     * (the raw 32 new bytes, stretched with the file's unchanged salt), whichever
     * mode the live handle was opened in. `VaultSelector` records the new key as a
     * PASSPHRASE payload accordingly and re-adopts it on the next unlock. Proven
     * from a raw-opened handle by androidTest `RawKeyAdoptionTest`.
     *
     * Implementations must not log, retain, or copy [newDbKey] beyond one
     * transient buffer that is wiped on every exit path, and must not throw —
     * every error is reported as `false`.
     */
    fun rekey(newDbKey: ByteArray): Boolean

    /**
     * False once [close] has run. Drains and probes that may still be in flight
     * during session teardown read it to stay quiet instead of warning about a
     * closed handle (2026-10-26). Defaults to true so test fakes need no change;
     * the two real databases override it.
     */
    val isOpen: Boolean get() = true

    /**
     * Closes the underlying database connection. Used after provisioning
     * (where the vault is opened only to materialize the encrypted file on
     * disk) so the SQLCipher connection is not leaked.
     */
    fun close()

    // -----------------------------------------------------------------------
    // Generic key/value (the `_meta` table). Small, app-internal state that
    // does not warrant its own table. Values are opaque strings; ratchet key
    // material is base64'd ciphertext-equivalent serialized state and lives only
    // inside the encrypted vault like every other column. NOT for arbitrary user
    // data. The namespaces, and the purge classifier each one is coupled to:
    //
    //   `dr*`, `cap-pend/…`, `m2-chseen/<id>`, `ib-bound-seen/<id>`, `grp-ann/<id>`
    //                        the Double Ratchet's per-(contact,channel) serialized
    //                        state, its enablement/bootstrap markers, the pending
    //                        read-cap rotation markers, the sticky "peer tags its
    //                        channel" / "peer binds the destination inbox" seen-markers
    //                        and the group-inbox backfill throttle (note the HYPHEN —
    //                        `grp_` below does not match it) — all purged through the
    //                        exact-key list [ratchetMetaKeysForContact].
    //   `grp_*`              group invite/roster throttles and pending membership
    //                        control ([GroupMetaKeys]: `grp_inv_rl:`, `grp_roster_rl:`,
    //                        `grp_ctl_pend:`) — [isGroupMetaResidueForGroup] / …ForContact.
    //   `grp_pinv:`          invites parked awaiting consent, one row per invite,
    //                        bounded and 7-day self-expiring (GroupInviteStore) —
    //                        [isGroupInviteResidueForGroup] / …ForContact. A
    //                        SEPARATE classifier from the `grp_*` throttles above:
    //                        its key carries BOTH a groupId and a contactId, so a
    //                        group delete (leave/removal) and a contact delete each
    //                        purge it from their own segment.
    //   `ref_*`              referral handshake records —
    //                        [isReferralMetaResidueForContact] (value-keyed).
    //   `ssn:`               received screenshot notices, one row per notice,
    //                        bounded and 24 h self-expiring (ScreenshotNoticeStore) —
    //                        [isScreenshotNoticeResidueForContact] / …ForGroup.
    //
    // DELIBERATELY NEVER PURGED by a contact/group delete (each outlives the row it
    // names, on purpose; the vault wipe still erases them):
    //
    //   `group_admin:<groupId>`  the anti-eclipse admin-of-record tombstone
    //                            (GroupManager.adminMetaKey) — the ONLY `group_`
    //                            prefix; in neither residue classifier, so a later
    //                            invite to that groupId from a different contact is
    //                            still flagged.
    //   `grp_declined`           the declined-invite tombstone singleton
    //                            (GroupManager.DECLINED_INVITE_META). It shares the
    //                            `grp_` prefix but names no group segment, so the
    //                            per-group classifiers do not match it.
    //
    // Plus a small set of vault SINGLETONS — fixed keys naming no contact and no
    // group, so NO purge classifier applies to them and none may match them (a
    // delete/re-pair must not reset them; the vault wipe erases them with every
    // other row):
    //
    //   `onboard_push_prompt_v1`  first-unlock push-notification prompt latch
    //                             (PushPromptOnboarding).
    //   `onboard_burn_notice_v1`  burn-on-read onboarding notice latch (Android
    //                             BurnOnReadNotice, androidApp).
    //   `review_prompt_v1`        store-review prompt state
    //                             (ReviewPromptPolicy.REVIEW_PROMPT_META_KEY).
    //   `notif_consent_v1`        the push-consent EPOCH latch for the sealed
    //                             `notif_consent` pref (NotificationLevelStore
    //                             .VAULT_MARKER_KEY) — global: not in either purge
    //                             list, denied by MoveMetaPolicy.
    //   `mig_*`                   device-move singletons (`mig_frozen`, `mig_handle`,
    //                             `mig_imported`, `mig_rotate_pending`), wiped only by
    //                             `wipeAllTables` (see MoveManager).
    //   `update_nudge_v1`         update-nudge throttle, `"<version>|<epochDay>"`
    //                             (UpdateNudge). Holds relay-advertised state,
    //                             bounded by the AppVersion grammar.
    //
    // (Schema note: `seeded` is also a `_meta` row both actuals upsert on every
    // open — a historical seeding marker, not app state.)
    //
    // Any NEW namespace MUST be classified by one of the classifiers above — or
    // be a singleton of this shape — or it leaks across a delete/re-pair; both
    // actuals iterate the identical set.
    // -----------------------------------------------------------------------

    /** Returns the value for [key] in the `_meta` table, or null if absent. */
    fun getMeta(key: String): String?

    /** Inserts or replaces [key]=[value] in `_meta`. @Throws so a lost ratchet
     *  state persist is catchable (fail-closed) rather than silently dropped. */
    @Throws(Throwable::class)
    fun putMeta(key: String, value: String)

    /** Deletes [key] from `_meta` (no-op if absent). */
    fun deleteMeta(key: String)

    /**
     * Snapshot of every KEY currently in `_meta` (values are NOT read).
     *
     * Both actuals already kept this privately so `deleteGroup`/`deleteContact`
     * could classify residue with the shared predicates
     * ([isGroupMetaResidueForContact], [isReferralMetaResidueForContact]); it is
     * on the interface so `commonMain` can do the same — [ReferralManager]
     * rehydrates its handshake records by scanning the `ref_*` namespace, and a
     * commonMain scan is what keeps Android and iOS from drifting on which keys
     * exist.
     *
     * MATERIALISED into a list, never streamed: callers delete while iterating.
     * Best-effort and non-throwing in spirit — treat a failure as "no keys".
     */
    fun metaKeys(): List<String>

    /**
     * Runs [block] inside ONE DB transaction: every vault write it performs commits
     * together or none do. Use for MULTI-ROW mutations (referral finalize, member
     * removal, the poll write-set) so a torn write — iOS backgrounding mid-batch,
     * SQLCipher lock contention — can't leave orphaned satellite rows / duplicates.
     * A throw from [block] rolls the whole transaction back and re-throws (so the
     * caller's fail-closed path fires). Reads inside are fine. Nesting is NOT
     * supported — never call withTransaction from inside a [block]. @Throws so a
     * commit/rollback failure is catchable in Swift rather than aborting the app.
     */
    @Throws(Throwable::class)
    fun withTransaction(block: () -> Unit)
}

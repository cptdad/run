package com.vg.run

// ---------------------------------------------------------------------------
// GroupInviteStore — the `_meta` namespace that makes a PARKED (un-answered)
// group invite survive the control drain (the blob is acked, i.e. deleted from the relay, once processed) and the session teardown
// that follows every backgrounding.
//
// WHY THIS EXISTS. `GroupManager.pendingInvites` is the GROUP-1 consent gate's
// RAM buffer, and the invite that fills it arrives over the control channel —
// a leased `GET /inbox/{id}` drain. The blob is deleted from the relay as soon
// as the client acks it as processed. Rún then tears the whole session down on background
// (Android `MainActivity.onStop` → `finishAndRemoveTask`; iOS `.background` →
// `IosAppController.lock` → `GroupManager.scrubInMemory`), so a user who SAW
// the invite prompt and backgrounded before tapping Join lost it for good:
// nothing on the relay, nothing on the device, and the inviter had to notice
// and re-invite. That is the product bug this store fixes. It is the exact
// sibling of ReferralStore (parked referral OFFERS) and ScreenshotNoticeStore,
// and it deliberately copies their discipline.
//
// WHERE IT LIVES. The ENCRYPTED VAULT's `_meta` table, exactly like the Double
// Ratchet's `dr-*` state, the referral handshake records and the `ssn:`
// notices — NOT the platform KeyValueStore/Keychain, and deliberately NOT a new
// table: a schema bump would make the vault file unopenable by an older binary
// ("Can't downgrade"), while `_meta` reuses the purge machinery both
// `VaultDatabase` actuals already iterate. NO MIGRATION is needed or performed:
// an install with no `grp_pinv:` rows simply has no parked invites, which is
// precisely the pre-existing behaviour. Establish-on-read throughout — an absent
// or undecodable row is "no parked invite", never an error and never an input to
// a wipe, a lock or a credential decision; and a row whose READ FAILED is
// ambiguous absence, so it is left on disk untouched rather than deleted.
//
// WHAT IT STORES, exactly — and NOTHING beyond what the in-RAM [GroupInvite]
// already held:
//   key   `grp_pinv:<groupId>:<inviterContactId>`
//   value `{"n":…,"ep":…,"adm":…,"you":…,"mem":"…,…","ts":…}`
// i.e. the invite's own wire body (group name, epoch, admin/my memberId, the
// member set) plus OUR receive stamp. No capability, no key material, no alias
// and no message plaintext. The two cosmetic fields the consent prompt also
// shows — `inviterAlias` and the M2 `adminMismatch`/`priorAdminAlias` warning —
// are deliberately NOT stored: they are re-derived at load from the contacts
// table and the `group_admin:<groupId>` tombstone, which is both less residue
// and fresher (aliases rotate).
//
// BOUNDS. One row per parked invite, at most [GroupInviteStore.MAX_PARKED_INVITES]
// across all contacts (oldest evicted), each self-expiring after
// [PARKED_INVITE_TTL_MS]. The per-contact blast radius is unchanged: the
// standing forced-group cap and the invite rate-limit still gate PARKING
// (`GroupManager.inviteAllowed`), and this store never re-opens that budget.
//
// PURGE COUPLING (the rule from docs/vault-relay-internals.md): classified by
// [isGroupInviteResidueForGroup] / [isGroupInviteResidueForContact] below, which
// `DatabaseManager.deleteGroup`/`deleteContact` (Android) and
// `IosVaultDatabase.deleteGroup`/`deleteContact` (iOS) iterate in the SAME loop
// they already run for the group / screenshot / referral classifiers — plus the
// commonTest `InMemoryVault`, so the double models production. They are NOT in
// `ratchetMetaKeysForContact` (an EXACT-key list; these keys carry a variable
// groupId segment) and NOT in `GroupMetaKeys` (which lives in ContactMetaPurge.kt;
// this namespace keeps its keys beside its codecs, exactly like
// `ReferralMetaKeys`). A leave / removal reaches `vault.deleteGroup`, so the
// group classifier is what removes a parked invite for a group the user left.
//
// DEVICE MOVE: `grp_pinv:` is carried by the existing `"grp_"` entry in
// MoveMetaPolicy.allowedPrefixes, which is deliberate and needs no new rule — the
// bundle also carries the inviter contact and its inbox rows, so the invite stays
// acceptable on the new phone, exactly like a parked referral offer (`ref_`). The
// load path re-validates it there like any other row (TTL from the ORIGINAL stamp,
// inviter must exist, group must not already be joined).
//
// FAIL-SOFT, NEVER FAIL-CLOSED. Every method swallows its own errors and
// degrades to the old RAM-only behaviour (on iOS `putMeta` genuinely throws when
// the keybag is locked mid-write). Losing durability must never break the
// consent gate itself: the prompt still appears, the accept still joins, the
// decline still tombstones.
// ---------------------------------------------------------------------------

/**
 * The `_meta` keys the parked-invite mirror owns — the same
 * single-source-of-truth arrangement as [ReferralMetaKeys], so the writer and
 * the purge classifiers below cannot drift.
 *
 * groupIds are Base64Url and contactIds are UUIDs (or the 24-char referral
 * form), so neither may contain `:` — which is what makes the two segments an
 * unambiguous boundary. [GroupInviteStore.isStorableId] refuses to write
 * anything else, so a malformed id degrades to RAM-only instead of contaminating
 * the namespace.
 */
internal object GroupInviteMetaKeys {
    /** `grp_pinv:` — the cheap prefix gate every purge/GC scan applies first.
     *  Distinct from `grp_inv_rl:` (the rate-limit list): neither string is a
     *  prefix of the other, so no classifier can cross-match. */
    const val PREFIX = "grp_pinv:"
}

/**
 * How long a parked invite stays acceptable, measured from OUR receive time.
 *
 * 7 days — the same bound the invite blob itself carries on the relay
 * (`GroupManager.MEMBERSHIP_CONTROL_TTL_SECONDS`, the relay's `maxTtlSeconds`
 * ceiling) and the same idle TTL a parked referral offer gets
 * ([REFERRAL_RECORD_TTL_MS]). Deliberately NOT refreshed by merely opening the
 * app: relaunching is not a decision about this invite. It bounds how long a
 * group name the user never joined can sit in the vault.
 */
internal const val PARKED_INVITE_TTL_MS: Long = 604_800_000L

/**
 * True when [key] is a parked invite [VaultDatabase.deleteGroup] must purge for
 * [groupId] — the group sibling of [isGroupMetaResidueForGroup], iterated in the
 * SAME loop by both `VaultDatabase` actuals.
 *
 * The trailing `:` after [groupId] is load-bearing for exactly the reason it is
 * in [isGroupMetaResidueForGroup]: groupIds are Base64Url (no `:`), so
 * `grp_pinv:<groupId>:` is a boundary a prefix-sharing sibling groupId
 * ("AB" vs "ABC") cannot straddle.
 *
 * This is the clause that drops a parked invite when the user LEAVES (or is
 * removed from) the group — every such path bottoms out in `vault.deleteGroup`.
 */
internal fun isGroupInviteResidueForGroup(key: String, groupId: String): Boolean =
    groupId.isNotEmpty() && key.startsWith(GroupInviteMetaKeys.PREFIX + groupId + ":")

/**
 * True when [key] is a parked invite [VaultDatabase.deleteContact] must purge for
 * [contactId] — IN ADDITION to [ratchetMetaKeysForContact],
 * [isGroupMetaResidueForContact], [isReferralMetaResidueForContact] and
 * [isScreenshotNoticeResidueForContact].
 *
 * `endsWith(":" + contactId)` is exact: contactIds carry no `:`, so the final
 * `:`-delimited segment of the key IS the inviter's contactId and a different
 * contact's key can never match. An invite from a deleted contact is also
 * unusable — `acceptInvite` would fan our KIND_JOIN at a contact that no longer
 * exists — so the load path drops it independently (belt and braces).
 */
internal fun isGroupInviteResidueForContact(key: String, contactId: String): Boolean =
    contactId.isNotEmpty() && key.startsWith(GroupInviteMetaKeys.PREFIX) &&
        key.endsWith(":" + contactId)

/**
 * One parked invite as it round-trips through `_meta`: the invite's own wire
 * fields plus our receive stamp. The display-only fields ([GroupInvite.inviterAlias],
 * [GroupInvite.adminMismatch], [GroupInvite.priorAdminAlias]) are re-derived at
 * load and therefore absent here.
 */
internal data class StoredGroupInvite(
    val groupId: String,
    val inviterContactId: String,
    val groupName: String,
    val epoch: Long,
    val adminMemberId: String,
    val myMemberId: String,
    val memberIds: List<String>,
    val receivedAt: Long,
) {
    val expiresAt: Long get() = receivedAt + PARKED_INVITE_TTL_MS
}

/** String-only flat JSON, read back with the linear scanner (never a regex —
 *  Kotlin/Native's engine recurses; see [firstStringFieldAnywhere]). */
private fun giField(key: String, value: String) = "\"" + key + "\":" + jsonEscapeString(value)

/**
 * Durable, bounded, self-expiring storage for invites parked awaiting consent.
 *
 * Owned by [GroupManager] (which holds the vault and already owns the consent
 * gate). Holds NO cache of its own: every method reads the vault, so lock/wipe
 * needs no participation from it and `scrubInMemory` has nothing here to clear —
 * the RAM buffer it mirrors is cleared there as before, and this durable copy is
 * deliberately left alone (clearing it on ordinary backgrounding would reinstate
 * the very loss this store exists to close). A wipe crypto-erases the whole
 * vault and takes these rows with everything else, so no wipe path needs to
 * enumerate them.
 *
 * [clock] is injectable purely for tests; production always passes the default.
 * Blocking vault I/O — call from the same background context as the polls, never
 * the main thread.
 */
internal class GroupInviteStore(
    private val vault: VaultDatabase,
    private val clock: () -> Long = { currentTimeMillis() },
) {
    companion object {
        private const val TAG = "GroupInviteStore"

        /**
         * Ceiling on PERSISTED parked invites across ALL contacts; the oldest is
         * evicted on insert and on load. The per-contact bound already exists at
         * PARK time (`GroupManager.MAX_FORCED_GROUPS_PER_CONTACT` = 8 plus the
         * hourly rate limit), so this is the GLOBAL backstop that stops many
         * contacts' worth of un-answered invites from accumulating in the vault
         * across sessions. 64 = eight contacts at their full standing cap, far
         * above any honest backlog.
         */
        internal const val MAX_PARKED_INVITES = 64

        /**
         * Ids are embedded verbatim in a `:`-delimited key, so anything carrying a
         * `:` (or empty) would make the key ambiguous for the purge classifiers.
         * contactIds are UUIDs and groupIds Base64Url, so this never rejects a real
         * id — it is the shape gate that keeps a malformed one out of the namespace
         * entirely (mirrors [ScreenshotNoticeStore.isStorableId] /
         * [isValidIntroId]), degrading that invite to RAM-only.
         */
        internal fun isStorableId(id: String): Boolean =
            id.isNotEmpty() && !id.contains(':') && !id.contains('|') && id.length <= 128

        internal fun keyFor(groupId: String, inviterContactId: String): String =
            GroupInviteMetaKeys.PREFIX + groupId + ":" + inviterContactId

        internal fun encode(invite: GroupInvite, receivedAt: Long): String =
            "{" + giField("n", invite.groupName) +
                "," + giField("ep", invite.epoch.toString()) +
                "," + giField("adm", invite.adminMemberId) +
                "," + giField("you", invite.myMemberId) +
                // memberIds are 16-hex by construction, so a bare `,` join needs no
                // escaping and cannot smuggle structure (same shape as
                // StoredSession.relayed).
                "," + giField("mem", invite.memberIds.joinToString(",")) +
                "," + giField("ts", receivedAt.toString()) + "}"

        /**
         * STRICT decode — it re-applies EVERY validation `GroupManager.handleInvite`
         * applies to the wire body, so a hand-tampered `_meta` row can never park an
         * invite the receive path would have rejected (epoch bounds, memberId shapes,
         * admin/self membership, the member cap). Anything that does not fully
         * validate returns null and the caller deletes the key: a corrupt row is
         * "no parked invite", never an error and never a throw.
         */
        internal fun decode(key: String, value: String?): StoredGroupInvite? {
            if (!key.startsWith(GroupInviteMetaKeys.PREFIX)) return null
            val parts = key.split(':')
            if (parts.size != 3) return null
            val groupId = parts[1]
            val inviterContactId = parts[2]
            if (!isStorableId(groupId) || !isStorableId(inviterContactId)) return null
            val raw = value ?: return null
            val name = firstStringFieldAnywhere(raw, "n")?.take(GroupManager.MAX_GROUP_NAME_CHARS)
                ?.takeIf { it.isNotBlank() } ?: return null
            val epoch = firstStringFieldAnywhere(raw, "ep")?.toLongOrNull() ?: return null
            if (epoch < 1 || epoch > GroupManager.MAX_GROUP_EPOCH) return null
            val adm = firstStringFieldAnywhere(raw, "adm") ?: return null
            val you = firstStringFieldAnywhere(raw, "you") ?: return null
            if (!GroupManager.isValidMemberId(adm) || !GroupManager.isValidMemberId(you)) return null
            if (adm == you) return null
            val memRaw = firstStringFieldAnywhere(raw, "mem") ?: return null
            // Bound the split before it allocates: a real list is at most
            // MAX_GROUP_MEMBERS 16-hex ids plus separators.
            if (memRaw.length > (GroupManager.MAX_GROUP_MEMBERS + 1) * 17) return null
            val mem = memRaw.split(',').filter { it.isNotEmpty() }
            if (mem.isEmpty() || mem.size > GroupManager.MAX_GROUP_MEMBERS) return null
            if (mem.any { !GroupManager.isValidMemberId(it) }) return null
            if (adm !in mem || you !in mem) return null
            val ts = firstStringFieldAnywhere(raw, "ts")?.toLongOrNull() ?: return null
            if (ts <= 0L) return null
            return StoredGroupInvite(
                groupId = groupId,
                inviterContactId = inviterContactId,
                groupName = name,
                epoch = epoch,
                adminMemberId = adm,
                myMemberId = you,
                memberIds = mem,
                receivedAt = ts,
            )
        }
    }

    /** Every `grp_pinv:` key currently in the vault; empty on any read failure. */
    private fun allKeys(): List<String> = try {
        vault.metaKeys().filter { it.startsWith(GroupInviteMetaKeys.PREFIX) }
    } catch (e: Exception) {
        platformLogWarn(TAG, "meta key scan failed: ${e::class.simpleName}"); emptyList()
    }

    /**
     * Reads one row through [readMetaForGc], distinguishing the two null-shaped
     * outcomes — which the sibling stores deliberately collapse and this one
     * deliberately does not:
     *
     *  - `first == false`: the READ ITSELF failed. Ambiguous absence. The row is left
     *    strictly alone (never deleted, never acted on) and retried next time; a
     *    transient vault hiccup must not destroy a live invite.
     *  - `first == true, second == null`: the value was read and does not decode —
     *    corrupt, tampered or a shape [decode] refuses. That is positive evidence the
     *    row can never be acted on, so the caller deletes it as residue.
     */
    private fun readRow(key: String): Pair<Boolean, StoredGroupInvite?> =
        when (val r = vault.readMetaForGc(key, TAG, "parked invite row")) {
            MetaRead.Unreadable -> false to null
            is MetaRead.Read -> true to decode(key, r.raw)
        }

    private fun deleteQuietly(key: String) {
        try { vault.deleteMeta(key) } catch (_: Exception) { /* best effort */ }
    }

    /**
     * Mirrors one freshly parked (or re-parked) invite. Returns whether the row is
     * durable; a `false` is FAIL-SOFT by design — the caller keeps the invite in
     * RAM for this session and it is simply not durable (exactly the pre-existing
     * behaviour).
     *
     * Evict-then-insert runs inside ONE [VaultDatabase.withTransaction] so a torn
     * write can never drop older rows without adding the new one. Expired and
     * undecodable rows encountered on the way are pruned in the same transaction.
     * Re-recording the SAME (group, inviter) overwrites its row, which is what
     * makes this idempotent for a re-delivered offer.
     */
    fun record(invite: GroupInvite, receivedAt: Long = clock()): Boolean {
        if (!isStorableId(invite.groupId) || !isStorableId(invite.inviterContactId)) {
            platformLogWarn(TAG, "parked invite not persisted — unstorable id shape")
            return false
        }
        if (receivedAt <= 0L) return false
        val key = keyFor(invite.groupId, invite.inviterContactId)
        val now = clock()
        // Decide the eviction set BEFORE the transaction: pure reads, so the
        // transaction holds nothing but the deletes plus the insert.
        val live = mutableListOf<Pair<String, StoredGroupInvite>>()
        val doomed = mutableListOf<String>()
        for (k in allKeys()) {
            if (k == key) continue                       // this row is being replaced
            val (readOk, rec) = readRow(k)
            // An unreadable row is neither live nor doomed: it keeps its place on disk
            // and merely leaves the cap a little slack for this one write.
            if (!readOk) continue
            if (rec == null || rec.expiresAt <= now) doomed.add(k) else live.add(k to rec)
        }
        live.sortWith(compareBy({ it.second.receivedAt }, { it.first }))
        val overflow = live.size - (MAX_PARKED_INVITES - 1)
        if (overflow > 0) for (i in 0 until overflow) doomed.add(live[i].first)
        return try {
            vault.withTransaction {
                for (k in doomed) vault.deleteMeta(k)
                vault.putMeta(key, encode(invite, receivedAt))
            }
            true
        } catch (e: Throwable) {
            // iOS: a locked keybag / SQLCipher refusal throws here. Never fatal.
            platformLogWarn(TAG, "parked invite not persisted: ${e::class.simpleName}")
            false
        }
    }

    /** Drops one parked invite's row (accept / decline / superseded). Never throws. */
    fun remove(groupId: String, inviterContactId: String) {
        if (!isStorableId(groupId) || !isStorableId(inviterContactId)) return
        deleteQuietly(keyFor(groupId, inviterContactId))
    }

    /**
     * Every still-valid parked invite, OLDEST FIRST, with expiry + eviction applied
     * as a side effect:
     *
     *  - a row that READS but fails [decode] is DELETED (it can never be acted on,
     *    and leaving it would be residue). A row whose READ FAILED is left strictly
     *    alone — ambiguous absence is never evidence, so it is retried next unlock;
     *  - a row past [PARKED_INVITE_TTL_MS] since ITS OWN receive stamp is DELETED;
     *  - past [MAX_PARKED_INVITES] the OLDEST rows are deleted, the newest kept.
     *
     * A future-dated stamp is NOT treated as expired (a clock that jumped forward
     * and back must never silently eat an invite) — it merely sorts last.
     *
     * Never throws: a scan failure yields an empty list, i.e. exactly the
     * pre-existing "invites die with the session" behaviour.
     */
    fun load(): List<StoredGroupInvite> {
        val now = clock()
        val live = mutableListOf<Pair<String, StoredGroupInvite>>()
        for (key in allKeys()) {
            val (readOk, rec) = readRow(key)
            if (!readOk) continue   // ambiguous absence — leave it for the next unlock
            if (rec == null || rec.expiresAt <= now) { deleteQuietly(key); continue }
            live.add(key to rec)
        }
        live.sortWith(compareBy({ it.second.receivedAt }, { it.first }))
        val overflow = live.size - MAX_PARKED_INVITES
        if (overflow > 0) {
            for (i in 0 until overflow) deleteQuietly(live[i].first)
            return live.drop(overflow).map { it.second }
        }
        return live.map { it.second }
    }
}

// ---------------------------------------------------------------------------
// DECLINED_INVITE_META codec — the group analog of ReferralStore's
// encodeCompletedIntros/decodeCompletedIntros. One hashed offer token per line;
// garbage/invalid lines are DROPPED (never a throw), and the list is capped to the
// newest [max] on BOTH encode and decode so a hand-tampered blob can never grow the
// in-RAM set past its bound. The shape check keeps a corrupt blob from seeding junk
// into the suppression set (fail toward "don't suppress"): a declineTokenFor() token
// is base64url of 18 bytes (24 chars), well within this range.
// ---------------------------------------------------------------------------
private val DECLINE_TOKEN_REGEX = Regex("^[A-Za-z0-9_\\-]{16,64}$")

/** Serializes the bounded decline tombstone; invalid tokens are dropped, not escaped. */
internal fun encodeDeclinedInvites(tokens: Collection<String>, max: Int): String =
    tokens.filter { DECLINE_TOKEN_REGEX.matches(it) }.let { if (it.size > max) it.takeLast(max) else it }
        .joinToString("\n")

/** Inverse of [encodeDeclinedInvites]; tolerates anything (returns what parses). */
internal fun decodeDeclinedInvites(raw: String, max: Int): List<String> =
    raw.split("\n").filter { DECLINE_TOKEN_REGEX.matches(it) }.let { if (it.size > max) it.takeLast(max) else it }

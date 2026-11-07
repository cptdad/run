package com.vg.run

// ---------------------------------------------------------------------------
// Data models — plain representations of database table rows.
//
// These live in commonMain because they are pure data classes with no
// platform-specific dependencies. They are used by VaultDatabase (interface),
// MessageManager, VaultSelector, and all UI screens.
// ---------------------------------------------------------------------------

data class ContactRecord(
    val contactId: String,
    val sharedSecret: ByteArray,    // Sensitive — treat carefully
    val trustLevel: Int,
    val alias: String,
    val aliasLastRotated: Long,     // Unix timestamp (ms)
    val mnemonic: String = "",      // User's private reminder for who this contact is

    // Anti-replay state. All counters are vault-persisted and
    // epoch-bound to the shared secret so a re-pair (new secret) resets the
    // counter space without the receiver false-rejecting fresh low counters.
    //   outboundCounter — last counter WE stamped on a message to this
    //                     contact; next send uses outboundCounter + 1.
    //   inboundCounter  — highest counter ACCEPTED from this contact within
    //                     [inboundEpoch]; a message with counter <= this is
    //                     a replay / reordered-old and is dropped.
    //   inboundEpoch    — the shared-secret epoch the inbound counters are
    //                     scoped to; a different epoch resets them.
    //   *CtlCounter     — the SAME machinery for the CONTROL channel (v7).
    //                     The two channels are drained independently (texts
    //                     only while a conversation is open; controls by the
    //                     background poller), so a single shared counter
    //                     space would false-reject cross-channel reordering.
    //                     One inboundEpoch covers both: a re-pair resets all.
    //   *GrpCounter     — the SAME machinery again for the GROUP-text channel
    //                     ([MessageManager.Chan.GRP], the third pairwise inbox
    //                     pair). Independent for exactly the reason above: the
    //                     group inbox is drained on its own schedule, so a
    //                     shared space would false-reject cross-channel
    //                     reordering as a replay. Still epoch-scoped by the one
    //                     [inboundEpoch] — a re-pair resets all THREE channels.
    val outboundCounter: Long = 0,
    val inboundCounter: Long = 0,
    val inboundEpoch: String = "",
    val outboundCtlCounter: Long = 0,
    val inboundCtlCounter: Long = 0,
    // PERSISTED since DB v10: `outbound_grp_counter` / `inbound_grp_counter`
    // on both actuals (DatabaseManager `Contacts` / IosVaultDatabase `contacts`),
    // added by an additive `ALTER TABLE … INTEGER NOT NULL DEFAULT 0`. A row
    // written by a v9 (or older) build has no column; after the migration it reads
    // 0, which is exactly the establish-on-read baseline the v4 and v7 counters
    // use — so an existing vault keeps every contact and simply starts the group
    // channel from zero. They also travel in the device-move bundle, with
    // MoveConstants.COUNTER_JUMP applied to the OUTBOUND one only (VaultSnapshotIo).
    val outboundGrpCounter: Long = 0,
    val inboundGrpCounter: Long = 0,

    // Referral/vouching (referral.md). Non-null when this contact was added via
    // a referral (an introducer vouched) rather than an in-person QR pairing:
    //   vouchedByContactId — the introducer's contactId (drives "Introduced by …").
    //   vouchedAt          — when the referral completed (ms), 0 for QR pairs.
    // QR-paired contacts leave both at their defaults. Trust provenance is
    // carried in [trustLevel] (see VaultSeedDefaults.TRUST_REFERRED_*).
    val vouchedByContactId: String? = null,
    val vouchedAt: Long = 0,
) {
    // Truncate the id (like the take(8) used at every log site) so an accidental
    // log/interpolation of a ContactRecord doesn't emit the full contact id.
    override fun toString() = "ContactRecord(contactId=${contactId.take(8)}…, trustLevel=$trustLevel)"
}

/**
 * One inbox on the relay, scoped to one direction within one peering.
 *
 * [cap] holds different cap material depending on [direction]:
 *   • "inbound"  — our own X-Read-Capability for this inbox. The peer never
 *                  sees this value. Used to authenticate poll / delete /
 *                  rotation operations.
 *   • "outbound" — the peer's X-Write-Capability for the inbox they minted
 *                  on their device. We received it via the IRL pairing QR
 *                  and use it to send messages to them.
 *
 * `null` indicates an old (pre-capability-protocol) record — those have to
 * be re-paired since the relay no longer accepts the legacy X-Read-Secret
 * model. UI should surface a "re-pair required" state for any contact whose
 * inbox records have null `cap`.
 */
data class InboxIdRecord(
    val inboxId: String,
    val contactId: String,
    val createdAt: Long,            // Unix timestamp (ms)
    val expiresAt: Long,            // Unix timestamp (ms)
    val direction: String,          // "outbound"/"inbound" (1:1 text), "outbound-ctl"/"inbound-ctl" (control) or "outbound-grp"/"inbound-grp" (group text)
    val cap: String? = null,        // base64url-no-pad capability — meaning depends on direction
) {
    // #39: the default data-class toString would print the full inboxId and the
    // live capability token (a relay read/write secret). Redact both so an
    // accidental log/interpolation of an InboxIdRecord can't leak them.
    override fun toString() =
        "InboxIdRecord(inboxId=${inboxId.take(8)}…, contactId=${contactId.take(8)}…, " +
            "direction=$direction, cap=${if (cap.isNullOrEmpty()) "none" else "[redacted]"})"
}

/**
 * One group chat. Groups exist ONLY client-side — the relay never sees a
 * group object; group messages are pairwise fan-out over the members'
 * existing 1:1 inboxes, with all group routing data (groupId, membership)
 * inside the AES-GCM envelope. The fan-out is NOT indistinguishable from 1:1
 * traffic to the relay — group existence and size
 * are observable from the burst shape; content and membership are not.
 *
 * Single-admin model: the creator is the admin, the only member whose
 * membership updates (rosters) honest clients apply. This is a client-side
 * convention — it serializes membership changes through one author (one
 * monotonic [epoch]) so members converge on one member list without a
 * coordination server. It does not bind malicious clients (nothing can).
 *
 * [epoch] increments on every membership change; an incoming roster with a
 * lower epoch is stale and ignored. [myMemberId] == [adminMemberId] iff this
 * device is the admin.
 */
data class GroupRecord(
    val groupId: String,            // 32-char base64url (24 random bytes), locally generated
    val name: String,
    val epoch: Long,
    val adminMemberId: String,      // 16 hex chars, admin-assigned
    val myMemberId: String,         // our own member id within this group
    val createdAt: Long,            // Unix timestamp (ms)
) {
    val isAdmin: Boolean get() = adminMemberId == myMemberId
    // Redact like the other records — groupId inside envelopes is E2E-protected;
    // don't leak it whole into logs.
    override fun toString() = "GroupRecord(groupId=${groupId.take(8)}…, epoch=$epoch, isAdmin=$isAdmin)"
}

/**
 * One member of a group.
 *
 * [contactId] is null until the member is RESOLVED — i.e. until we know which
 * of our local contacts this memberId belongs to. Resolution happens via
 * pairwise tags (see GroupManager): each member's join carries
 * HMAC(pairwiseSharedSecret, groupId) tags; only the two peers of a pairing
 * can compute a given tag, so matching one proves the binding without any
 * global identity. Our own row (memberId == GroupRecord.myMemberId) keeps
 * contactId null.
 *
 * [tags] is the member's tag list as received in their join (JSON-array-free
 * `;`-joined hex), persisted on the ADMIN's device only, so the admin can
 * intersect tag sets across members joining in different sessions. Tags are
 * opaque HMAC outputs — they reveal nothing about non-members.
 */
data class GroupMemberRecord(
    val groupId: String,
    val memberId: String,           // 16 hex chars
    val contactId: String?,         // null until resolved (or for our own row)
    val addedAt: Long,              // Unix timestamp (ms)
    val tags: String = "",          // ';'-joined 33-char "sym:bound" pair tags (only the admin stores non-empty tags)
) {
    override fun toString() =
        "GroupMemberRecord(groupId=${groupId.take(8)}…, memberId=${memberId.take(6)}…, resolved=${contactId != null})"
}

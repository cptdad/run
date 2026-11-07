package com.vg.run

// ---------------------------------------------------------------------------
// InboxOwnership — the ONE ownership gate every `inbox_ids` write goes through.
//
// `inbox_ids.inbox_id` is the PRIMARY KEY on both
// platforms and every insert is replace-on-conflict (Android
// `CONFLICT_REPLACE`, iOS `INSERT OR REPLACE`), so writing a PEER-SUPPLIED id
// that already exists silently OVERWRITES that row — flipping its direction,
// reassigning its contactId and destroying the stored capability. Nothing
// throws, nothing is logged. The check below is therefore not an optimisation:
// it is the only thing standing between a peer-chosen string and another
// contact's route.
//
// Three sinks write peer-supplied inbox ids and all three call this:
// [ReferralManager.finalizeFromPeerAccept], [PairingVault.savePairedContact]
// and MessageManager's `applyInboxAnnounce`. In all three the call is the FIRST
// statement INSIDE the vault transaction, so the check and the writes it guards
// commit (or roll back) together — a pre-transaction check could be raced by a
// concurrent control poll applying an announce.
// ---------------------------------------------------------------------------

/**
 * One (inboxId → contact, direction) row a caller is about to write.
 *
 * [direction] must be the exact value that will be persisted in the
 * `InboxIdRecord` ("inbound" / "outbound" / [MessageManager.DIR_INBOUND_CTL] /
 * [MessageManager.DIR_OUTBOUND_CTL]) — the check compares it against the stored
 * row, so a claim that lies about its direction would wave through the very
 * overwrite this exists to stop.
 */
internal data class InboxClaim(
    val inboxId: String,
    val contactId: String,
    val direction: String,
)

/**
 * Returns the first claim in [claims] that is already SPOKEN FOR and therefore
 * cannot be written, or null when the whole batch is safe to persist. Three
 * independent reasons a claim is unavailable:
 *
 *  - Another claim in the SAME batch already used that id. A pairing writes up
 *    to four rows keyed by inboxId, so a peer naming one id twice (e.g. `ib` ==
 *    `cib`) would have the second insert silently REPLACE the first and leave
 *    the contact with a broken channel and no re-pair UX.
 *  - It is an inbox WE mint + poll (an inbound / inbound-ctl record) — never a
 *    legitimate peer-declared outbound target. Rejects a relay that reflects our
 *    own inbox announce back at us. Expressed here as the general
 *    "the stored direction differs" rule, which also covers the mirror case.
 *  - It already belongs to a DIFFERENT contact. `inbox_ids` is keyed by
 *    inboxId on BOTH platforms (SQLite `PRIMARY KEY` + INSERT-OR-REPLACE), so accepting such a claim MOVES the
 *    row: the victim contact's outbound route is destroyed (its
 *    getInboxIdForContact returns null → un-sendable, no re-pair signal) and our
 *    sends to the claimant are misrouted into the victim's inbox. It is remotely
 *    reachable without device access: the referral handshake ships the
 *    introducee's freshly-minted `ib`/`wc`/`cib`/`cwc` THROUGH the introducer in
 *    plaintext ([ReferralManager] acceptBody), so the introducer learns a third
 *    party's inbox ids and can announce them as its own inside a genuinely
 *    AEAD-authenticated control blob that passes every epoch / counter / "ch" /
 *    "di" check.
 *
 * An UNKNOWN inbox (no row) is deliberately AVAILABLE — that is the normal
 * first-announce case (instant-QR pairing) and also every capability/inbox
 * rotation and post-404 re-announce; rejecting it would break pairing outright.
 * A re-claim of the SAME id, by the SAME contact, in the SAME direction also
 * stays available, so a cap refresh still lands. A genuine re-pair mints a fresh
 * contactId AND fresh inbox ids on both platforms, so it is never rejected.
 *
 * [VaultDatabase.getInboxId] is the PRIMARY-KEY lookup and is deliberately NOT
 * expiry-filtered (unlike `getInboxIdForContact`): an EXPIRED row still occupies
 * the primary key and would still be overwritten, so it must still block.
 */
internal fun firstUnavailableInboxClaim(
    vault: VaultDatabase,
    claims: List<InboxClaim>,
): InboxClaim? {
    val seen = HashSet<String>(claims.size)
    for (c in claims) {
        if (!seen.add(c.inboxId)) return c            // intra-batch self-collision
        val existing = vault.getInboxId(c.inboxId) ?: continue
        if (existing.contactId != c.contactId) return c
        if (existing.direction != c.direction) return c
    }
    return null
}

/**
 * Thrown by the ownership gate when a pairing/referral would overwrite an
 * `inbox_ids` row that belongs to someone else. Public + styled on
 * [ExistingVaultException] because it crosses the Swift bridge out of
 * [PairingVault.savePairedContact] (`@Throws`), where the caller's `do/catch`
 * turns it into a user-visible "already in use" message. NOTHING is written and
 * nothing is destroyed on this path — the throw happens before the first insert,
 * inside the transaction.
 */
class InboxInUseException : RuntimeException(
    "an inbox id in this pairing is already owned by another contact — refusing to overwrite it"
)

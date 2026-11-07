package com.vg.run

/**
 * The contact list's vault reads and writes, and its consent-dialog rule, kept
 * out of the composable so they run where the ViewModel puts them (on IO) and
 * can be unit-tested.
 *
 * Callers: RunViewModel's contact-list loader and its `*InBackground` edit
 * helpers (the vault work), and ContactListScreen ([consentToShow], pure).
 */

/**
 * The whole contact-list load, run by the ViewModel on IO.
 *
 * getAllContacts() returns full ContactRecords, each carrying a raw 32-byte
 * sharedSecret (the pre-image of the legacy static-envelope key —
 * vault-relay-internals.md:198). This list is re-materialised on every vault
 * event for the life of the unlocked session, so retaining the records would
 * accumulate one unzeroed secret copy per control sweep. Only the secret-free
 * [ContactListItem] projection is retained; every source record's secret is
 * wiped the instant it has been projected. Mirrors iOS
 * ContactListView.loadContacts() → ContactItem.
 *
 * The stale set (pre-capability-protocol inbox rows: UUID-shaped id or a null
 * cap → "Re-pair" tag) and the pending set (instant-QR contacts still awaiting
 * their peer's inbox announce → "Waiting…") read the vault per contact, which
 * is why the whole load is off the main thread.
 */
internal fun loadContactListSnapshot(vault: VaultDatabase): ContactListSnapshot {
    val records = vault.getAllContacts()
    val contacts = records.map { it.toListItem() }
    records.forEach { it.sharedSecret.secureWipe() }
    val groups = vault.getAllGroups()
    val staleIds = contacts.filter { contactNeedsRepair(vault, it.contactId) }.map { it.contactId }.toSet()
    val pendingIds = contacts.filter { contactAwaitingPeerInbox(vault, it.contactId) }.map { it.contactId }.toSet()
    return ContactListSnapshot(contacts, groups, staleIds, pendingIds)
}

/**
 * Persists a mnemonic change. ContactEdits.updateMnemonic re-reads the row and
 * copy()s it (preserving the shared secret AND the anti-replay counters/epoch)
 * entirely inside commonMain, so this call site never needs (and
 * must never hold) the full ContactRecord — only the contactId. Write
 * failures are swallowed: a memory edit is not worth surfacing a transient
 * vault error for (mirrors the iOS saveMnemonic).
 */
internal fun saveContactMnemonic(vault: VaultDatabase?, contactId: String, mnemonic: String) {
    if (vault == null) return
    // The read-modify-write (which preserves the shared secret + anti-replay
    // state) lives in commonMain so iOS runs the identical logic.
    ContactEdits.updateMnemonic(vault, contactId, mnemonic)
}

/**
 * Rolls a fresh random alias for [contact] and persists it. The alias is a
 * vault-local pseudonym (never sent anywhere), so this is purely cosmetic and,
 * like [saveContactMnemonic], copy() preserves the shared secret + anti-replay
 * state. Returns the updated projection so the caller can refresh the open menu
 * live; on a write failure the original is returned unchanged. A new draw equal
 * to the current alias is re-rolled so the button always visibly does something.
 *
 * [ContactEdits.rollAlias] necessarily returns the FULL ContactRecord
 * (copy() must preserve every field, including sharedSecret, in the vault
 * write) — that record is projected to [ContactListItem] and its secret
 * wiped immediately, in this function's local scope, before it is ever
 * exposed to a caller or Compose state.
 */
internal fun rollContactAlias(vault: VaultDatabase?, contact: ContactListItem): ContactListItem {
    if (vault == null) return contact
    // Shared read-modify-write (see ContactEdits) — preserves the shared
    // secret + anti-replay state; returns null unchanged on write failure.
    val updated = ContactEdits.rollAlias(vault, contact.contactId) ?: return contact
    val projected = updated.toListItem()
    updated.sharedSecret.secureWipe()
    return projected
}

/** What the consent surface currently shows: at most one of the two dialogs. */
internal data class ConsentShown(val offer: ReferralOffer?, val invite: GroupInvite?)

/**
 * Which incoming referral offer / group invite the contact list shows, given
 * what is pending in the managers ([pending], from RunViewModel.pendingConsent)
 * and what is on screen now ([shown]). One prompt at a time, offers first.
 *
 *  1. While the introduce picker is open ([introduceOpen]) nothing changes.
 *  2. A pending offer: keep the shown offer, or adopt the pending one if none
 *     is shown.
 *  3. No pending offer and no accept in flight ([referralBusy]): the offer was
 *     consumed, so dismiss it. (Mid-accept the "Connecting…" state stays put.)
 *  4. An offer is shown and no join in flight ([groupInviteBusy]): no invite.
 *  5. No offer: adopt the pending invite if none is shown and not busy; clear
 *     it once none is pending and not busy.
 *
 * Syncing both ways matters: after a successful accept the offer leaves
 * pendingOffers, so the dialog must clear rather than linger on "Approve".
 */
internal fun consentToShow(
    pending: PendingConsent,
    shown: ConsentShown,
    introduceOpen: Boolean,
    referralBusy: Boolean,
    groupInviteBusy: Boolean,
): ConsentShown {
    if (introduceOpen) return shown
    val offer = when {
        pending.offer != null -> shown.offer ?: pending.offer
        !referralBusy -> null
        else -> shown.offer
    }
    val invite = when {
        offer != null -> if (!groupInviteBusy) null else shown.invite
        pending.invite != null ->
            if (shown.invite == null && !groupInviteBusy) pending.invite else shown.invite
        !groupInviteBusy -> null
        else -> shown.invite
    }
    return ConsentShown(offer, invite)
}

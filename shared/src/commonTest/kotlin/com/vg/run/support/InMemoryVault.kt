package com.vg.run

/**
 * In-memory [VaultDatabase] for tests that do not care about SQLCipher.
 *
 * Models: contacts, inbox rows (INSERT-OR-REPLACE by inboxId, newest-row
 * selection via the shared [selectOperationalInbox]), groups and members, the
 * `_meta` table, and the production purge rules of [deleteContact] /
 * [deleteGroup] (the same classifiers both actuals use). Every read of a contact
 * returns a COPY of its shared secret, as both actuals decode a fresh record per
 * call, so production code may wipe what it was handed.
 *
 * Does NOT model: encryption or re-keying ([rekey] only records the request),
 * transactions ([withTransaction] just runs the block; a throw does not roll the
 * maps back), expiry filtering, or [VaultDatabase.getAllInboxIds] (the interface
 * default throws). Decorate it (`VaultDatabase by inner`) for those.
 */
internal open class InMemoryVault : VaultDatabase {
    val contacts = mutableMapOf<String, ContactRecord>()
    val inboxes = mutableListOf<InboxIdRecord>()
    val groups = mutableMapOf<String, GroupRecord>()
    val groupMembers = mutableListOf<GroupMemberRecord>()
    override fun insertContact(contact: ContactRecord): Long {
        // Mirror real SQLCipher: the sharedSecret blob is copied into the DB at bind
        // time, so a caller may wipe its source array right after insert (ReferralManager).
        // Store a DEFENSIVE COPY of the key so a post-persist wipe of the caller's
        // array can't zero our at-rest snapshot (the fake would otherwise alias it).
        contacts[contact.contactId] = contact.copy(sharedSecret = contact.sharedSecret.copyOf())
        return 1
    }
    // Mirror real SQLCipher / the iOS bridge on the READ side too: every read decodes a
    // FRESH copy of the secret, so production code may (and MessageManager does) wipe
    // the array it was handed without touching the at-rest snapshot.
    override fun getContact(contactId: String) =
        contacts[contactId]?.let { it.copy(sharedSecret = it.sharedSecret.copyOf()) }
    override fun getAllContacts() =
        contacts.values.map { it.copy(sharedSecret = it.sharedSecret.copyOf()) }
    override fun insertInboxId(record: InboxIdRecord): Long {
        // Mirror the production INSERT-OR-REPLACE behaviour keyed by inboxId.
        inboxes.removeAll { it.inboxId == record.inboxId }
        inboxes.add(record)
        return 1
    }
    // The PRIMARY-KEY lookup: never expiry-filtered in production either (an expired
    // row still occupies the key, so the ownership gate must still see it).
    override fun getInboxId(inboxId: String) = inboxes.firstOrNull { it.inboxId == inboxId }
    // Route through the SAME shared chooser both actuals use, so this double
    // models production instead of approximating it. Two behaviours follow: the
    // NEWEST row wins (the old `firstOrNull` returned the oldest — an acknowledged
    // divergence, see InboxAnnounceTest's rotation case), and `expiresAt` is not
    // consulted (see selectOperationalInbox for why).
    override fun getInboxIdForContact(contactId: String, direction: String) =
        selectOperationalInbox(inboxes.filter { it.contactId == contactId && it.direction == direction })
    // Forward-only single-column re-stamp, mirroring both actuals'
    // `... WHERE inbox_id = ? AND expires_at < ?` (never lowers, never inserts).
    override fun touchInboxExpiry(inboxId: String, expiresAt: Long) {
        val i = inboxes.indexOfFirst { it.inboxId == inboxId }
        if (i >= 0 && inboxes[i].expiresAt < expiresAt) {
            inboxes[i] = inboxes[i].copy(expiresAt = expiresAt)
        }
    }
    override fun insertGroup(group: GroupRecord): Long {
        groups[group.groupId] = group
        return 1
    }
    override fun getGroup(groupId: String) = groups[groupId]
    override fun getAllGroups() = groups.values.sortedBy { it.name }
    override fun deleteGroup(groupId: String) {
        groups.remove(groupId)
        groupMembers.removeAll { it.groupId == groupId }
        // Mirror production: purge group-scoped _meta residue via the shared
        // classifier (group_admin: tombstone deliberately retained).
        meta.keys.filter { isGroupMetaResidueForGroup(it, groupId) }.forEach { meta.remove(it) }
        // Mirror production: purge this group's persisted screenshot notices.
        meta.keys.toList()
            .filter { isScreenshotNoticeResidueForGroup(it, groupId) }
            .forEach { meta.remove(it) }
        // Mirror production: purge this group's durable PARKED INVITE row — the
        // clause that drops a parked invite when the user leaves/is removed.
        meta.keys.toList()
            .filter { isGroupInviteResidueForGroup(it, groupId) }
            .forEach { meta.remove(it) }
    }
    override fun insertGroupMember(member: GroupMemberRecord): Long {
        groupMembers.removeAll { it.groupId == member.groupId && it.memberId == member.memberId }
        groupMembers.add(member)
        return 1
    }
    override fun getGroupMembers(groupId: String) = groupMembers.filter { it.groupId == groupId }
    override fun deleteGroupMember(groupId: String, memberId: String) {
        groupMembers.removeAll { it.groupId == groupId && it.memberId == memberId }
    }
    override fun deleteContact(contactId: String) {
        contacts.remove(contactId)
        inboxes.removeAll { it.contactId == contactId }
        // Mirror production: purge the contact's ratchet/session meta.
        for (key in ratchetMetaKeysForContact(contactId)) meta.remove(key)
        // Mirror production: purge contact-scoped GROUP _meta residue via the
        // shared classifier (invite/roster throttles keyed by this contactId).
        meta.keys.filter { isGroupMetaResidueForContact(it, contactId) }.forEach { meta.remove(it) }
        // Mirror production: purge the contact's persisted screenshot notices in BOTH
        // id positions (their own 1:1 notices and the ones they left inside groups).
        meta.keys.toList()
            .filter { isScreenshotNoticeResidueForContact(it, contactId) }
            .forEach { meta.remove(it) }
        // Mirror production: purge durable PARKED INVITES from this inviter — an
        // invite from a deleted contact can never be accepted.
        meta.keys.toList()
            .filter { isGroupInviteResidueForContact(it, contactId) }
            .forEach { meta.remove(it) }
        // Mirror production (referral): persisted handshake records name the contact
        // in the VALUE (they are keyed by introId), so the classifier takes the value.
        meta.keys.toList()
            .filter { isReferralMetaKey(it) && isReferralMetaResidueForContact(it, meta[it], contactId) }
            .forEach { meta.remove(it) }
        // Production behaviour: group member rows become unresolved.
        for (i in groupMembers.indices) {
            if (groupMembers[i].contactId == contactId) {
                groupMembers[i] = groupMembers[i].copy(contactId = null)
            }
        }
    }
    override fun wipeAllTables() {
        contacts.clear(); inboxes.clear(); groups.clear(); groupMembers.clear(); meta.clear()
    }
    /**
     * There is no encryption to re-key in an in-RAM double, so this only RECORDS
     * the request. It is deliberately not an oracle: the production contract is
     * that a `true` proves nothing (see [VaultDatabase.rekey]) and the outcome
     * must be re-proved with [VaultFactory.probeKey], so any test that wants to
     * assert re-key BEHAVIOUR has to run against real SQLCipher — see the Android
     * instrumented coverage in `DatabaseManagerTest`.
     */
    var rekeyedTo: ByteArray? = null
    override fun rekey(newDbKey: ByteArray): Boolean {
        rekeyedTo = newDbKey.copyOf()
        return true
    }
    override fun close() {}

    val meta = mutableMapOf<String, String>()
    override fun getMeta(key: String) = meta[key]
    override fun putMeta(key: String, value: String) { meta[key] = value }
    override fun deleteMeta(key: String) { meta.remove(key) }
    // Materialised snapshot, like both actuals — callers delete while iterating.
    override fun metaKeys(): List<String> = meta.keys.toList()
    // In-memory stub: no real transaction — just run the block (a throw propagates,
    // and these tests don't assert rollback of the in-RAM maps).
    override fun withTransaction(block: () -> Unit) { block() }
}

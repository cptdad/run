package com.vg.run

// ---------------------------------------------------------------------------
// VaultSnapshotIo — export/import between VaultDatabase and VaultSnapshot
// (docs/device-move.md, "Move to new device", area 2).
//
// Pure vault I/O: no relay, no sealing/chunking (MigrationBundle.kt), no
// orchestration (MoveManager.kt). Both directions run against the
// commonMain VaultDatabase interface so they are identical on Android and
// iOS by construction — only the interface's Android/iOS actuals differ.
// ---------------------------------------------------------------------------

object VaultSnapshotIo {

    /**
     * Reads every migratable record out of [db]: all contacts, EVERY inbox row
     * of every direction (not just the operational one — [VaultDatabase.getAllInboxIds]),
     * all groups and their members, and every `_meta` row that passes
     * [MoveMetaPolicy.isAllowedKey]. Read-only — never calls a mutating
     * [VaultDatabase] method, so the vault is unchanged by exporting it.
     */
    fun export(db: VaultDatabase): VaultSnapshot {
        val meta = db.metaKeys()
            .asSequence()
            .filter { MoveMetaPolicy.isAllowedKey(it) }
            .mapNotNull { key -> db.getMeta(key)?.let { value -> key to value } }
            .toMap()
        val groups = db.getAllGroups()
        return VaultSnapshot(
            contacts = db.getAllContacts(),
            inboxes = db.getAllInboxIds(),
            groups = groups,
            members = groups.flatMap { db.getGroupMembers(it.groupId) },
            meta = meta,
        )
    }

    /**
     * Imports [snapshot] into [db] inside ONE [VaultDatabase.withTransaction]:
     * every row lands together or (on a throw) none do.
     *
     * - Contacts are upserted with `+[counterJump]` on ALL THREE outbound
     *   counters — [ContactRecord.outboundCounter], [ContactRecord.outboundCtlCounter]
     *   and [ContactRecord.outboundGrpCounter] (D3, docs/device-move.md) — cheap
     *   insurance against anything the old phone sent between the snapshot and the
     *   freeze. Every channel needs it: the peer enforces strict-monotonic per
     *   channel, so a group counter the old phone already spent would be dropped
     *   as a replay and the message silently lost. Inbound counters and
     *   [ContactRecord.inboundEpoch] travel unchanged (they are baselines we
     *   learned from the peer, not values we spend).
     * - Inboxes, groups and members are upserted verbatim
     *   (`insertInboxId`/`insertGroup`/`insertGroupMember` are all INSERT-OR-REPLACE
     *   on both actuals, keyed by their primary key, so a contact already present
     *   — should not happen on a fresh vault, but this must be safe regardless —
     *   is replaced, never duplicated).
     * - `_meta` rows are written ONLY when [MoveMetaPolicy.isAllowedKey] passes —
     *   re-checked here rather than trusted from the caller, so a snapshot built
     *   by hand (or a future bug in [export]) can never smuggle a `vlt_*` or other
     *   denied key into the vault.
     * - [MoveMetaKeys.IMPORTED] is written LAST, strictly after every other write
     *   in the batch, so its presence is proof the whole import landed.
     *
     * Idempotent: if [db] already carries [MoveMetaKeys.IMPORTED] == [bundleId],
     * the transaction no-ops immediately — the counter jump is applied AT MOST
     * ONCE per bundle, so re-running an import (the documented partial-import
     * recovery path) converges instead of double-jumping counters.
     */
    fun import(db: VaultDatabase, snapshot: VaultSnapshot, counterJump: Long, bundleId: String) {
        db.withTransaction {
            if (db.getMeta(MoveMetaKeys.IMPORTED) == bundleId) return@withTransaction

            for (contact in snapshot.contacts) {
                db.insertContact(
                    contact.copy(
                        outboundCounter = contact.outboundCounter + counterJump,
                        outboundCtlCounter = contact.outboundCtlCounter + counterJump,
                        outboundGrpCounter = contact.outboundGrpCounter + counterJump,
                    )
                )
            }
            for (inbox in snapshot.inboxes) db.insertInboxId(inbox)
            for (group in snapshot.groups) db.insertGroup(group)
            for (member in snapshot.members) db.insertGroupMember(member)
            for ((key, value) in snapshot.meta) {
                if (MoveMetaPolicy.isAllowedKey(key)) db.putMeta(key, value)
            }

            // Must be the LAST write in the batch — its presence is what the
            // idempotency guard above (and the caller's "did it land" check) trusts.
            db.putMeta(MoveMetaKeys.IMPORTED, bundleId)
        }
    }
}

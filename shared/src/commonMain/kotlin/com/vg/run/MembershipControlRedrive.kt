package com.vg.run

import com.vg.run.GroupManager.Companion.KIND_LEAVE
import com.vg.run.GroupManager.Companion.KIND_ROSTER
import com.vg.run.GroupManager.Companion.MEMBERSHIP_CONTROL_TTL_SECONDS
import com.vg.run.GroupManager.Companion.isValidMemberId
import com.vg.run.GroupManager.Companion.membershipHash

// ---------------------------------------------------------------------------
// MembershipControlRedrive — the durable, ACK-GATED redrive of group membership
// control (roster / leave), split out of GroupManager. All state is `_meta`
// under [GroupMetaKeys.CTL_PEND_PREFIX] (`grp_ctl_pend:<groupId>:<contactId>`);
// there is no RAM state and no lock. The two mechanisms and their bounds are
// described at GroupManager's `MEMBERSHIP_CONTROL_TTL_SECONDS` and in
// docs/vault-relay-internals.md ("Group membership control is durable",
// "Delivery is confirmed END TO END"). Logs keep the "GroupManager" tag.
// ---------------------------------------------------------------------------
internal class MembershipControlRedrive(
    private val vault: VaultDatabase,
    private val clock: () -> Long,
    private val transport: (String) -> MessageManager?,
    private val rosterBody: (String) -> String?,
    private val leaveBody: (Long, String) -> String,
) {
    companion object {
        private const val TAG = "GroupManager"
        private const val MAX_CTL_REDRIVE_ATTEMPTS = 12
        private const val CTL_PEND_MAX_LIFETIME_MS = 7L * 24 * 60 * 60 * 1000
        private const val MAX_CTL_PEND_RECORDS = 256
        private const val MAX_CTL_ACK_RESENDS = 4
        private const val CTL_ACK_RESEND_INTERVAL_MS = 30L * 60 * 1000
    }

    /**
     * One `grp_ctl_pend:<groupId>:<contactId>` record.
     *
     * Wire format, 8 `|`-separated fields:
     * `<kind>|<epoch>|<hash>|<attempts>|<firstSeenMs>|<state u|a>|<lastSentMs>|<leaverMemberId>`
     *
     * LEGACY five-field records are still read:
     * they decode as state `u` (undelivered), `lastSentMs = firstSeenMs` and no
     * leaver memberId, i.e. exactly the behaviour they were written for, and the
     * next write migrates them to the 8-field shape. Anything else is refused, which
     * fails toward no obligation, never a send loop.
     *
     * [attempts] counts attempts IN THE CURRENT STATE, so the transition
     * `u → a` (the relay accepted the append) resets it: the two states have
     * different bounds and different cadences.
     */
    private class CtlObligation(
        val kind: String,
        val epoch: Long,
        val hash: String,
        val attempts: Int,
        val firstSeenMs: Long,
        // True once the relay ACCEPTED an append for this target and we are
        // waiting for END-TO-END proof (that member's own membershipHash) that it
        // actually converged. A 2xx alone is not that proof.
        val awaitingAck: Boolean,
        val lastSentMs: Long,
        // Our OWN memberId in the group this LEAVE announces. The group is deleted
        // locally before the obligation is written, so a redrive cannot re-derive it
        // — and without it the re-sent leave would carry no `"you"`, which is the
        // field that makes a stale leave harmless after a re-join. Empty for
        // rosters (the roster body is re-derived from live state).
        val leaverMemberId: String,
    ) {
        fun encode() =
            "$kind|$epoch|$hash|$attempts|$firstSeenMs|${if (awaitingAck) "a" else "u"}|$lastSentMs|$leaverMemberId"

        companion object {
            fun decode(raw: String?): CtlObligation? {
                val p = raw?.split('|') ?: return null
                if (p.size != 5 && p.size != 8) return null
                val kind = p[0]; if (kind != KIND_ROSTER && kind != KIND_LEAVE) return null
                val epoch = p[1].toLongOrNull() ?: return null
                val hash = p[2]; if (hash.isEmpty() || hash.length > 64) return null
                val attempts = p[3].toIntOrNull() ?: return null
                val first = p[4].toLongOrNull() ?: return null
                if (p.size == 5) {
                    return CtlObligation(kind, epoch, hash, attempts, first, awaitingAck = false, lastSentMs = first, leaverMemberId = "")
                }
                val awaiting = when (p[5]) { "a" -> true; "u" -> false; else -> return null }
                val lastSent = p[6].toLongOrNull() ?: return null
                val leaver = p[7]
                if (leaver.isNotEmpty() && !isValidMemberId(leaver)) return null
                return CtlObligation(kind, epoch, hash, attempts, first, awaiting, lastSent, leaver)
            }
        }
    }

    private fun ctlPendKey(groupId: String, contactId: String) = GroupMetaKeys.CTL_PEND_PREFIX + groupId + ":" + contactId

    /**
     * Persist one obligation per (group, contact) for a fan-out of [kind].
     *
     * A DELIVERED target keeps its obligation, in state AWAITING_ACK:
     * `HttpResult.isSuccess` means only that the relay took the blob; a relay that
     * answers 201 and discards would otherwise suppress a roster/leave forever at lower
     * cost than the 4xx/5xx veto the redrive closes, with no obligation left behind to
     * redrive. It is cleared only by `GroupManager.noteMembershipView` (via
     * [acknowledge]) observing that member's own membershipHash equal to ours — or
     * by the attempt/lifetime bounds.
     *
     * A pre-existing obligation keeps its FIRST-SEEN stamp (so a member that keeps
     * failing cannot be redriven forever by repeated membership churn — the 7-day
     * ceiling runs from the first miss, not from the latest roster), while a newer
     * roster still supersedes an older one's body: the roster is full state and is
     * re-derived at redrive time anyway.
     */
    fun record(
        groupId: String,
        kind: String,
        epoch: Long,
        hash: String,
        failed: List<String>,
        delivered: List<String>,
        leaverMemberId: String = "",
    ) {
        try {
            val now = clock()
            for (c in delivered) {
                if (c in failed) continue
                val key = ctlPendKey(groupId, c)
                val prior = CtlObligation.decode(vault.getMeta(key))
                vault.putMeta(
                    key,
                    CtlObligation(
                        kind, epoch, hash, attempts = 0, firstSeenMs = prior?.firstSeenMs ?: now,
                        awaitingAck = true, lastSentMs = now, leaverMemberId = leaverMemberId,
                    ).encode(),
                )
            }
            for (c in failed) {
                val key = ctlPendKey(groupId, c)
                val prior = CtlObligation.decode(vault.getMeta(key))
                // Attempts carry over only WITHIN the undelivered state (see the
                // CtlObligation kdoc).
                val attempts = if (prior != null && !prior.awaitingAck) prior.attempts else 0
                vault.putMeta(
                    key,
                    CtlObligation(
                        kind, epoch, hash, attempts, firstSeenMs = prior?.firstSeenMs ?: now,
                        awaitingAck = false, lastSentMs = now, leaverMemberId = leaverMemberId,
                    ).encode(),
                )
            }
            if (failed.isNotEmpty()) {
                platformLogWarn(TAG, "membership control '$kind' undelivered to ${failed.size} member(s) — recorded for redrive")
            }
            // One `_meta` key scan, and only when this call actually wrote a record.
            if (failed.isNotEmpty() || delivered.isNotEmpty()) trim()
        } catch (e: Exception) {
            platformLogWarn(TAG, "recording undelivered membership control failed: ${e::class.simpleName}")
        }
    }

    /**
     * Bound the obligation set beyond [MAX_CTL_PEND_RECORDS]. AWAITING_ACK records
     * are evicted BEFORE undelivered ones (a delivered-but-unacked copy is already
     * on the relay for 7 days; an undelivered one has never been sent at all), and
     * within each class the oldest goes first.
     */
    private fun trim() {
        val all = vault.metaKeys().filter { it.startsWith(GroupMetaKeys.CTL_PEND_PREFIX) }
        if (all.size <= MAX_CTL_PEND_RECORDS) return
        all.map { it to CtlObligation.decode(vault.getMeta(it)) }
            .sortedWith(
                compareBy(
                    { if (it.second?.awaitingAck != false) 0 else 1 },
                    { it.second?.firstSeenMs ?: 0L },
                )
            )
            .take(all.size - MAX_CTL_PEND_RECORDS)
            .forEach { vault.deleteMeta(it.first) }
    }

    // End-to-end acknowledgement: [contactId] was seen carrying OUR membership hash
    // for [groupId] ([GroupManager]'s `noteMembershipView`), so its obligation, if
    // any, is done.
    fun acknowledge(groupId: String, contactId: String) {
        val key = ctlPendKey(groupId, contactId)
        if (vault.getMeta(key) != null) {
            vault.deleteMeta(key)
            platformLog(TAG, "membership control acknowledged end-to-end by one member")
        }
    }

    /**
     * Redrive every persisted membership obligation once, bounded by attempts, a
     * per-state cadence and an absolute lifetime. Runs from the control sweep
     * (SessionManagers, through `GroupManager.redriveUndeliveredMembershipControl`),
     * i.e. only with a live transport. A roster is re-derived from CURRENT vault
     * state (superset semantics: the latest roster subsumes the missed one); a
     * leave re-sends the stored epoch + our old memberId, since the group is
     * already gone locally. An obligation whose contact or (for rosters)
     * group/admin role is gone is dropped — there is nothing left to say.
     *
     * An AWAITING_ACK record (the relay took the append but the member has never
     * since echoed our membership hash) is re-sent on the SLOW
     * [MembershipControlRedrive.CTL_ACK_RESEND_INTERVAL_MS] cadence and is bounded
     * by [MembershipControlRedrive.MAX_CTL_ACK_RESENDS], so an honest member that
     * simply has not spoken costs a handful of appends rather than a beacon.
     */
    fun redrive() {
        val mgr = transport("membership redrive") ?: return
        val keys = try { vault.metaKeys().filter { it.startsWith(GroupMetaKeys.CTL_PEND_PREFIX) } } catch (e: Exception) {
            platformLogWarn(TAG, "membership redrive: meta scan failed: ${e::class.simpleName}"); return
        }
        if (keys.isEmpty()) return
        val now = clock()
        var sent = 0
        // Secure shuffle, like the sibling loops ([UnconvergedMembers.takeDue],
        // [GroupInboxBackfillArming.runDue]): the relay observes the send order.
        for (key in keys.secureShuffled()) {
            val rest = key.removePrefix(GroupMetaKeys.CTL_PEND_PREFIX)
            val sep = rest.indexOf(':')
            if (sep <= 0 || sep == rest.length - 1) { runCatching { vault.deleteMeta(key) }; continue }
            val groupId = rest.substring(0, sep); val contactId = rest.substring(sep + 1)
            val ob = CtlObligation.decode(vault.getMeta(key))
            val maxAttempts = if (ob != null && ob.awaitingAck) MAX_CTL_ACK_RESENDS else MAX_CTL_REDRIVE_ATTEMPTS
            if (ob == null || now - ob.firstSeenMs > CTL_PEND_MAX_LIFETIME_MS || ob.attempts >= maxAttempts) {
                if (ob != null && ob.attempts >= maxAttempts) platformLogWarn(TAG, "membership redrive exhausted for one member — dropping")
                runCatching { vault.deleteMeta(key) }; continue
            }
            // A delivered-but-unacked copy is already sitting on the relay for
            // 7 days — re-send it slowly, not on every sweep. Checked BEFORE the
            // contact lookup: with ack-gating there is one record per (group, member) after
            // every roster, and this loop runs on a cadence as fast as 2.5 s, so the
            // steady state must cost ONE keyed `_meta` read per record and no more.
            // (A contact that is gone has its records purged by
            // [isGroupMetaResidueForContact] on delete; the check below is the backstop
            // for a record that outlived one, and it costs nothing to defer.)
            if (ob.awaitingAck && now >= ob.lastSentMs && now - ob.lastSentMs < CTL_ACK_RESEND_INTERVAL_MS) continue
            if (vault.getContact(contactId) == null) { runCatching { vault.deleteMeta(key) }; continue }
            val send: Pair<String, String>? = when (ob.kind) {   // body to hash
                KIND_ROSTER -> {
                    val g = vault.getGroup(groupId)
                    if (g == null || !g.isAdmin) null
                    else rosterBody(groupId)?.let { body ->
                        val members = vault.getGroupMembers(groupId)
                        body to membershipHash(groupId, g.epoch, members.map { it.memberId })
                    }
                }
                // A LEAVE obligation may only be redriven
                // while we are genuinely OUT of the group. Without this check, a
                // leave whose fan-out failed and was then followed by a RE-JOIN of
                // the same groupId (the admin re-invites; the eclipse warning does
                // not fire because the inviter IS the tombstoned admin-of-record)
                // would later evict us from the group we just joined, on every peer
                // that missed the original. `acceptInvite` also purges the group's
                // obligations outright; this is the belt to that braces, because the
                // obligation may name a peer whose invite arrived by another route.
                KIND_LEAVE -> if (vault.getGroup(groupId) != null) null else leaveBody(ob.epoch, ob.leaverMemberId) to ob.hash
                else -> null
            }
            if (send == null) { runCatching { vault.deleteMeta(key) }; continue }
            if (sent > 0) sleepInterSendJitter()
            sent++
            val ok = try {
                mgr.sendGroupControl(contactId, groupId, ob.kind, send.first, send.second, noPush = true, ttlSeconds = MEMBERSHIP_CONTROL_TTL_SECONDS)
            } catch (e: Exception) {
                platformLogWarn(TAG, "membership redrive send threw: ${e::class.simpleName}"); false
            }
            try {
                when {
                    // A LEAVE the relay took is done: nothing can acknowledge it
                    // (the group is gone locally), so an AWAITING-ACK record would
                    // only keep the left group's roster residue in `_meta`.
                    ok && ob.kind == KIND_LEAVE -> {
                        vault.deleteMeta(key)
                        platformLog(TAG, "membership control 'leave' accepted on a redrive — obligation closed")
                    }
                    // Relay took it for the FIRST time: stop re-sending every sweep,
                    // start waiting for the member's own hash. The record is
                    // NOT deleted — a 2xx is not delivery.
                    ok && !ob.awaitingAck -> {
                        vault.putMeta(key, CtlObligation(ob.kind, ob.epoch, ob.hash, 0, ob.firstSeenMs, awaitingAck = true, lastSentMs = now, leaverMemberId = ob.leaverMemberId).encode())
                        platformLog(TAG, "membership control '${ob.kind}' accepted on a redrive — awaiting the member's acknowledgement")
                    }
                    ok -> {
                        val next = ob.attempts + 1
                        if (next >= MAX_CTL_ACK_RESENDS) {
                            vault.deleteMeta(key)
                            platformLogWarn(TAG, "membership control never acknowledged by one member — giving up")
                        } else {
                            vault.putMeta(key, CtlObligation(ob.kind, ob.epoch, ob.hash, next, ob.firstSeenMs, awaitingAck = true, lastSentMs = now, leaverMemberId = ob.leaverMemberId).encode())
                        }
                    }
                    ob.attempts + 1 >= maxAttempts -> {
                        vault.deleteMeta(key); platformLogWarn(TAG, "membership redrive exhausted for one member — dropping")
                    }
                    else -> vault.putMeta(key, CtlObligation(ob.kind, ob.epoch, ob.hash, ob.attempts + 1, ob.firstSeenMs, ob.awaitingAck, lastSentMs = now, leaverMemberId = ob.leaverMemberId).encode())
                }
            } catch (e: Exception) {
                platformLogWarn(TAG, "membership redrive bookkeeping failed: ${e::class.simpleName}")
            }
        }
    }

    /**
     * Drop every `grp_ctl_pend:<groupId>:*` obligation for [groupId].
     *
     * Called when this device (re)JOINS the group — a LEAVE obligation recorded
     * before the re-join is now a lie that would kick us back out on every peer that
     * missed the original, and a ROSTER obligation from a previous incarnation
     * belongs to an epoch/member set that no longer exists. `deleteGroup` already
     * purges the same prefix through [isGroupMetaResidueForGroup], but `leaveGroup`
     * writes its obligation AFTER the delete, so only this purge clears it on the
     * way back in. Never throws — a failed purge costs the stale-leave
     * guard in [redrive], not the join.
     */
    fun purgeForGroup(groupId: String) {
        try {
            val prefix = GroupMetaKeys.CTL_PEND_PREFIX + groupId + ":"
            for (key in vault.metaKeys()) if (key.startsWith(prefix)) vault.deleteMeta(key)
        } catch (e: Exception) {
            platformLogWarn(TAG, "purging stale membership obligations failed: ${e::class.simpleName}")
        }
    }
}

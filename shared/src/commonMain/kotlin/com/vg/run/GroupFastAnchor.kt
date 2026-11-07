package com.vg.run

import com.vg.run.GroupManager.Companion.MAX_UNRESOLVED_ANCHORS
import com.vg.run.GroupManager.Companion.UNRESOLVED_FAST_EPISODE_MAX_MS
import com.vg.run.GroupManager.Companion.UNRESOLVED_MEMBER_FAST_WINDOW_MS

// ---------------------------------------------------------------------------
// GroupFastAnchor — when this device last applied a membership change to group
// G; keeps the fast control cadence while G still has an unresolved member.
//
// The RECEIVER-side cadence hint: groupId -> the clock of the last MEMBERSHIP
// control this device applied for that group, plus groupId -> the clock of the
// FIRST anchor of the current episode (same lock, same lifetime, same eviction).
// Read by GroupManager's `hasUnresolvedMembers` and `transferAdmin` (through
// `joinPending`), so a convergence chain that is still moving keeps the fast
// cadence even when the unresolved slot's persisted `addedAt` is older than
// [UNRESOLVED_MEMBER_FAST_WINDOW_MS].
//
// RAM-only and session-scoped ON PURPOSE, and that is the whole never-resolvable
// pin: a vault-persisted anchor would survive relaunch and could be re-armed
// forever by a peer, while an in-RAM one costs at most ONE idle interval after a
// session starts — the first membership control to land re-anchors it. Bounded
// by [MAX_UNRESOLVED_ANCHORS] (oldest evicted); groups are few, and an evicted
// anchor degrades to the `addedAt`-only behaviour, never to a wrong "fast".
//
// Its own lock: `hasUnresolvedMembers` runs on the platform poll loop while the
// writers run on the control-sweep thread, and SyncLock is non-reentrant on iOS,
// so it shares no lock with [UnconvergedMembers]. [groupExists] (a vault read) and
// the clock are read OUTSIDE the lock. Cleared by GroupManager.scrubInMemory.
// ---------------------------------------------------------------------------
internal class GroupFastAnchor(
    private val clock: () -> Long,
    private val groupExists: (String) -> Boolean,
) {
    private val lock = SyncLock()
    private val anchorMs = mutableMapOf<String, Long>()
    private val episodeStartMs = mutableMapOf<String, Long>()

    /**
     * Re-open the unresolved-member fast window for [groupId]: called when this
     * device APPLIES a membership control (roster / leave / invite / join) that
     * actually changed the group's convergence fingerprint, or completes a local
     * join — exactly the events after which another resolution hop is expected.
     *
     * Deliberately NOT called for every drained blob, nor for every membership-KIND
     * blob, for the same reason the convergence window is not armed off one: a
     * chatty peer must not be able to hold the device on the 2.5–5 s cadence.
     * `GroupManager.ingest` calls this only when the handler moved the fingerprint
     * (epoch / admin / member count / resolved count); a dropped, stale, malformed
     * or unchanged re-applied control re-anchors nothing. Each call buys at most
     * [UNRESOLVED_MEMBER_FAST_WINDOW_MS], and only while a group actually still HAS
     * an unresolved member — a fully resolved device reads the anchor and ignores it.
     *
     * **Episode cap (defence in depth, the same shape as the control-poll episode
     * cap):** a stream of APPLIED changes — an admin flapping the epoch is one
     * applied roster per blob — would otherwise re-anchor forever. Anchor-driven
     * fast time is therefore bounded per group to [UNRESOLVED_FAST_EPISODE_MAX_MS]
     * from the FIRST anchor of an episode ([anchor] returns 0 past it, i.e. the
     * pre-anchor `addedAt`-only behaviour). A new episode starts only after a
     * genuinely quiet gap — no anchor for a whole [UNRESOLVED_MEMBER_FAST_WINDOW_MS]
     * — never on an anchor inside the current one. `transferAdmin`'s
     * join-in-flight guard reads the same bounded anchor, so a pinging co-member
     * cannot hold `joinPending` open past the window.
     *
     * **Gated on the group EXISTING locally**, which is not cosmetic: without it a
     * peer could churn the bounded map with membership kinds for groupIds we never
     * joined and evict a real group's anchor. (An eviction only degrades to the
     * `addedAt`-only behaviour, never to a wrong "still converging" — but there is
     * no reason to hand a peer the lever.) The one caller that legitimately runs
     * before a group exists is `acceptInvite`, which calls this AFTER its commit.
     */
    fun note(groupId: String) {
        if (!groupExists(groupId)) return
        val now = clock()
        lock.withLock {
            if (groupId !in anchorMs && anchorMs.size >= MAX_UNRESOLVED_ANCHORS) {
                anchorMs.minByOrNull { it.value }?.key?.let {
                    anchorMs.remove(it)
                    episodeStartMs.remove(it)
                }
            }
            val last = anchorMs[groupId]
            val episode = episodeStartMs[groupId]
            // A new episode only after the previous anchor's whole window lapsed
            // (or on a backward clock step, which fails toward FAST everywhere here).
            val quiet = last == null || now < last || now - last >= UNRESOLVED_MEMBER_FAST_WINDOW_MS
            if (episode == null || quiet || now < episode) episodeStartMs[groupId] = now
            anchorMs[groupId] = now
        }
    }

    /**
     * The last membership-event clock for [groupId], or 0 when there is none — or
     * when the current episode has run past [UNRESOLVED_FAST_EPISODE_MAX_MS], in
     * which case the anchor contributes nothing and the fast-window predicates fall
     * back to the persisted `addedAt` alone. A backward clock step keeps the anchor
     * (fail toward FAST, as the subtraction in `hasUnresolvedMembers` does).
     */
    fun anchor(groupId: String): Long = lock.withLock {
        val anchor = anchorMs[groupId] ?: return@withLock 0L
        val episode = episodeStartMs[groupId] ?: anchor
        val now = clock()
        if (now < episode) anchor
        else if (now - episode >= UNRESOLVED_FAST_EPISODE_MAX_MS) 0L
        else anchor
    }

    fun scrub() = lock.withLock { anchorMs.clear(); episodeStartMs.clear() }
}

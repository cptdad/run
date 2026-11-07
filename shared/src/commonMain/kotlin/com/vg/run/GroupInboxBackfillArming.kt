package com.vg.run

// ---------------------------------------------------------------------------
// Arming the GROUP-INBOX BACKFILL.
//
// Every pairing made before the third inbox existed has no group inbox, so
// without a backfill those pairings would stay on the legacy route forever and
// the invariant would have a permanent, pairing-shaped hole. The WORK
// (a PoW mint + one control append) lives in
// [MessageManager.maybeBackfillGroupInbox] behind a durable 24 h / 4-attempt
// throttle; this is the arming half, and it is deliberately narrow:
//
//  - only contacts we SHARE A GROUP WITH (or hold a parked invite from) — a
//    pairing that will never carry a group text needs no group inbox;
//  - at most [MAX_GROUP_BACKFILLS_PER_SWEEP] per control sweep, because a mint
//    is a 1–5 s CPU grind that would otherwise stall the sweep behind it;
//  - never at connect time (two PoW mints on one cold circuit were observed to
//    fail for minutes, and the connect wait must stay short) — the sweep only
//    runs this once [MessageManager.hasCompletedRelayRoundTrip] is latched,
//    which that method re-checks for itself.
//
// Armed by MEMBERSHIP EVENTS (a roster/join/leave/invite applied, a group
// created, a member added, an invite accepted) and ONCE per session for the
// groups that already exist — that second arm is what converges the pairings
// formed before the third inbox existed that never see another membership event. It is not
// a fast-window-style beacon: the durable throttle means a peer that never converges
// costs four appends over four days and then nothing at all, forever.
//
// Split out of GroupManager: RAM-only arming state under its own lock. The
// `grp-ann/` key and its durable throttle stay in MessageManager
// (`groupBackfillKey`, `ratchetMetaKeysForContact`). Logs keep the
// "GroupManager" tag.
// ---------------------------------------------------------------------------
internal class GroupInboxBackfillArming(
    private val primeInFlight: () -> Boolean,
    private val groupSharingContacts: (Set<String>) -> Set<String>,
    private val blocked: () -> Set<String>,
    private val pendingInviters: () -> List<String>,
    private val groupMemberContacts: (String) -> List<String?>,
) {
    companion object {
        private const val TAG = "GroupManager"

        /** At most one group-inbox backfill mint per control sweep — a PoW
         *  grind is 1–5 s of CPU and the sweep is what delivers invites and
         *  rosters. */
        private const val MAX_GROUP_BACKFILLS_PER_SWEEP = 1

        /** Bound on the armed backfill set, so a peer that keeps inviting us
         *  to fresh groupIds cannot grow it. An evicted entry is re-armed by the
         *  next membership event or the next session; it never degrades into an
         *  attempt that should not happen. */
        private const val MAX_GROUP_BACKFILL_ARMED = 64
    }

    private val lock = SyncLock()
    /** Contacts armed for a group-inbox backfill attempt, consumed by the control
     *  sweep. RAM-only and session-scoped: the DURABLE half is the per-contact
     *  throttle, so losing this set costs at most one deferred attempt. */
    private val armed = LinkedHashSet<String>()
    private var sessionArmed = false
    /** True once a control sweep has reached the backfill step, so the session's
     *  FIRST sweep — the one inside the connect wait — never mints. */
    private var sweptOnce = false

    /** Arms [contactId] for one throttled group-inbox backfill attempt. */
    fun arm(contactId: String) = lock.withLock {
        if (contactId.isEmpty() || contactId in armed) return@withLock
        while (armed.size >= MAX_GROUP_BACKFILL_ARMED) {
            armed.remove(armed.iterator().next())
        }
        armed.add(contactId)
        Unit
    }

    /** Arms every resolved member of [groupId] — the membership-event hook. Cheap
     *  local reads; never throws. */
    fun armForGroup(groupId: String) {
        try {
            for (contactId in groupMemberContacts(groupId)) contactId?.let { arm(it) }
        } catch (e: Exception) {
            platformLogWarn(TAG, "group backfill arming failed: ${e::class.simpleName}")
        }
    }

    /**
     * The ONCE-PER-SESSION arm over the groups that already exist.
     *
     * Without it, a group formed before the third inbox existed whose membership never changes
     * again would never produce an event, so its pairings would sit on the legacy
     * route for good — the feature would silently not converge exactly the vaults
     * it was written for. It is bounded by the same durable throttle as every other
     * arm, so the cost of a permanently un-upgradeable peer is four appends over
     * four days and then silence.
     */
    fun armOnceForSession() {
        lock.withLock {
            if (sessionArmed) return
            sessionArmed = true
        }
        // Blocked-filtered like every other use of the predicate: a block severs
        // the relationship, so it must not produce a mint + an announce either.
        for (contactId in groupSharingContacts(blocked())) arm(contactId)
        // …and the invite we have not answered yet: accepting it makes that inviter
        // a co-member, and the group texts start immediately after.
        try {
            for (inviter in pendingInviters()) arm(inviter)
        } catch (_: Exception) { /* best effort */ }
    }

    /**
     * Runs at most [MAX_GROUP_BACKFILLS_PER_SWEEP] armed backfill attempts, in
     * CSPRNG-shuffled order so the relay sees no stable per-contact sequence.
     *
     * A contact is DISARMED the moment it is attempted, whatever the outcome: the
     * durable throttle is the retry policy, and re-queueing here would turn a
     * refused mint into a per-sweep loop. Never throws — a backfill failure must
     * not cost the sweep the invites and rosters it exists to deliver.
     */
    fun runDue(mgr: MessageManager) {
        // NEVER inside the connect wait. A mint is a 1–5 s grind plus two relay
        // round trips on the same circuit the connect-time prime is using, and the
        // contact list stays hidden until that prime settles (ConnectReveal). Two
        // independent gates, both cheap: the prime must not be in flight, and this
        // must not be the session's FIRST sweep (which runs 3–7 s after the
        // transport wires, i.e. squarely inside the connect wait).
        // [MessageManager.maybeBackfillGroupInbox] additionally
        // refuses until the relay has answered this transport at least once.
        if (primeInFlight()) return
        val firstSweep = lock.withLock {
            val first = !sweptOnce
            sweptOnce = true
            first
        }
        if (firstSweep) return
        val due = lock.withLock {
            if (armed.isEmpty()) return
            val picked = armed.secureShuffled()
                .take(MAX_GROUP_BACKFILLS_PER_SWEEP)
            for (c in picked) armed.remove(c)
            picked
        }
        for (contactId in due) {
            val outcome = try {
                mgr.maybeBackfillGroupInbox(contactId)
            } catch (e: Exception) {
                platformLogWarn(TAG, "group inbox backfill failed: ${e::class.simpleName}")
                continue
            }
            if (outcome == MessageManager.GroupBackfillOutcome.ANNOUNCED) {
                platformLog(TAG, "group inbox backfilled for one contact")
            }
        }
    }

    // Session end (GroupManager.scrubInMemory): the armed set is contactIds. The
    // DURABLE throttle is untouched, so a fresh session re-arms and the bound holds.
    fun scrub() = lock.withLock {
        armed.clear()
        sessionArmed = false
        sweptOnce = false
    }
}

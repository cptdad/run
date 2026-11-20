package com.vg.run

/**
 * What one steady-state unread sweep tells the CONTACT dots, and the one rule both
 * platforms publish it by: `shown = sweep.applyTo(shown)`, merged at publish time
 * against the map the contact list is showing right now (Android inside the
 * session-epoch check, iOS inside the `MainActor.run` block).
 *
 * [counts] is the sweep's arithmetic for every contact whose text-inbox peek the
 * relay ANSWERED ([GroupUnreadTally.contactCountsFrom]); a contact absent from it
 * has no dot. [carry] is the contacts whose peek this sweep could NOT answer (a Tor
 * timeout, a 429, a cap-rotation 404) — or every existing contact when there was no
 * transport at all — and for those an unknown answer KEEPS the dot already shown
 * instead of blanking it. Unknown is never zero, the rule the connect-time prime
 * and the group dot already follow.
 *
 * Why a stale dot cannot stick:
 *  - only a value STILL in [current] is carried, so a carried contact whose
 *    conversation the user opened (both platforms' `markContactRead` drop the key)
 *    is never brought back. (A peek that ANSWERED N > 0 before the open still
 *    republishes that dot until the next sweep, as before this rule.)
 *  - a deleted or blocked contact is not swept, so it is never in [carry];
 *  - [carry] holds a contact for at most [GroupManager.MAX_UNKNOWN_UNREAD_CARRY]
 *    consecutive unknown sweeps (an inbox that never answers again stops holding a
 *    dot), and any answered peek, a genuine 0 included, replaces the value;
 *  - a move-frozen device carries nothing.
 */
class ContactUnreadSweep internal constructor(
    val counts: Map<String, Int>,
    val carry: Set<String>,
) {
    /**
     * The contact-dot map to show after this sweep, given the one shown before it.
     * A carried contact keeps the LARGER of its shown value and its fresh count (the
     * fresh count of an unknown peek is at most its unseen-screenshot-notice term).
     */
    fun applyTo(current: Map<String, Int>): Map<String, Int> {
        if (carry.isEmpty()) return counts
        val out = counts.toMutableMap()
        for (contactId in carry) {
            val shown = current[contactId] ?: continue
            if (shown > (out[contactId] ?: 0)) out[contactId] = shown
        }
        return out
    }
}

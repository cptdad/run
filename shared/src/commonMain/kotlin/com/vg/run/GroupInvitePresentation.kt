package com.vg.run

/**
 * Which pending consent prompt (group invitation OR referral offer) the contact
 * list presents, and which ones it shows as a row instead. The rule is id-based and
 * kind-agnostic: each platform keeps ONE deferred set per kind (group ids / introIds)
 * and calls these functions with that kind's ids. (The name predates the referral
 * offer, which reuses it unchanged; the cross-kind precedence, offers first, lives
 * in `consentToShow` / the iOS `syncGroupInvites`.)
 *
 * Both dialogs are NON-BLOCKING: besides Join|Approve / Decline they offer "Later",
 * which closes the dialog without deciding. The invite / offer stays pending in
 * [GroupManager] / [ReferralManager]; this rule only decides how the UI surfaces it.
 * (Referral offers pass busy=false to [toAutoPresent] — an accept in flight keeps
 * the "Connecting…" dialog on screen — and the real busy flag to [rowIds].)
 *
 * Pure and id-based so BOTH platforms call the one rule (Android:
 * `ContactListScreen` via `RunViewModel`; iOS: `ContactListView` via `AppState`).
 * The deferred set ("Later" was tapped) is RAM-only session state owned by each
 * platform's session object and cleared at lock / teardown / wipe, so a new session
 * presents each pending invite once again.
 *
 * Ids are passed as plain lists so the Swift side needs no Kotlin collection types.
 */
object GroupInvitePresentation {

    /**
     * The group id whose dialog should be on screen now, or null for none.
     *
     *  * [busy] (a join/decline is in flight): nothing new is presented; the
     *    current [shownId] is returned unchanged (null when none).
     *  * An invite already on screen STAYS on screen while anything is pending
     *    (the dialog never swaps its subject under a reading user's finger), and
     *    is dismissed once nothing is pending (accepted / declined / withdrawn).
     *  * Otherwise the first pending invite NOT in [deferredIds] is presented, so
     *    deferring one lets the next present, and a deferred invite never loops.
     */
    fun toAutoPresent(pendingIds: List<String>, deferredIds: List<String>, shownId: String?, busy: Boolean): String? {
        if (busy) return shownId
        if (shownId != null) return if (pendingIds.isEmpty()) null else shownId
        return pendingIds.firstOrNull { it !in deferredIds }
    }

    /**
     * The invites shown as "Invitation: ..." rows in the groups area, in pending
     * order: those pending, deferred with Later, and not currently in a dialog.
     * An invite that is neither deferred nor shown is about to be auto-presented
     * by [toAutoPresent] and gets no row (no one-frame flash on first sight).
     * While [busy] no rows are shown, so the invite being joined does not flash
     * back as a row between the tap and the vault write landing.
     */
    fun rowIds(pendingIds: List<String>, deferredIds: List<String>, shownId: String?, busy: Boolean): List<String> {
        if (busy) return emptyList()
        return pendingIds.filter { it != shownId && it in deferredIds }
    }

    /**
     * [deferredIds] restricted to invites still pending, so a withdrawn / declined
     * invite's id does not linger and a later re-invite of the same group presents
     * afresh. Callers apply it only after a SUCCESSFUL read of the pending list.
     */
    fun pruneDeferred(pendingIds: List<String>, deferredIds: Set<String>): Set<String> =
        deferredIds.filterTo(HashSet()) { it in pendingIds }
}

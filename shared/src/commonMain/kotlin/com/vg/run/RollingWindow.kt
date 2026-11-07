package com.vg.run

/**
 * The persisted rolling-window rate limit shared by `GroupManager.inviteAllowed`
 * and `ReferralManager.offerAllowed`. Pure: each caller keeps its own `_meta`
 * read/write and its own error semantics (Group lets a store throw out to
 * `handleControl`; Referral degrades to RAM-only), so only the arithmetic and
 * the persisted string format live here.
 *
 * The stored value is a comma-joined list of millisecond stamps. A stamp
 * outside `[now - windowMs, now]` is discarded — including one in the FUTURE
 * (the clock jumped back), so it can neither wedge the window open nor closed.
 */
internal object RollingWindow {
    /**
     * [allowed] and the exact string the caller must persist: the pruned list
     * on a deny (no new stamp is charged), the pruned list plus `now` on an allow.
     */
    data class Admission(val allowed: Boolean, val persist: String)

    fun admit(stored: String?, now: Long, windowMs: Long, max: Int): Admission {
        val recent = inWindow(stored, now, windowMs)
        return if (recent.size >= max) {
            Admission(allowed = false, persist = recent.joinToString(","))
        } else {
            Admission(allowed = true, persist = (recent + now).joinToString(","))
        }
    }

    // True when no stamp in [stored] lies inside `[now - windowMs, now]`, i.e. the
    // row admits exactly as an absent row would. The same filter as [admit], so a
    // caller may delete such a row without changing any admission.
    fun isSpent(stored: String?, now: Long, windowMs: Long): Boolean =
        inWindow(stored, now, windowMs).isEmpty()

    // The stamps of [stored] inside `[now - windowMs, now]`, in stored order — the
    // one filter both [admit] and [isSpent] apply.
    private fun inWindow(stored: String?, now: Long, windowMs: Long): List<Long> =
        (stored ?: "")
            .split(',')
            .mapNotNull { it.toLongOrNull() }
            .filter { it in (now - windowMs)..now }
}

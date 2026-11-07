package com.vg.run

import android.content.Context

// ---------------------------------------------------------------------------
// SecurePrefs — formerly held CryptoProvider-encrypted background-poll state
// (inbox IDs + read-secrets) for the pre-capability ("X-Read-Secret") relay
// protocol. That protocol was replaced — capabilities now live in the vault DB
// (InboxIdRecord.cap) — so the store/load methods were dead and were removed.
//
// Since 2026-08-11 the file carries the push-deregistration pending flag
// below. It is a BARE BOOLEAN by design (it replaced a
// plaintext-domain (inboxId, readCap) push mirror): never store inbox ids or read capabilities here. The sweep that
// consumes the flag re-enumerates allPushableInboxes() from the OPEN vault
// instead (RunViewModel.sweepPendingPushDeregistration). clear() keeps
// deleting the whole file on every wipe path (WipeRoutine), which also
// disarms the flag — a wiped install has no vault left for the sweep to
// enumerate, so a surviving flag would be unclearable dead state.
//
// The in-app store-review counters further down used to be the same shape
// (non-sensitive, non-vault, swept for free by clear()) but were moved into
// the encrypted vault's `_meta` table: an AFU (filesystem-image)
// extraction could read the plaintext first-unlock timestamp and unlock count
// straight off disk, no vault credential needed. What remains here is LEGACY-ONLY, kept solely to migrate
// a pre-fix install's history into the vault once — see their own doc.
// ---------------------------------------------------------------------------

object SecurePrefs {

    private const val PREFS_NAME = "secure_prefs"

    /**
     * "A Settings opt-out's relay-side `DELETE /inbox/{id}/push` has not been
     * confirmed for every inbound-text inbox yet." Armed BEFORE the first
     * DELETE attempt of the opt-out path
     * ([RunViewModel.unregisterPushInBackground]); cleared only once a full
     * pass succeeds for EVERY ref — in-session, or by the later control-poll
     * sweep ([RunViewModel.sweepPendingPushDeregistration]). The wipe paths
     * never arm it (they delete this file instead — see the header). Mirrors
     * iOS `PushDeregPending.storageKey` ("pushDeregPending", AppState.swift).
     */
    private const val KEY_PUSH_DEREG_PENDING = "push_dereg_pending"

    fun isPushDeregPending(context: Context): Boolean =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .getBoolean(KEY_PUSH_DEREG_PENDING, false)

    /**
     * commit(), not apply() (PrefsApplySourceGuardTest): the arm happens
     * moments before paths on which the process routinely dies — this app
     * tears the whole session down on background
     * (`MainActivity.onStop` → `finishAndRemoveTask()`) while the opt-out's
     * Tor DELETE can still be tens of seconds from settling — and an apply()
     * lost to that death is exactly the silent leak this flag exists to catch.
     * Callers are already on Dispatchers.IO.
     *
     * Clearing REMOVES the key (absence reads false) and never touches a file
     * that does not hold it — so a clear that lands after a wipe deleted
     * secure_prefs cannot mint a fresh, freshly-dated prefs file (the same
     * post-wipe-artifact class ProcessWipeLatch guards elsewhere).
     */
    fun setPushDeregPending(context: Context, pending: Boolean) {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        if (pending) {
            prefs.edit().putBoolean(KEY_PUSH_DEREG_PENDING, true).commit()
        } else if (prefs.contains(KEY_PUSH_DEREG_PENDING)) {
            prefs.edit().remove(KEY_PUSH_DEREG_PENDING).commit()
        }
    }

    // -------------------------------------------------------------------
    // LEGACY plaintext store for the privacy-respecting in-app store-review
    // nudge (ReviewPromptPolicy.kt, commonMain — the pure decision function).
    // These counters now live in the
    // encrypted vault's `_meta` table (`REVIEW_PROMPT_META_KEY`,
    // `readReviewPromptState`/`recordReviewPromptUnlock`/`markReviewPromptShown`
    // in ReviewPromptPolicy.kt) — an AFU extraction could previously read
    // these three keys straight off disk without the vault credential.
    // What remains here exists ONLY to migrate an existing pre-fix install's
    // history into the vault once, on its first unlock after upgrading — see
    // [readLegacyReviewCounters] / [clearLegacyReviewCounters] and their
    // caller, RunViewModel.onVaultOpened. `clear()` still deletes the whole
    // file (and therefore these keys too) on every wipe path, same as
    // before — no separate wipe plumbing needed for the legacy remnants.
    // Do not add new writers here; new state belongs in the vault.
    // Mirrors iOS `ReviewPromptStore` (AppState.swift), same legacy role.
    // -------------------------------------------------------------------
    private const val KEY_REVIEW_FIRST_UNLOCK_AT = "review_first_unlock_at"
    private const val KEY_REVIEW_UNLOCK_COUNT = "review_unlock_count"
    private const val KEY_REVIEW_PROMPTED = "review_prompted"

    /** Legacy (firstUnlockAt, unlockCount, alreadyPrompted) snapshot — absent
     *  keys read as a fresh install (null / 0 / false), same defaults
     *  [ReviewPromptVaultState] expects. Used only for the one-time
     *  migration into the vault. */
    data class LegacyReviewCounters(
        val firstUnlockAt: Long?,
        val unlockCount: Int,
        val alreadyPrompted: Boolean,
    )

    /** Reads the legacy snapshot without side effects — safe to call even
     *  when no legacy keys exist (a fresh install or an already-migrated one). */
    fun readLegacyReviewCounters(context: Context): LegacyReviewCounters {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return LegacyReviewCounters(
            firstUnlockAt = if (prefs.contains(KEY_REVIEW_FIRST_UNLOCK_AT)) {
                prefs.getLong(KEY_REVIEW_FIRST_UNLOCK_AT, 0L)
            } else {
                null
            },
            unlockCount = prefs.getInt(KEY_REVIEW_UNLOCK_COUNT, 0),
            alreadyPrompted = prefs.getBoolean(KEY_REVIEW_PROMPTED, false),
        )
    }

    /**
     * Deletes ONLY the three legacy review keys (never the whole file —
     * `push_dereg_pending` lives here too). Callers MUST invoke this only
     * AFTER `recordReviewPromptUnlock`'s vault write is confirmed to have
     * landed (its `Boolean` return) — never delete unread-back state.
     * `commit()`, not `apply()` (PrefsApplySourceGuardTest). No-op (and no
     * write at all) when none of the three keys are present, so this is safe
     * to call unconditionally on every unlock once migration is done.
     */
    fun clearLegacyReviewCounters(context: Context) {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        if (prefs.contains(KEY_REVIEW_FIRST_UNLOCK_AT) ||
            prefs.contains(KEY_REVIEW_UNLOCK_COUNT) ||
            prefs.contains(KEY_REVIEW_PROMPTED)
        ) {
            prefs.edit()
                .remove(KEY_REVIEW_FIRST_UNLOCK_AT)
                .remove(KEY_REVIEW_UNLOCK_COUNT)
                .remove(KEY_REVIEW_PROMPTED)
                .commit()
        }
    }

    /** Deletes the prefs file — legacy encrypted content on old installs AND
     *  the pending-dereg flag AND any not-yet-migrated review-prompt legacy
     *  keys — on every wipe path (WipeRoutine). */
    fun clear(context: Context) {
        context.deleteSharedPreferences(PREFS_NAME)
    }
}

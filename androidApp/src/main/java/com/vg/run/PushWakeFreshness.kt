package com.vg.run

/**
 * Late-delivered FCM wake suppression.
 *
 * THE BUG. The relay's FCM push is a contentless data wake (`{"type":"wake"}`),
 * and [RunFcmService.onMessageReceived] posts the generic banner for every one it
 * receives (no peek, no fetch, no Tor, no vault in the service). FCM STORES a
 * wake it could not deliver and hands it over late, when the phone's push socket
 * comes back from doze. Observed 2026-10-14: banners at ~12:57 UTC for wakes the
 * relay sent the previous day at 15:04, whose messages the app had already shown at
 * 15:59 — "a notification, but no message".
 *
 * THE RULE. `RemoteMessage.sentTime` (stamped by FCM when the relay sent the wake;
 * 0 when absent) is compared with the start of the app's last COMPLETE inbox sweep
 * ([KEY_LAST_SWEEP]). A wake sent clearly BEFORE that sweep began concerns a message
 * the unlocked app has already observed on the relay (it is the unread dot, or it was
 * read), so its banner is stale. See [shouldSuppressWake] — every doubt shows it.
 *
 * WHY THE STAMP LIVES OUTSIDE THE VAULT. The decision is made in the FCM service,
 * which runs on a locked screen in a process the system started for the wake, with
 * no vault and no usable device key (the service must not open either). So the stamp sits
 * in the same outside-vault plaintext store as the wake gate it qualifies
 * ([RunViewModel.NOTIFICATION_LEVEL_PREFS_NAME], key `notif_level`).
 *
 * WHAT IT DISCLOSES (physical possession). ONE coarse "the app last
 * synced its inboxes at" wall-clock value — the same class of information as the
 * inactivity-wipe marker and the prefs files' own mtimes. Deliberately nothing else:
 * no inbox count, no contact, no per-inbox anything, no history (each write replaces
 * the last). It is written ONLY while vendor push is the persisted level, so a device
 * with notifications off never carries it, and it dies with that level (opt-out,
 * enable-revert, transport switch — see [recordInboxSweep]'s self-clear) and with the
 * whole file in [WipeRoutine]'s `PREFS_FILES`.
 *
 * NOT TAMPER EVIDENCE, AND NOT AN ANCHOR. Nothing in the wipe/tamper logic reads this
 * key: `InactivityWipe` reads only `inactivity_prefs` and its anchor in
 * `vault_selector_prefs`, and the establish-on-read paths never look at this store.
 * Its absence, presence or value can therefore never arm a wipe. A planted value can
 * at worst SUPPRESS banners (a local nuisance by someone who can already write the
 * app's files); a far-future plant is ignored by the clock check in
 * [shouldSuppressWake].
 */
object PushWakeFreshness {

    /** Sibling key in `notification_level_prefs`. Decimal ms since the epoch. */
    const val KEY_LAST_SWEEP = "inbox_sweep_ms"

    /**
     * Clock-skew allowance between FCM's server clock (which stamps `sentTime`) and
     * this phone's clock (which stamps the sweep). A wake must predate the sweep by
     * MORE than this to be suppressed.
     */
    const val MARGIN_MS: Long = 5L * 60_000L

    /**
     * Disk-write throttle: a sweep finishing less than this after the stored stamp
     * does not rewrite it. Moves the stamp EARLIER than the truth by at most this
     * much, which only ever suppresses LESS.
     */
    const val MIN_REWRITE_INTERVAL_MS: Long = 60_000L

    /** Max decimal digits of a positive Long; anything longer is not ours. */
    private const val MAX_DIGITS = 19

    /**
     * The pure gate. True ONLY when the wake was positively sent more than [marginMs]
     * before the last complete sweep began. Every ambiguous input answers false (show
     * the banner): a missed stale banner is cheap, a missed real one is not.
     *
     * @param sentTimeMs `RemoteMessage.sentTime`; ≤ 0 means FCM did not supply it.
     * @param lastSweepMs the stored sweep start; ≤ 0 means absent/unparseable.
     * @param nowMs this phone's wall clock now.
     * @param marginMs the skew allowance ([MARGIN_MS] in production).
     */
    fun shouldSuppressWake(sentTimeMs: Long, lastSweepMs: Long, nowMs: Long, marginMs: Long): Boolean {
        if (sentTimeMs <= 0L || lastSweepMs <= 0L || nowMs <= 0L || marginMs < 0L) return false
        // All differences below are of two POSITIVE Longs, so none can overflow
        // (an `x + marginMs` form could, for a planted near-MAX value).
        // A sentTime in our future (beyond the skew allowance) means one of the two
        // clocks is wrong — we cannot tell which, so we cannot order the two events.
        if (sentTimeMs - nowMs > marginMs) return false
        // A stored sweep in our future means the phone's clock was ahead when it was
        // written and has since been corrected (or the value was planted): it is not
        // evidence about anything that happened, so it suppresses nothing.
        if (lastSweepMs - nowMs > marginMs) return false
        return lastSweepMs - sentTimeMs > marginMs
    }

    /** Strict parse: ASCII digits only, 1..19 of them, positive. Null otherwise. */
    internal fun parseStamp(raw: String?): Long? {
        if (raw == null || raw.isEmpty() || raw.length > MAX_DIGITS) return null
        for (ch in raw) if (ch < '0' || ch > '9') return null
        val v = raw.toLongOrNull() ?: return null
        return if (v > 0L) v else null
    }

    /**
     * The FCM service's read: should this wake's banner be dropped? Never throws —
     * any failure reading the store answers false (show).
     */
    fun isStaleWake(store: KeyValueStore, sentTimeMs: Long, nowMs: Long): Boolean = try {
        staleWakeFromStamp(store.getString(KEY_LAST_SWEEP), sentTimeMs, nowMs)
    } catch (_: Exception) {
        false
    }

    /**
     * [isStaleWake] minus the store: the strict parse of the RAW stamp string
     * composed with [shouldSuppressWake] at the production margin. An absent or
     * unparseable stamp is `0`, which the gate answers false for (show).
     * Pure, so the composition is unit-pinnable without a `Context`.
     */
    internal fun staleWakeFromStamp(rawStamp: String?, sentTimeMs: Long, nowMs: Long): Boolean =
        shouldSuppressWake(sentTimeMs, parseStamp(rawStamp) ?: 0L, nowMs, MARGIN_MS)

    /** What a finished control-poll cycle does to the stamp — see [sweepStampAction]. */
    internal enum class SweepStampAction { WRITE, CLEAR, NONE }

    /**
     * The pure stamp POLICY behind [recordInboxSweep], one decision per finished
     * control-poll cycle. Byte-for-byte the rules the 2026-10-14 change shipped,
     * lifted out so they are unit-pinnable without a `Context`:
     *
     *  - after a wipe in this process ([wipedInProcess]) NOTHING is written or
     *    removed — a write landing after `WipeRoutine` deleted the file would
     *    re-create it;
     *  - a sweep in which any text/group peek did not answer ([sweepComplete]
     *    false) or whose control pass threw ([controlPassRan] false) leaves the
     *    stamp exactly as it was — including a stale one; it is not cleared;
     *  - a complete sweep under any level but [NotificationLevel.VENDOR_PUSH]
     *    REMOVES the stamp (self-clean: no stamp on a device that cannot receive
     *    an FCM wake);
     *  - otherwise WRITE [sweepStartedAtMs], unless it is non-positive, or it is
     *    less than [MIN_REWRITE_INTERVAL_MS] AFTER the stored [lastRecordedMs]
     *    (the disk-write throttle). A start EARLIER than the stored stamp — a
     *    backward clock step — is written, which only ever suppresses LESS.
     *
     * Never consults the wall clock: the throttle is measured on the two sweep
     * starts, so the recorded value is always the cycle START the caller took.
     */
    internal fun sweepStampAction(
        level: NotificationLevel,
        sweepComplete: Boolean,
        controlPassRan: Boolean,
        sweepStartedAtMs: Long,
        lastRecordedMs: Long?,
        wipedInProcess: Boolean,
    ): SweepStampAction {
        if (wipedInProcess) return SweepStampAction.NONE
        if (!sweepComplete || !controlPassRan) return SweepStampAction.NONE
        if (level != NotificationLevel.VENDOR_PUSH) return SweepStampAction.CLEAR
        if (sweepStartedAtMs <= 0L) return SweepStampAction.NONE
        if (lastRecordedMs != null &&
            sweepStartedAtMs >= lastRecordedMs &&
            sweepStartedAtMs - lastRecordedMs < MIN_REWRITE_INTERVAL_MS
        ) {
            return SweepStampAction.NONE
        }
        return SweepStampAction.WRITE
    }

    /**
     * Called by the unlocked app at the end of EVERY control-poll cycle.
     * [sweepStartedAtMs] is the wall clock taken BEFORE that cycle issued its
     * first request — the conservative end: a message present when the sweep
     * began was observed by it; one appended during it may not have been.
     * [sweepComplete] is `GroupManager.contactUnreadCounts`' `onSweepFinished`
     * answer (every text + group peek answered); [controlPassRan] is whether
     * `pollAllControls` returned without throwing. The decision itself is
     * [sweepStampAction].
     *
     * Writes only when the persisted wake gate is [NotificationLevel.VENDOR_PUSH]
     * (no stamp on a device that cannot receive an FCM wake) and REMOVES a stale
     * stamp otherwise, so every non-vendor state self-cleans on the next complete
     * sweep. Refused after a wipe in this process ([ProcessWipeLatch]): a write
     * landing after `WipeRoutine` deleted the file would re-create it. Synchronous
     * `commit()` underneath ([KeyValueStore.putString]) — never `apply()`. Never
     * throws.
     */
    fun recordInboxSweep(
        store: KeyValueStore,
        sweepStartedAtMs: Long,
        sweepComplete: Boolean,
        controlPassRan: Boolean,
    ) {
        try {
            if (ProcessWipeLatch.wipedThisProcess) return
            val action = sweepStampAction(
                level = NotificationLevelStore.getLevel(store),
                sweepComplete = sweepComplete,
                controlPassRan = controlPassRan,
                sweepStartedAtMs = sweepStartedAtMs,
                lastRecordedMs = parseStamp(store.getString(KEY_LAST_SWEEP)),
                wipedInProcess = ProcessWipeLatch.wipedThisProcess,
            )
            when (action) {
                SweepStampAction.NONE -> return
                SweepStampAction.CLEAR -> clear(store)
                SweepStampAction.WRITE -> {
                    // Re-check immediately before the write: narrows (cannot close)
                    // the window in which a wipe latching mid-call lets this commit
                    // re-create the file the wipe just deleted.
                    if (ProcessWipeLatch.wipedThisProcess) return
                    store.putString(KEY_LAST_SWEEP, sweepStartedAtMs.toString())
                }
            }
        } catch (e: Exception) {
            LogBuffer.append("W", "PushWakeFreshness", "sweep stamp not recorded: ${e.javaClass.simpleName}")
        }
    }

    /** Remove the stamp (opt-out / enable-revert). Absent key = no write. Never throws. */
    fun clear(store: KeyValueStore) {
        try {
            store.remove(KEY_LAST_SWEEP)
        } catch (_: Exception) {
        }
    }
}

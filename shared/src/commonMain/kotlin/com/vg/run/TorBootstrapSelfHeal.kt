package com.vg.run

/**
 * The PURE decision core for the iOS stuck-bootstrap self-heal.
 *
 * ## Why this exists
 *
 * A production user's Tor never connected across several app relaunches; only an
 * iPhone reboot fixed it. Four gaps made that state permanent:
 *
 *  1. **Stuck-in-`.bootstrapping` is never terminal.** All of iOS `TorManager`'s
 *     terminal branches (connect-attempt exhaustion, cookie-unreadable
 *     exhaustion, auth failure, SOCKS-port readback failure) are *fast, early*
 *     failures. Tor's `forCircuitEstablished` observer has no timeout, so a
 *     daemon that authenticates and then sits at N% forever is indistinguishable
 *     — to the app — from one that is about to succeed.
 *  2. The Tor state dir (`<Caches>/tor`, preserved across launches since
 *     2026-08-01 so entry guards stay sticky) is never validated or quarantined.
 *  3. The 90 s watchdog is purely cosmetic (it sets a hint; it never escalates).
 *  4. There is no escalation guidance past "close and reopen".
 *
 * This object holds ONLY the decisions. It has no platform dependencies, no I/O
 * and no clock of its own — every input is passed in — so the policy that
 * decides to throw away a user's entry guards is unit-testable on the JVM
 * instead of only reproducible on a wedged phone. The Swift side
 * (`iosApp/iosApp/TorManager.swift`) owns the persistence, the Keychain and the
 * actual directory delete.
 *
 * ## ANONYMITY RATIONALE (read before touching the thresholds)
 *
 * Deleting the Tor working directory **re-samples entry guards**. Guard
 * stickiness is a deliberate anonymity defence: a client that rotates its guards
 * often gives a network adversary repeated fresh chances to end up on the
 * client's path. So a state discard is NOT a free retry — it has a real
 * anonymity cost, and an adversary who can block *only the pinned guards* (a
 * cheap, targeted attack, since the guard set is small and stable) can
 * manufacture exactly the stuck-HIGH symptom that asks for one.
 *
 * Three properties bound that:
 *
 *  - **N-strikes**, not one: [MIN_CONSECUTIVE_FAILURES_FOR_DISCARD] separate
 *    failed sessions must accumulate across launches. A single bad network,
 *    airplane mode, or a captive portal never gets there.
 *  - **Shape-gated**: only a *stuck-HIGH* bootstrap ([STUCK_HIGH_PERCENT]% and
 *    above) qualifies, because that is the shape a corrupt/unusable cached
 *    consensus or an unreachable pinned guard set produces — the only shapes a
 *    state discard can actually repair. A bootstrap stuck LOW (0–25%) means the
 *    network is eating Tor outright; discarding state there would pay the full
 *    guard-rotation cost for nothing, which is precisely the free re-roll an
 *    attacker would want to farm.
 *  - **Wall-clock floored**: [MIN_DAYS_BETWEEN_DISCARDS] days between discards,
 *    so even an adversary who can hold the stuck-HIGH condition indefinitely
 *    forces guard rotation at most about once a week — the same order as Tor's
 *    own guard lifetime, rather than once per launch.
 *
 * The reboot HINT ([shouldSuggestReboot]) is deliberately un-gated on shape and
 * fires earlier: it costs nothing, changes no state, and the real incident was
 * not resolvable by anything Tor-internal at all.
 */
object TorBootstrapSelfHeal {

    // ---------------------------------------------------------------------
    // Thresholds (see the ANONYMITY RATIONALE above before changing any of
    // these — they are a bounded-cost budget, not tuning knobs).
    // ---------------------------------------------------------------------

    /** Failed sessions that must accumulate, across launches, before a discard. */
    const val MIN_CONSECUTIVE_FAILURES_FOR_DISCARD: Int = 5

    /**
     * "Stuck HIGH" floor. At or above this percent the daemon got through the
     * directory/consensus phase and is failing at guards/circuits — the classes
     * a state discard can repair. Below it, the network is blocking Tor and a
     * discard only pays the guard-rotation cost.
     */
    const val STUCK_HIGH_PERCENT: Int = 85

    /**
     * Minimum whole days between two discards. Bounds forced guard rotation to
     * roughly once a week even under a sustained attack that can synthesise
     * stuck-HIGH at will.
     */
    const val MIN_DAYS_BETWEEN_DISCARDS: Long = 5

    /**
     * Failed sessions before the UI additionally suggests restarting the phone.
     * Lower than the discard threshold and shape-independent on purpose: the
     * hint is free, reversible, and the observed incident (a wedged embedded
     * daemon that only a device reboot cleared) presented at BOTH ends of the
     * percent range.
     */
    const val MIN_CONSECUTIVE_FAILURES_FOR_REBOOT_HINT: Int = 3

    /**
     * A session must have spent at least this many seconds of FOREGROUND dwell
     * in `.bootstrapping` before it can be scored as a failure. A user who opens
     * the app for ten seconds and leaves, five times a week, must score ZERO —
     * otherwise ordinary glance-and-go usage would eventually delete their
     * guards. Foreground dwell (not wall time) because iOS suspends the process
     * in the background, where Tor makes no progress and the user sees nothing.
     */
    const val MIN_FAILED_ATTEMPT_DWELL_SECONDS: Int = 60

    /** Serialisation format tag. Bump only with a legacy read path. */
    private const val FORMAT_V1 = "v1"

    /** Field separator + the "no discard has ever happened" sentinel. */
    private const val SEP = ':'
    private const val NULL_DAY = "-"

    /**
     * Sanity ceilings used by [parse]. Anything outside them is treated as
     * garbage rather than clamped: a clamp would let a planted value keep part
     * of its effect, while rejecting the whole record fails toward "no
     * evidence" — no discard, no reboot hint.
     */
    private const val MAX_PLAUSIBLE_FAILURES: Int = 10_000
    private const val MAX_PLAUSIBLE_EPOCH_DAY: Long = 1_000_000

    /** The neutral record: nothing observed yet, nothing ever discarded. */
    val EMPTY: BootstrapBreadcrumb = BootstrapBreadcrumb(0, 0, null)

    // ---------------------------------------------------------------------
    // Decisions
    // ---------------------------------------------------------------------

    /**
     * Should this launch throw away the preserved Tor working directory and
     * bootstrap cold?
     *
     * True iff ALL of:
     *  - [BootstrapBreadcrumb.consecutiveFailures] >=
     *    [MIN_CONSECUTIVE_FAILURES_FOR_DISCARD] (N-strikes across launches), AND
     *  - [BootstrapBreadcrumb.lastStuckPercent] >= [STUCK_HIGH_PERCENT] (the
     *    stuck-HIGH shape — guards/circuit trouble, the only class a discard can
     *    repair), AND
     *  - the wall-clock floor is satisfied: either **no discard has ever
     *    happened** ([BootstrapBreadcrumb.lastDiscardEpochDay] == `null`), in
     *    which case the floor is **VACUOUSLY SATISFIED** — a first-ever discard
     *    is never rate-limited, there is nothing to rate-limit against — or at
     *    least [MIN_DAYS_BETWEEN_DISCARDS] whole days have elapsed since the
     *    last one.
     *
     * A [todayEpochDay] that is EARLIER than the recorded discard day (clock
     * rolled back, timezone/NTP correction, restored backup) yields a negative
     * delta and therefore `false` — the floor holds. That is the safe direction:
     * a clock the user or an attacker can move must never be able to *unlock*
     * extra guard rotations, only delay them.
     */
    fun shouldDiscardTorState(b: BootstrapBreadcrumb, todayEpochDay: Long): Boolean {
        if (b.consecutiveFailures < MIN_CONSECUTIVE_FAILURES_FOR_DISCARD) return false
        if (b.lastStuckPercent < STUCK_HIGH_PERCENT) return false
        val last = b.lastDiscardEpochDay ?: return true   // first-ever discard: floor vacuous
        return todayEpochDay - last >= MIN_DAYS_BETWEEN_DISCARDS
    }

    /**
     * Should the UI additionally suggest restarting the iPhone?
     *
     * Deliberately shape-INDEPENDENT (reachable from stuck-LOW as well as
     * stuck-HIGH) and lower-threshold than [shouldDiscardTorState]: it mutates
     * nothing, costs no anonymity, and the production incident it was written
     * for was not resolvable by any Tor-internal recovery.
     */
    fun shouldSuggestReboot(consecutiveFailures: Int): Boolean =
        consecutiveFailures >= MIN_CONSECUTIVE_FAILURES_FOR_REBOOT_HINT

    /**
     * Did this session count as a FAILED bootstrap attempt?
     *
     * All three conditions are required:
     *  - [reachedBootstrapping] — a session where Tor never even started (no
     *    relay configured, refused second init, wipe before start) is not
     *    evidence about bootstrapping.
     *  - `!`[reachedConnected] — a session that connected is a success no matter
     *    how long it took.
     *  - [foregroundDwellSeconds] >= [MIN_FAILED_ATTEMPT_DWELL_SECONDS] — the
     *    user actually waited. Ten-second glances must score ZERO; see the
     *    constant's doc.
     */
    fun isFailedAttempt(
        reachedBootstrapping: Boolean,
        reachedConnected: Boolean,
        foregroundDwellSeconds: Int,
    ): Boolean =
        reachedBootstrapping &&
            !reachedConnected &&
            foregroundDwellSeconds >= MIN_FAILED_ATTEMPT_DWELL_SECONDS

    // ---------------------------------------------------------------------
    // Pure state transitions
    //
    // These exist so the Swift caller never has to construct a
    // BootstrapBreadcrumb itself — its `Long?` field bridges to ObjC as an
    // optional boxed `KotlinLong`, which is awkward and easy to get wrong at a
    // call site that is deciding whether to delete a user's entry guards.
    // ---------------------------------------------------------------------

    /** One more failed session, remembering the shape it got stuck at. */
    fun recordFailure(b: BootstrapBreadcrumb, stuckPercent: Int): BootstrapBreadcrumb =
        BootstrapBreadcrumb(
            consecutiveFailures = b.consecutiveFailures + 1,
            lastStuckPercent = stuckPercent.coerceIn(0, 100),
            lastDiscardEpochDay = b.lastDiscardEpochDay,
        )

    /**
     * Tor reached `.connected` — the streak is broken. The last-discard day is
     * DELIBERATELY preserved: it is a rate limit on guard rotation, not part of
     * the failure evidence, so a single success must not hand out a fresh
     * discard budget.
     */
    fun recordSuccess(b: BootstrapBreadcrumb): BootstrapBreadcrumb =
        BootstrapBreadcrumb(
            consecutiveFailures = 0,
            lastStuckPercent = 0,
            lastDiscardEpochDay = b.lastDiscardEpochDay,
        )

    /**
     * A discard just ran. Stamps the wall-clock floor and clears the streak, so
     * the retry that follows gets [MIN_CONSECUTIVE_FAILURES_FOR_DISCARD] fresh
     * chances to prove the discard did or did not help before another one is
     * considered.
     */
    fun recordDiscard(b: BootstrapBreadcrumb, todayEpochDay: Long): BootstrapBreadcrumb =
        BootstrapBreadcrumb(
            consecutiveFailures = 0,
            lastStuckPercent = 0,
            lastDiscardEpochDay = todayEpochDay,
        )

    // ---------------------------------------------------------------------
    // Serialisation
    //
    // Compact single-line string: "v1:<failures>:<stuckPercent>:<day|->".
    // DAY granularity only, never milliseconds — this record lives outside the
    // vault (it must survive its own trigger), so it is forensic residue by
    // construction and must not carry a precise "when did you last use Rún"
    // timestamp. A day number is already implied by any Tor state dir mtime.
    // ---------------------------------------------------------------------

    fun serialize(b: BootstrapBreadcrumb): String =
        "$FORMAT_V1$SEP${b.consecutiveFailures}$SEP${b.lastStuckPercent}$SEP" +
            (b.lastDiscardEpochDay?.toString() ?: NULL_DAY)

    /**
     * Parses [raw]; returns `null` for anything that is not an exactly-shaped,
     * in-range v1 record — absent, blank, truncated, wrong tag, non-numeric, or
     * out of sane range.
     *
     * Rejecting rather than clamping is the fail-safe direction: [EMPTY] (what
     * [parseOrEmpty] substitutes) triggers no discard and no reboot hint, while
     * a partially-honoured garbage record could do both.
     */
    fun parse(raw: String?): BootstrapBreadcrumb? {
        val s = raw?.trim() ?: return null
        if (s.isEmpty()) return null
        val parts = s.split(SEP)
        if (parts.size != 4) return null
        if (parts[0] != FORMAT_V1) return null

        val failures = parts[1].toIntOrNull() ?: return null
        if (failures < 0 || failures > MAX_PLAUSIBLE_FAILURES) return null

        val stuck = parts[2].toIntOrNull() ?: return null
        if (stuck < 0 || stuck > 100) return null

        val dayField = parts[3]
        val day: Long? = if (dayField == NULL_DAY) {
            null
        } else {
            val parsed = dayField.toLongOrNull() ?: return null
            if (parsed < 0 || parsed > MAX_PLAUSIBLE_EPOCH_DAY) return null
            parsed
        }
        return BootstrapBreadcrumb(failures, stuck, day)
    }

    /** [parse] with the fail-safe substitution baked in, for the Swift caller. */
    fun parseOrEmpty(raw: String?): BootstrapBreadcrumb = parse(raw) ?: EMPTY
}

/**
 * Cross-launch evidence about iOS Tor bootstraps. Persisted by the Swift side in
 * the KEYCHAIN (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`), deliberately
 * NOT in UserDefaults (AFU-readable — a weaker class than the `<Caches>/tor`
 * evidence it summarises) and NOT inside the Tor working dir itself (every
 * fast-terminal failure already wipes that dir on failure #1, so a counter
 * stored there could never survive its own trigger).
 *
 * @param consecutiveFailures failed bootstrap sessions since the last success or
 *   discard. See [TorBootstrapSelfHeal.isFailedAttempt] for what counts.
 * @param lastStuckPercent the highest bootstrap percent observed during the most
 *   recent FAILED session — the "shape" gate. 0 when the streak is clean.
 * @param lastDiscardEpochDay days since the Unix epoch on which the last Tor
 *   state discard ran, or `null` if one has never run (the wall-clock floor is
 *   then vacuously satisfied). Day granularity only — see the serialisation note.
 */
data class BootstrapBreadcrumb(
    val consecutiveFailures: Int,
    val lastStuckPercent: Int,
    val lastDiscardEpochDay: Long?,
)

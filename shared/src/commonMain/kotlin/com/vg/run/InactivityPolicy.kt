package com.vg.run

// ---------------------------------------------------------------------------
// InactivityPolicy — the PURE inactivity-expiry decision for the 7-day
// dead-man's-switch, shared by Android (InactivityWipe.kt) and iOS
// (InactivityWipe.swift) so the anti-forensic rule CANNOT diverge between
// platforms.
//
// It once did: the clock-rollback defense below
// shipped on Android but not iOS, so a seized-but-unlocked iPhone could defer the
// wipe INDEFINITELY by setting the device clock back. Hoisting the decision here —
// one copy, pinned by InactivityPolicyTest — closes that gap and prevents the next
// one. Storage of the encrypted last-opened timestamp stays platform-side
// (Keystore/Keychain AEAD); only the DECISION lives here.
//
// A second, un-rollable input and a tolerance were added:
// the sealed record now carries the device UPTIME sampled alongside the wall-clock
// stamp (formatStamp/parseStamp — legacy bare-decimal blobs still read, and migrate
// on the next write), and expiry is the DISJUNCTION of the wall-clock term and the
// monotonic term. See isExpired for why the two terms are OR'd rather than the
// monotonic one replacing the wall one the way windowRolled does it.
// ---------------------------------------------------------------------------

object InactivityPolicy {

    /** Default inactivity threshold: 7 days. */
    val THRESHOLD_MS: Long = 7L * 24 * 60 * 60 * 1000

    /**
     * Sentinel for "this stamp carries no monotonic uptime anchor" — a legacy
     * (pre-anchor) blob, or a platform sampler that failed this call. Uptime is
     * always >= 0, so a negative value can only mean "absent".
     */
    val NO_UPTIME: Long = -1L

    /**
     * How far the wall clock may step BACKWARD before that
     * alone is read as deliberate tampering. **24 hours.**
     *
     * The old rule was zero-tolerance — ANY backward step (`nowMs < lastOpenedMs`,
     * i.e. one millisecond) meant "expired", and the caller turns "expired" into an
     * unconfirmed, irreversible crypto-erase of the vault INCLUDING the recovery
     * blob. `lastOpened` is re-stamped on every unlock, so it is typically minutes
     * old: an ordinary NTP/NITZ correction after RTC drift (this app's users run
     * offline and on Tor for long stretches), or a user fixing a mis-set date,
     * destroyed a healthy vault. Verified UTC-anchored on both platforms, so DST and
     * timezone crossings never reach here — but clock CORRECTION does.
     *
     * Why 24 h specifically, and why the security cost is ~nil:
     *  - Correction noise is seconds-to-minutes; a full day of slack is far past any
     *    plausible RTC drift, and also covers a user who fixes a clock that was up to
     *    a day fast. A deliberate multi-day back-set (the "freeze the dead-man's
     *    switch" move) still trips it.
     *  - Incremental back-sets (e.g. -23 h/day) defeat the wall clock entirely at
     *    ANY tolerance, since `lastOpened` is a fixed anchor rather than the
     *    previous reading. The un-rollable monotonic term below is what actually
     *    closes that; this
     *    branch is a cheap backstop, so widening it costs almost nothing.
     */
    val CLOCK_BACK_TOLERANCE_MS: Long = 24L * 60 * 60 * 1000

    /** Separator between the wall-clock stamp and the optional uptime anchor. */
    private const val STAMP_SEPARATOR = '|'

    /**
     * Serialises the last-active record that the platforms seal under their device
     * key. Legacy shape is a bare decimal (`"1700000000000"`); the v2 shape appends
     * the monotonic uptime anchor (`"1700000000000|3600000"`).
     *
     * Pass [NO_UPTIME] (or any negative) when no anchor is available — the output is
     * then byte-identical to the legacy shape, so nothing is written that an older
     * reader could choke on.
     */
    fun formatStamp(timestampMs: Long, uptimeMs: Long): String =
        if (uptimeMs < 0L) timestampMs.toString()
        else "$timestampMs$STAMP_SEPARATOR$uptimeMs"

    /**
     * Parses [formatStamp]'s output, INCLUDING every legacy bare-decimal blob
     * written before the anchor existed (they yield [NO_UPTIME] and are then judged
     * by the wall-clock rules alone — exactly the old behaviour, minus the old
     * zero-tolerance rollback). Migration is lazy: the next `recordUnlock`/`touch`
     * rewrites the stamp in the v2 shape.
     *
     * Returns null only when the WALL-CLOCK field is unparseable — the callers treat
     * that the same way they always treated a malformed decrypted timestamp. A
     * malformed UPTIME field degrades to [NO_UPTIME] rather than failing the whole
     * parse: the anchor is an optimisation, and failing open here would turn a
     * cosmetic defect into a wipe.
     */
    fun parseStamp(raw: String): InactivityStamp? {
        val sep = raw.indexOf(STAMP_SEPARATOR)
        if (sep < 0) {
            val ts = raw.toLongOrNull() ?: return null
            return InactivityStamp(ts, NO_UPTIME)
        }
        val ts = raw.substring(0, sep).toLongOrNull() ?: return null
        val up = raw.substring(sep + 1).toLongOrNull()
        return InactivityStamp(ts, if (up != null && up >= 0L) up else NO_UPTIME)
    }

    /**
     * [isExpired] over a parsed [InactivityStamp] — the entry point both platforms
     * call (and the only one Swift uses, since Kotlin default arguments are not
     * exported to Obj-C).
     */
    fun isStampExpired(
        stamp: InactivityStamp,
        nowMs: Long,
        nowUptimeMs: Long,
        thresholdMs: Long,
    ): Boolean = isExpired(
        lastOpenedMs = stamp.timestampMs,
        nowMs = nowMs,
        thresholdMs = thresholdMs,
        storedUptimeMs = stamp.uptimeMs,
        nowUptimeMs = nowUptimeMs,
    )

    /**
     * True when the app has been inactive at/past [thresholdMs] by EITHER measure —
     * the wall clock, or the un-rollable monotonic uptime term — or when the wall
     * clock has rolled backward by more than [CLOCK_BACK_TOLERANCE_MS] and nothing
     * contradicts that.
     *
     * The three terms, in evaluation order:
     *
     * 1. **Monotonic.** [storedUptimeMs] is the device
     *    uptime sampled when [lastOpenedMs] was stamped (Android
     *    `SystemClock.elapsedRealtime()`, iOS `ProcessInfo.systemUptime` — the SAME
     *    samplers `PinAttemptsStore`/`windowRolled` use for the wrong-credential
     *    windows). Kernel uptime is not user-writable, so disabling automatic time
     *    and pinning the date to the seizure day — which used to disarm the 7/90/180
     *    day self-destruct PERMANENTLY, since the elapsed term never grew — no
     *    longer helps: the uptime delta still reaches the threshold and fires. Only
     *    consulted when uptime has NOT gone backwards; uptime going backwards is a
     *    REBOOT, which destroys the anchor. NOTE: a reboot is NOT a cost to the
     *    attacker here — this check only runs when the app is launched on an
     *    already-unlocked device (the attacker already has the passcode, and a
     *    passcode crack reboots the phone anyway), so an attacker can reset the
     *    anchor cheaply; the self-destruct is a backstop against an UNATTENDED
     *    phone, never against an adversary who can launch the app.
     *    BRICK-SAFETY: whenever this term is consulted the delta is bounded above by
     *    the real elapsed time (with no reboot it IS the real elapsed time; with one,
     *    `nowUptime - storedUptime <= nowUptime <= real elapsed`), so it can only
     *    ever fire LATE — never early, on any device, at any tier.
     *
     * 2. **Wall clock, forward.** Unchanged, and deliberately NOT vetoed by term 1.
     *    The monotonic delta can UNDERSTATE real elapsed time — a reboot whose new
     *    uptime happens to exceed the stored anchor's still passes the
     *    not-gone-backwards test while the delta silently misses the downtime, and
     *    iOS's `systemUptime` does not advance across deep sleep at all. Letting a
     *    small delta suppress a genuine wall-clock expiry would be a permanent
     *    disarm — the exact failure the Damaged case below avoids. So the terms are a
     *    DISJUNCTION, which is also why `windowRolled` could not simply be reused
     *    verbatim here: its monotonic branch REPLACES the wall-clock branch (correct
     *    for a rate-limit window, wrong for a dead-man's switch).
     *
     * 3. **Wall clock, backward, with tolerance.** See
     *    [CLOCK_BACK_TOLERANCE_MS]. Skipped entirely when term 1 is usable: a
     *    same-boot monotonic anchor is direct evidence that only minutes of real
     *    time have passed, so the backward step is a clock ADJUSTMENT, not a stale
     *    vault — and term 1 will fire on its own at the true threshold if the device
     *    really is being sat on. Nothing is lost by not wiping twice as fast on a
     *    signal we can positively explain.
     *
     * Uses `>=` so exactly [thresholdMs] elapsed counts as expired. Both uptime
     * arguments default to [NO_UPTIME], so the pre-anchor 3-argument call form still
     * compiles and still means "wall-clock rules only".
     */
    fun isExpired(
        lastOpenedMs: Long,
        nowMs: Long,
        thresholdMs: Long,
        storedUptimeMs: Long = NO_UPTIME,
        nowUptimeMs: Long = NO_UPTIME,
    ): Boolean {
        // (1) Un-rollable elapsed term. `nowUptimeMs >= storedUptimeMs` implies both
        // are present (storedUptimeMs >= 0) and uptime has not gone backwards.
        val monotonicUsable = storedUptimeMs >= 0L && nowUptimeMs >= storedUptimeMs
        if (monotonicUsable && nowUptimeMs - storedUptimeMs >= thresholdMs) return true
        // (2) Wall clock forward — never vetoed by (1), see above.
        if (nowMs - lastOpenedMs >= thresholdMs) return true
        // (3) Backward step, only when (1) cannot vouch for the elapsed time.
        if (monotonicUsable) return false
        // Written as a difference guarded by the `<` so an (unreachable) overflow
        // falls toward NOT expired — never toward wiping a vault.
        return nowMs < lastOpenedMs && lastOpenedMs - nowMs > CLOCK_BACK_TOLERANCE_MS
    }

    /**
     * Threshold to enforce for a persisted-level [read], or null when the check
     * must be SKIPPED this launch. One shared copy (like [isExpired]) so the
     * fail-safe cannot diverge between platforms:
     *  - Present    → the chosen tier's window.
     *  - Absent     → [defaultMs] (legacy pre-slider install — current constants).
     *  - Damaged    → MAXIMUM's window. The device key
     *    WORKS and the blob failed AEAD, i.e. positive tamper evidence. Folding
     *    this into Unreadable (below) meant one flipped byte INSIDE the base64
     *    disarmed the dead-man's-switch on every launch, for good — the exact
     *    move an examiner makes before sitting on a seized device for months.
     *    Deleting the value still yields Absent (establish-on-read, [defaultMs]);
     *    only a provably-corrupt value fails secure to the tightest window.
     *    NOT a wipe by itself: this only picks the window the ordinary
     *    timestamp-vs-now check is then evaluated against.
     *  - Unreadable → null. The level exists but the DEVICE KEY is transiently
     *    unavailable, so a healthy blob is indistinguishable from a damaged one;
     *    applying [defaultMs] instead would shrink e.g. CASUAL's 180-day window
     *    to 7 days and crypto-erase the vault ~173 days early. Skipping one
     *    launch is safe — the dead-man's-switch re-arms as soon as the level
     *    reads again.
     */
    fun thresholdMsOrNull(read: ProtectionLevelRead, defaultMs: Long = THRESHOLD_MS): Long? = when (read) {
        is ProtectionLevelRead.Present -> read.level.inactivityWipeMs
        ProtectionLevelRead.Absent -> defaultMs
        ProtectionLevelRead.Damaged -> ProtectionLevel.MAXIMUM.inactivityWipeMs
        ProtectionLevelRead.Unreadable -> null
    }
}

/**
 * A decoded last-active record: the wall-clock stamp plus the OPTIONAL monotonic
 * uptime anchor sampled at the same instant ([InactivityPolicy.NO_UPTIME] when the
 * record predates the anchor, or the sampler failed).
 *
 * Deliberately a plain pair of Longs rather than [MonotonicSample]: this record
 * holds exactly one uptime reading, `MonotonicSample.bootId` is vestigial (fixed to
 * 0 on both platforms — the Android source was shell-writable),
 * and a nullable Kotlin class would cross the Obj-C bridge as an awkward boxed
 * optional on the one path iOS actually calls. The SAMPLERS and the
 * uptime-not-gone-backwards RULE are the same ones `PinAttemptsStore`/`windowRolled`
 * use; only the container differs.
 */
class InactivityStamp(val timestampMs: Long, val uptimeMs: Long)

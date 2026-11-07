package com.vg.run

import kotlin.math.max

// ---------------------------------------------------------------------------
// ReauthPolicy — periodic random re-authentication at MAXIMUM
// (docs/periodic-reauth-design.md).
//
// On top of Lever C's IDLE auto-lock, MAXIMUM additionally re-locks the vault
// after a RANDOM interval — drawn fresh at every unlock, uniform on
// [MIN_INTERVAL_MS, MAX_INTERVAL_MS] — regardless of activity, so a long
// ACTIVE session (which never trips the idle timer) still forces a fresh
// credential check at least once every ten minutes. Shared by MainActivity/
// RunViewModel (Android) and ContentView/IosAppController (iOS) so the two
// platforms cannot drift on the bound, the tier gate, or the debug/e2e escape
// hatch.
//
// FULL LOCK, NOT A VERIFY GATE (design doc §2): this reuses the SAME lock
// primitive Lever C uses (vault close + key wipe), and the re-auth prompt IS
// the existing PinEntryScreen/PinEntryView, so wrong-credential attempts
// count through the SAME PinAttemptsStore + wipe budget as an ordinary
// unlock. Nothing here touches VaultSelector.unlock or the credential store.
// ---------------------------------------------------------------------------

object ReauthPolicy {

    /** Interval floor — strictly above MAXIMUM's (60 s) and PRIVATE's (2 min)
     *  Lever C windows, so an IDLE user always hits Lever C first; also bounds
     *  how often the Argon2id re-derive can fire (pinned by [ReauthPolicyTest]). */
    val MIN_INTERVAL_MS: Long = 3L * 60 * 1000

    /** Interval ceiling — the "at least once every ten minutes" requirement. */
    val MAX_INTERVAL_MS: Long = 10L * 60 * 1000

    /** Warning-overlay window before the deadline fires. Reuses Lever C's
     *  constant so the two overlays share one cadence/threshold. */
    val WARNING_MS: Long = CredentialPolicy.AUTO_LOCK_WARNING_MS

    /** Debug-only fixed interval, armed via [setTestIntervalOverrideMs]. Stays
     *  null in a release binary — the setter refuses to write it there. */
    private var testIntervalOverrideMs: Long? = null

    /**
     * Tier gate: true iff the persisted level is MAXIMUM, or the read is
     * [ProtectionLevelRead.Damaged]/[ProtectionLevelRead.Unreadable] — the same
     * fail-SECURE direction [CredentialPolicy.autoLockTimeoutMs] takes for those
     * two states (locking/re-checking sooner loses no data; see this object's
     * own [ReauthPolicyTest] for the cross-check). CASUAL, PRIVATE and a legacy
     * [ProtectionLevelRead.Absent] vault are unaffected. Never gate this on
     * `VaultSelector.isPassphraseMode()` — that selector is display-only.
     */
    fun appliesTo(read: ProtectionLevelRead): Boolean = when (read) {
        is ProtectionLevelRead.Present -> read.level == ProtectionLevel.MAXIMUM
        ProtectionLevelRead.Damaged, ProtectionLevelRead.Unreadable -> true
        ProtectionLevelRead.Absent -> false
    }

    /**
     * Whole enable decision: the tier gate above, ANDed with the debug/e2e
     * escape hatch. A debuggable build is OFF by default — the device e2e
     * suites run iOS seats on MAXIMUM for multi-minute Tor waits, and this
     * timer is touch-independent so KeepAwake cannot defeat it — and turns ON
     * only once a test has armed a fixed [override] via
     * [setTestIntervalOverrideMs]. A RELEASE build ([debugBuild] false) has no
     * such escape: it is always on at MAXIMUM. [debugBuild]/[override] are
     * parameters (rather than reading the private field directly) purely so
     * this decision is unit-testable without touching global mutable state.
     */
    fun isEnabled(
        read: ProtectionLevelRead,
        debugBuild: Boolean = isDebugBuild,
        override: Long? = testIntervalOverrideMs,
    ): Boolean = appliesTo(read) && (!debugBuild || override != null)

    /**
     * Maps 8 uniformly-random bytes onto [MIN_INTERVAL_MS, MAX_INTERVAL_MS] by
     * reduction mod the range width. [bytes] is treated as a big-endian
     * unsigned 64-bit integer; the range width here (~420,001 ms) is far from
     * a power of two over 2^64, so the reduction is NOT perfectly uniform —
     * values in `[0, 2^64 mod range)` are drawn with probability `range / 2^64`
     * MORE than the rest. That bias is ~2^-45 (range ≈ 2^18.7, so
     * `range / 2^64 ≈ 2^-45.3`): far below anything the CSPRNG's own output
     * could be distinguished from, and acceptable for a re-auth TIMER (not a
     * key) — documented here rather than paying for full rejection sampling
     * (contrast [secureRandomInt], which DOES reject for a bound that needs to
     * be bias-FREE).
     */
    fun intervalFromRandom(bytes: ByteArray): Long {
        require(bytes.size >= 8) { "intervalFromRandom needs >= 8 random bytes, got ${bytes.size}" }
        var v = 0uL
        for (i in 0 until 8) {
            v = (v shl 8) or bytes[i].toUByte().toULong()
        }
        val range = (MAX_INTERVAL_MS - MIN_INTERVAL_MS + 1).toULong()
        return MIN_INTERVAL_MS + (v % range).toLong()
    }

    /**
     * Draws the next interval: the debug fixed [testIntervalOverrideMs] when
     * one is armed (deterministic e2e timing), otherwise 8 fresh CSPRNG bytes
     * reduced through [intervalFromRandom]. [random] is injectable for tests;
     * production callers use the default ([generateSecureRandom]).
     */
    fun nextIntervalMs(random: (Int) -> ByteArray = ::generateSecureRandom): Long {
        val override = testIntervalOverrideMs
        if (isDebugBuild && override != null) return override
        return intervalFromRandom(random(8))
    }

    /**
     * Arms a fixed interval for e2e determinism — `--el TEST_REAUTH_INTERVAL_MS`
     * (Android) / `--test-reauth-interval-ms=<n>` (iOS). Refuses (returns
     * false, leaves any prior override untouched) outside a debuggable build,
     * so no override path exists in a release binary even if the intent
     * extra/launch arg were somehow delivered to one. Floors at 1000 ms so a
     * 0/negative test value can't turn the interrupt-mid-action UX into a
     * busy-loop.
     */
    fun setTestIntervalOverrideMs(ms: Long): Boolean {
        if (!isDebugBuild) return false
        testIntervalOverrideMs = max(ms, 1000L)
        return true
    }

    /**
     * Test-only reset between cases — internal, so it never crosses the module
     * boundary into androidApp/iosApp (they only ever see the public setter
     * above). No-op outside a debuggable build, mirroring
     * [ProcessWipeLatch.resetForTest].
     */
    internal fun clearTestIntervalOverrideForTest() {
        if (isDebugBuild) testIntervalOverrideMs = null
    }

    /** [deadlineElapsedMs] minus [nowElapsedMs] — both monotonic
     *  (`SystemClock.elapsedRealtime()` / `ProcessInfo.systemUptime`), so a
     *  wall-clock change can never move the deadline. */
    fun remainingMs(deadlineElapsedMs: Long, nowElapsedMs: Long): Long = deadlineElapsedMs - nowElapsedMs

    /** Where a deadline sits relative to now. */
    sealed class Phase {
        /** More than [WARNING_MS] remains — nothing to show. */
        data object Idle : Phase()

        /** Inside the last [WARNING_MS] — show the countdown overlay, with NO
         *  "tap to stay" (the deadline never moves). */
        data class Warn(val secondsLeft: Int) : Phase()

        /** The deadline has passed — lock now. */
        data object Fire : Phase()
    }

    /** Classifies a [remainingMs] value (see the function of the same name)
     *  into a [Phase]. Matches the `((ms + 999) / 1000)` rounding MainActivity's
     *  Lever-C countdown already uses, so the two overlays never disagree by a
     *  second at the same boundary. */
    fun phase(remainingMs: Long): Phase = when {
        remainingMs <= 0L -> Phase.Fire
        remainingMs <= WARNING_MS -> Phase.Warn(((remainingMs + 999) / 1000).toInt())
        else -> Phase.Idle
    }
}

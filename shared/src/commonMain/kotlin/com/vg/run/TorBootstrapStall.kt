package com.vg.run

// ---------------------------------------------------------------------------
// TorBootstrapStall — the progress-aware BOOTSTRAP-STALL rung (2026-10-06).
//
// THE CLASS IT TARGETS. A Tor bootstrap that sits at one percent inside the
// ladder (dev-relay device runs 2026-10-06, Pixel: 50–69 % `loading_descriptors` for ~100 s
// with a FRESH consensus and the guard OR connection up — a directory fetch
// stalled over a live channel). Tor reaps a stalled directory connection only
// after `TestingDirConnectionMaxStall` (5 min), and nothing of ours acted before
// the flat 90 s hint / 100 s restart; the Android restart then bootstrapped in
// 5 s from the preserved state. iOS cannot restart its Tor at all, so it had no
// rescue for this class (observed tor = 110 / 185 / 195 s there).
//
// THE KICK. `SETCONF DisableNetwork=1` and `SETCONF DisableNetwork=0`, written
// as ONE pipelined write on the command control connection (Android
// TorManager.kickStalledBootstrap, iOS TorManager.kickStalledBootstrap). Tor
// executes the two in order inside one read of the control socket, so the
// network is never left disabled across a main-loop turn, and the second
// command cannot be lost without the first being lost too. What it does — read
// from tor 0.4.9 (config.c options_act_reversible, connection.c
// connection_mark_all_noncontrol_connections / retry_all_listeners,
// dirclient.c connection_dir_client_request_failed):
//  - every non-control connection is marked for close: OR channels (an OPEN
//    one is closed normally — no failure is attributed to its guard), directory
//    connections, client streams. A directory fetch that had not finished goes
//    through connection_dir_client_request_failed — EXACTLY the path Tor's own
//    5-minute stall reaper takes — so its directory guard is noted failed
//    (prop271: primary retry after 10 min, not removed from the sample) and the
//    fetch is rescheduled on a fresh connection, normally to another dir guard.
//    That is the rescue; the guard attribution is the same one Tor would make at
//    the reaper, only earlier. A not-yet-open OR handshake is likewise noted
//    failed (entry_guard_chan_failed). Bounded: [MAX_KICKS] per Tor process.
//  - the guard SAMPLE, the consensus, the microdescriptor cache and the state
//    file are untouched; the bootstrap percent is monotone inside Tor
//    (control_bootstrap.c ignores a lower status), so no phase is re-run.
//  - CONTROL connections and the control listener survive (that is how the
//    second command and every later one still arrive).
//  - THE SOCKS LISTENER IS CLOSED AND RE-BOUND. With `SocksPort auto` (L8) the
//    re-bound listener gets a NEW OS-assigned port. Both platforms therefore
//    refuse to kick once a SOCKS port has been handed to the app (Android: once
//    Connected is published; iOS: once the listener readback has started), and
//    Android re-learns the port from Tor's own notice line before it publishes
//    Connected (TorManager.kt, `socksMovePending`). iOS reads the port back at
//    CIRCUIT_ESTABLISHED, i.e. after any kick, by construction.
//
// IDENTIFIERS. Nothing here reads anything but a percent and clocks; the
// control-event parser below returns only the PROGRESS integer. The two panel
// phrases are built HERE so the platforms cannot drift: numbers and fixed words.
// ---------------------------------------------------------------------------

object TorBootstrapStall {

    /**
     * How long the bootstrap percent may stand still (inside the ladder) before
     * the kick. A healthy warm bootstrap moves every few seconds (the evidence
     * timeline went 0 → 69 % inside the first 5 s bucket, and the post-restart
     * bootstrap finished in 5 s); 20 s is four times the observed step and still
     * 70 s ahead of the 90 s hint.
     */
    const val STALL_MS = 20_000L

    /**
     * Kicks per Tor PROCESS (Android: per TorManager start attempt; iOS: per
     * process, tor_main runs once). One covers "that directory connection was
     * wedged", the second "so was the next one"; past that the existing 90 s /
     * 100 s ladder owns it. Public: both platforms render it as `(n/2)`.
     */
    const val MAX_KICKS = 2

    /**
     * Below this percent no OR connection has been attempted yet (`starting` is
     * 0 %, `conn` is 5 %): there is nothing to re-kick, and a slow daemon start
     * is not a network stall.
     */
    const val MIN_PERCENT = 5

    /**
     * Minimum spacing after ANY `SIGNAL NEWNYM` handed to the same Tor (both
     * TorManagers stamp it in requestNewCircuit). Tor rate-limits NEWNYM to one
     * per 10 s itself; a kick inside that window would tear down the circuits the
     * NEWNYM was about to build and make neither rung's effect readable.
     */
    const val NEWNYM_SPACING_MS = 10_000L

    /** "Never happened" for the two optional clocks in [msUntilKick]. */
    const val NEVER = Long.MAX_VALUE

    /** [msUntilKick]'s "not for this progress level — wait for the percent to move". */
    const val NO_KICK = -1L

    /**
     * THE decision, shared by both platforms. Returns how many ms until a kick is
     * due: `0` = kick now, `> 0` = re-evaluate after that long, [NO_KICK] = not
     * at this percent (re-armed only by a percent change).
     *
     * @param percent the HIGHEST bootstrap percent this Tor process has reported
     *   (Tor's own counter is monotone; a lower re-report is not progress).
     * @param msSinceProgress ms since that percent last went UP.
     * @param msSinceLastKick ms since this process's last kick, or [NEVER]. The
     *   stall clock runs from the LATER of progress and kick, so a second kick
     *   needs a fresh [STALL_MS] of no progress after the first.
     * @param msSinceLastNewnym ms since the last NEWNYM handed to this Tor, or
     *   [NEVER]. See [NEWNYM_SPACING_MS].
     * @param kicksFired kicks this Tor process already handed to the control
     *   channel. A skipped kick (control channel down) is NOT counted — and is
     *   not retried either until the percent moves, so there is no retry storm.
     *
     * Every malformed input (negative clock, negative counter) fails CLOSED.
     * Pure; unit-tested in TorBootstrapStallTest.
     */
    fun msUntilKick(
        percent: Int,
        msSinceProgress: Long,
        msSinceLastKick: Long,
        msSinceLastNewnym: Long,
        kicksFired: Int,
    ): Long {
        if (percent < MIN_PERCENT || percent >= 100) return NO_KICK
        if (kicksFired < 0 || kicksFired >= MAX_KICKS) return NO_KICK
        if (msSinceProgress < 0 || msSinceLastKick < 0) return NO_KICK
        val stalledFor = minOf(msSinceProgress, msSinceLastKick)
        val stallWait = STALL_MS - stalledFor
        // A negative NEWNYM clock cannot happen on a monotonic clock; treat it as
        // "a NEWNYM just happened" (wait the whole spacing), never as "long ago".
        val newnymWait = if (msSinceLastNewnym < 0) NEWNYM_SPACING_MS else NEWNYM_SPACING_MS - msSinceLastNewnym
        return maxOf(0L, stallWait, newnymWait)
    }

    /** [msUntilKick] == 0. */
    fun shouldKick(
        percent: Int,
        msSinceProgress: Long,
        msSinceLastKick: Long,
        msSinceLastNewnym: Long,
        kicksFired: Int,
    ): Boolean = msUntilKick(percent, msSinceProgress, msSinceLastKick, msSinceLastNewnym, kicksFired) == 0L

    /**
     * The panel line for a kick handed to the control channel — IDENTICAL on
     * both platforms (code [ConnectionLog.Code.TOR_BOOT_KICK]). [n] is this
     * process's kick count after the kick.
     */
    fun kickLine(percent: Int, n: Int): String =
        "bootstrap stalled ${STALL_MS / 1000} s at $percent% - network re-kicked ($n/$MAX_KICKS)"

    /**
     * The panel line for a due kick that was NOT carried out (code
     * [ConnectionLog.Code.TOR_BOOT_KICK_SKIP]): the command control connection
     * was down, the write failed, or Tor refused the first `SETCONF`. Emitted at
     * most once per progress level (no retry until the percent moves).
     */
    fun skipLine(percent: Int): String =
        "bootstrap stalled ${STALL_MS / 1000} s at $percent% - network re-kick unavailable"

    /**
     * The bootstrap PROGRESS from one control-port line, or null. Android's
     * event socket feeds this (the NOTICE log only reports every 5th percent,
     * the control event every step — the granularity iOS already sees through
     * TORController's status observer).
     *
     * `[650 ]STATUS_CLIENT <Severity> BOOTSTRAP PROGRESS=<n> TAG=… SUMMARY="…" …`
     *
     * Only the integer leaves: SUMMARY / WARNING / HOSTID / HOSTADDR are never
     * read. Accepts the line with or without the `650 ` / `650-` prefix.
     */
    fun progressFromControlEvent(rawEventLine: String): Int? {
        var line = rawEventLine.trimEnd('\r', '\n')
        if (line.length >= 4 && line.startsWith("650") && (line[3] == ' ' || line[3] == '-')) {
            line = line.substring(4)
        }
        val tokens = line.split(' ')
        if (tokens.size < 4 || tokens[0] != "STATUS_CLIENT" || tokens[2] != "BOOTSTRAP") return null
        // PROGRESS is a fixed keyword argument before any quoted prose, but scan
        // rather than index so an argument-order change cannot misread a value.
        for (t in tokens) {
            if (!t.startsWith("PROGRESS=")) continue
            val digits = t.substring("PROGRESS=".length)
            if (digits.isEmpty() || digits.length > 3 || !digits.all { it in '0'..'9' }) return null
            val pct = digits.toInt()
            return if (pct in 0..100) pct else null
        }
        return null
    }
}

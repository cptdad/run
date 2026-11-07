package com.vg.run

import kotlin.concurrent.Volatile
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

// ---------------------------------------------------------------------------
// ConnectTelemetry — the only anonymous connect-time signal
// (product rule: when the relay has been reached, an anonymous
// control signal is sent to the relay containing the time it took for the relay
// to connect).
//
// DEBUG-MODE ONLY. The report is sent ONLY
// while the user's Debug mode consent ([DebugMode.isEnabled]) is on — the same
// opt-in that gates the debug-log upload, and whose consent text ("send
// anonymous diagnostic logs to the relay") already covers this report. A
// default install sends NOTHING about itself: [send] reads the consent through
// the caller's provider BEFORE the jitter (cheap skip) and AGAIN after it
// (consent revoked mid-jitter = no report), and fails toward "off" if the
// provider throws. Before this date the report went out on every connect of
// every install; the wire format below is unchanged.
//
// `POST {relayBaseUrl}/telemetry/connect`, `Content-Type: application/json`,
// body `{"v":1,"platform":"android"|"ios","app":"<version>","secs":<int>}`,
// plus the OPTIONAL `"tor":<int>` phase split (2026-09-11, lever 5) when this
// session knows how long Tor itself took: `…,"secs":45,"tor":20}`, the
// OPTIONAL `"boot":<int>` (2026-09-11) — seconds from this session's Tor
// PROCESS start (app launch / speculative start, NOT unlock) to Tor reporting
// Connected: `…,"secs":45,"tor":20,"boot":38}` — the OPTIONAL `"reveal":<int>`
// (2026-09-15, C4a) — the same anchor as `secs`, but to the frame the CONTACT
// LIST actually appeared in — and the OPTIONAL trailing
// `"log":[[<offsetSeconds>,"<CODE>"],…]` CODED TIMELINE (2026-09-14, see
// below). Fixed key order `v, platform, app, secs, tor, boot, reveal, log`. The
// relay answers 204; ANY other response, and any transport error, is ignored
// (the emulator/simulator mock relay answers 404 — deliberately fine).
//
// The phase split exists to make the connect levers PROVABLE rather than
// guessed: `secs - tor` is the onion RENDEZVOUS + first round trip, which is
// the phase the pre-unlock warm-up ([RelayWarmup]) targets, while `tor` is the
// portion of THIS SESSION'S CONNECT WAIT spent on Tor (measured from the same
// anchor as `secs`, so it is capped at `secs`). `tor == 0` is meaningful and
// common — it means Tor was ALREADY up when the connect clock started, i.e.
// the speculative start paid for itself. `boot` is a DIFFERENT, unrelated-anchor
// measurement of the same bootstrap: the wall-clock cost of the bootstrap
// itself, from the moment the process actually launched Tor (which may be well
// BEFORE the connect clock — the speculative pre-unlock start overlaps
// credential entry) to Connected. It is never capped at `secs` and can exceed
// it. `boot` is omitted, never a sentinel, when this session never started Tor
// (Tor not required) or Tor never reported Connected.
//
// THE `reveal` FIELD. `secs` stops at the first relay answer, but since the reveal gate
// landed (6d997ef3) the contact list waits for the relay answer AND for the
// connect-time unread prime to settle (bounded by a 10 s backstop) — so in
// 39/48 Android and 44/45 iOS measured timelines the user was still looking at
// "Connecting…" when `secs` stopped. `reveal` is the SAME anchor as `secs`
// carried to the frame the list actually appeared in, so the relay derives the
// reveal gate as `reveal - secs` exactly the way it derives the rendezvous as
// `secs - tor`. It is FLOORED at `secs` for that reason (the two share one
// anchor and the reveal can never precede the answer that triggers it) and
// OMITTED entirely — never a sentinel — when this session's list had not
// revealed by the time the report was assembled. Absence is itself honest
// information ("the reveal took longer than the jitter"), which is why nothing
// waits for it: the report is never delayed to make the field appear.
//
// THE CODED TIMELINE (`log`, since 2026-09-14). Sent on every
// connect of a DEBUG-MODE session — never gated on slowness — with no
// user-facing text beyond the Debug mode consent dialog (since 2026-11-03;
// before that, on every connect of every install, silently). It exists because
// the three numbers say WHETHER a connect was slow but
// never WHERE the time went; the timeline names the phases, in the relay's own
// allowlisted vocabulary, so a bad bucket can be attributed to bootstrap vs.
// HSDir fetch vs. rendezvous vs. the first round trip.
//  - Entries are `[offsetSeconds, CODE]`. CODE is a [ConnectionLog.Code] enum
//    NAME verbatim — a CLOSED vocabulary the relay allowlists; a line's TEXT
//    never reaches the wire, and a line with no code is never eligible.
//  - The offset is seconds from the ANCHOR line, [bucketSeconds]-style rounded
//    UP to 5 s and clamped to [0, 3600], forced non-decreasing (a clock step
//    clamps to the previous entry rather than going backwards). Both ends read
//    [ConnectionLog.Line.timestamp] — one clock, never mixed with the monotonic
//    boot anchor.
//  - Anchor = the first buffered line coded `TOR_START` (or `TOR_REUSED`, a
//    warm Android session's start marker), else the first coded line. The window runs from the anchor up to and INCLUDING the first
//    `FIRST_ROUNDTRIP` after it — and, since C4a, on to the first `REVEAL`
//    after THAT when one has already landed (the user's wait ends at the
//    reveal, not at the answer); else to the end.
//  - At most [MAX_LOG_ENTRIES]; see [reduceTimeline] for the reduction ladder.
//    No truncation marker is ever emitted — the array is simply shorter.
//  - The key is OMITTED entirely when nothing is eligible.
//
// What is deliberately NOT in it, and must never be added:
//  - NO capability, NO auth header, NO push/`X-No-Push` or any other custom
//    header. Nothing beyond what every relay call already carries. An inbox id
//    or a read capability here would tie this device's wait time to its inbox
//    set, which is exactly the linkage the rest of the relay protocol avoids.
//  - NO identifier of any kind: no install id, no device model, no locale, no
//    wall-clock timestamp, no Tor circuit/guard/consensus detail. The body is
//    the platform string, the app version, FOUR 5-second buckets and a list of
//    (5-second offset, closed-vocabulary code) pairs. `tor`, `boot` and
//    `reveal` are each a DURATION, and an entry names a PHASE TRANSITION —
//    never which guard, circuit, descriptor, address or fingerprint produced it.
//  - NO FREE TEXT. [ConnectionLog.Line.text] — the narration the panel renders,
//    including Tor's own SUMMARY/WARNING prose — is never read by this file;
//    only [ConnectionLog.Line.code] is. That is the property
//    `timelineField_neverCarriesLineText` pins.
//  - NOTHING is persisted. No vault write, no prefs, no retry queue — a session
//    that cannot send simply does not.
//
// Bounds that keep the report low-entropy: [bucketSeconds] rounds UP to a
// multiple of 5 s and clamps to [5, 3600], so each number is one of 720 coarse
// buckets rather than a precise per-device fingerprint — and the timeline is
// quantised on the same 5 s grid, deduped, capped at [MAX_LOG_ENTRIES] and
// drawn from a closed vocabulary, so it cannot become free-form.
//
// Once per process/session, only while Debug mode is on, after the FIRST relay
// answer, after a uniform random 2-8 s delay ([jitterDelayMs]) so the report is
// not co-timed with the first real relay request; fire-and-forget over the
// session's existing transport, 20 s timeout, no retry.
//
// Known limitation: it rides the SAME Tor circuit as the health
// probe, so the relay can correlate the report with the session that just
// connected. That is inherent — the report is about that session — and is why
// the body carries nothing the relay does not already see from the connection
// itself.
//
// Known limitation of the timeline: a
// coded sequence with 5-second offsets is far more distinguishing than three
// buckets — an unusual phase pattern (a repeated `TOR_RESTART`, a long
// `HSDESC_FAILED` run) is a weak per-SESSION fingerprint the relay can use to
// tell two connects apart, and it describes this device's Tor experience in
// more detail than the connection alone shows. It is bounded by the closed
// vocabulary, the 5 s quantisation, the dedupe, the [MAX_LOG_ENTRIES] cap and
// the fact that nothing is persisted (so there is no cross-session identifier
// to join on), but it is NOT zero.
// ---------------------------------------------------------------------------

object ConnectTelemetry {

    /** Path appended to the relay base URL. No capability, no auth. */
    const val PATH: String = "/telemetry/connect"

    const val PLATFORM_ANDROID: String = "android"
    const val PLATFORM_IOS: String = "ios"

    private const val CONTENT_TYPE = "application/json"

    /** Bucket width in seconds — the reported value is always a multiple of this. */
    const val BUCKET_SECONDS: Int = 5

    /** Reported seconds are clamped into `[MIN_SECONDS, MAX_SECONDS]`. */
    const val MIN_SECONDS: Int = 5
    const val MAX_SECONDS: Int = 3600

    /**
     * The Tor-phase floor is **0**, not [MIN_SECONDS], and that is the whole
     * point of the field: "Tor was already up before this session's connect
     * clock started" is a real, common and interesting outcome (it is what the
     * speculative / at-launch Tor start produces), so it must be reportable
     * rather than rounded up into a fake 5 s. [bucketSeconds]'s argument for a
     * floor does not apply here — 0 is not the only sub-floor value, it is the
     * meaning of the measurement.
     */
    const val MIN_TOR_SECONDS: Int = 0

    /**
     * The `boot` floor is [MIN_SECONDS] like the total, NOT [MIN_TOR_SECONDS]:
     * unlike `tor`, `boot` is never "Tor was already up when the clock
     * started" (its own clock IS Tor's own start), so a real bootstrap is
     * never legitimately 0 — the floor exists only to absorb clock-skew noise
     * near zero, same as [MIN_SECONDS].
     */
    const val MIN_BOOT_SECONDS: Int = MIN_SECONDS

    /**
     * Floor for a TIMELINE offset. `0` for the same reason as
     * [MIN_TOR_SECONDS] and not [MIN_SECONDS]: the anchor entry's own offset is
     * 0 by definition, and every entry inside the first bucket is genuinely
     * "at the start", so rounding those up to 5 would invent a delay.
     */
    const val MIN_OFFSET_SECONDS: Int = 0

    /**
     * Hard cap on `log` entries actually put on the wire. A normal connect
     * produces far fewer; the cap exists so a pathological session (a Tor that
     * restarts in a loop, a stream that fails a hundred times) cannot turn a
     * fixed-size report into an unbounded one. See [reduceTimeline].
     */
    const val MAX_LOG_ENTRIES: Int = 48

    /**
     * Ceiling on the WHOLE request body, matching the relay's (2026-09-14 the
     * relay raised its own limit from 256 to 2048 for exactly this field). The
     * timeline is bounded by construction well below it —
     * `ConnectTelemetryTest.payload_worstCaseBodyStaysUnderTheRelayCeiling`
     * pins the arithmetic against the longest name in [ConnectionLog.Code], so
     * adding a very long code name fails the build's test tier rather than the
     * relay. [payload] still re-checks at runtime and drops `log` (never the
     * numbers) if it is ever exceeded.
     */
    const val MAX_BODY_BYTES: Int = 2048

    /** Fire-and-forget: one attempt, a short budget, never the 60 s default. */
    const val HTTP_TIMEOUT_SECONDS: Int = 20

    /** Uniform random pre-send delay, inclusive bounds. */
    const val MIN_DELAY_MS: Long = 2_000L
    const val MAX_DELAY_MS: Long = 8_000L

    /**
     * Longest app-version string that may reach the wire. A version is
     * `MAJOR.MINOR.PATCH` from `version.properties` on both platforms, so this
     * is pure defence in depth against a malformed bundle/`BuildConfig` value
     * becoming an unbounded field in an unauthenticated request body.
     */
    internal const val MAX_APP_CHARS: Int = 16

    private const val BUCKET_MS = BUCKET_SECONDS * 1000L

    /**
     * [elapsedMs] rounded UP to a whole multiple of [BUCKET_SECONDS] seconds and
     * clamped into `[MIN_SECONDS, MAX_SECONDS]`.
     *
     * Round UP, never to-nearest: the value is a coarse "how long did this take"
     * bucket, and rounding down would let a 4.9 s connect report as 0 — which is
     * both untrue and (being the only value below the floor) distinguishable.
     * Pure; no clock read of its own, so it is unit-testable at the boundaries.
     */
    fun bucketSeconds(elapsedMs: Long): Int = roundUpToBucket(elapsedMs, MIN_SECONDS)

    /**
     * The arithmetic all three bucket functions share; only the [floor] differs.
     * `<= 0` reports [floor]; otherwise [elapsedMs] is rounded UP to a multiple of
     * [BUCKET_SECONDS] and clamped into `[floor, MAX_SECONDS]`.
     */
    private fun roundUpToBucket(elapsedMs: Long, floor: Int): Int {
        if (elapsedMs <= 0L) return floor
        // Early-out before the +BUCKET_MS-1 ceiling arithmetic can overflow on a
        // nonsense input (a caller subtracting two clocks that disagree).
        if (elapsedMs >= MAX_SECONDS * 1000L) return MAX_SECONDS
        val buckets = (elapsedMs + BUCKET_MS - 1L) / BUCKET_MS
        val secs = buckets * BUCKET_SECONDS
        return when {
            secs < floor -> floor
            secs > MAX_SECONDS -> MAX_SECONDS
            else -> secs.toInt()
        }
    }

    /**
     * [elapsedMs] of the TOR phase, rounded UP to a whole multiple of
     * [BUCKET_SECONDS] seconds and clamped into `[MIN_TOR_SECONDS, MAX_SECONDS]`.
     *
     * Identical arithmetic to [bucketSeconds] except for the floor: `<= 0`
     * reports **0** (see [MIN_TOR_SECONDS]), and anything above 0 still rounds
     * up, so a 1 ms measurement never becomes 0 and cannot be confused with
     * "Tor was already up". Pure.
     */
    fun bucketTorSeconds(elapsedMs: Long): Int = roundUpToBucket(elapsedMs, MIN_TOR_SECONDS)

    /**
     * [elapsedMs] of the Tor PROCESS bootstrap (process start → Connected),
     * rounded UP to a whole multiple of [BUCKET_SECONDS] seconds and clamped
     * into `[MIN_BOOT_SECONDS, MAX_SECONDS]`.
     *
     * Identical arithmetic to [bucketSeconds] — including its floor, unlike
     * [bucketTorSeconds] — because `boot` has no "already up" reading: it is
     * timed from Tor's OWN start, so `0` would only ever be clock noise, never
     * a real answer. Pure.
     */
    fun bucketBootSeconds(elapsedMs: Long): Int = roundUpToBucket(elapsedMs, MIN_BOOT_SECONDS)

    // -----------------------------------------------------------------------
    // The reveal (`reveal`) — the ONE piece of session state
    // this object holds, and it holds it for the same reason [send] reads
    // [ConnectionLog] itself: the reveal lands AFTER the first relay answer
    // that arms the report, so a value captured at the call site would almost
    // always be missing. Platforms call [markRevealed] from the same place they
    // emit their `REVEAL` panel line; [send] reads it after the jitter delay.
    //
    // The latch below is right for iOS ONLY: iOS sends one report per
    // CONNECT ANCHOR, and its anchor + report latch live in the process-wide
    // AppState. Since the bounded Tor keep-alive (2026-10-23,
    // BackgroundTorKeepAlive) a process can host a SECOND session — a warm
    // return within the background-task window — and AppState then re-arms its
    // anchor + report latch and calls [startNewRevealSession], so the latch is
    // scoped to the same session as the anchor it is measured against.
    //
    // ANDROID MUST NOT USE IT. Android's report latch and its
    // connect anchor are fields of the RunViewModel, i.e. per SESSION — every
    // foreground return builds a new ViewModel, and when the process survives
    // (always, with the bounded Tor keep-alive; often without it) that new
    // session sends its OWN report. Reading this process latch there stamped
    // session 2's report with session 1's reveal, measured against session 1's
    // anchor — `reveal` then read as `secs` (floored) after a fast first
    // session, or as session 1's slow reveal after a slow one. Android keeps
    // the value in its ViewModel through [latchedReveal] (same set-once and
    // drop-negative rule as [markRevealed]) and passes it to [send] as the
    // `revealElapsedMs` provider.
    // -----------------------------------------------------------------------

    @Volatile
    private var revealElapsedMs: Long? = null

    /**
     * The set-once rule shared by [markRevealed] and Android's per-session
     * field: the FIRST non-negative measurement wins; a negative one (a caller
     * that cannot measure) is dropped, never clamped to an invented 0 s. Pure.
     */
    fun latchedReveal(current: Long?, msSinceConnectAnchor: Long): Long? =
        current ?: msSinceConnectAnchor.takeIf { it >= 0L }

    /**
     * Records how long after the PROCESS's connect anchor (the same anchor
     * `secs` uses — iOS `AppState.connectStartUptime`) the contact list
     * actually revealed. iOS only: Android's anchor is per session, so it
     * keeps its own [latchedReveal] field instead (see the section note above).
     *
     * Set-once: a later in-process re-auth unlock re-reveals the list, but the
     * report this feeds describes the FIRST connect of the session and must not
     * be overwritten by a second one (a warm keep-alive session starts a new one
     * through [startNewRevealSession]). Negative/absurd inputs are dropped rather
     * than clamped — a caller that cannot measure must not be able to invent a
     * 0 s reveal. Never logs, never touches the wire by itself.
     */
    fun markRevealed(msSinceConnectAnchor: Long) {
        revealElapsedMs = latchedReveal(revealElapsedMs, msSinceConnectAnchor)
    }

    /**
     * @see markRevealed — null until the list has revealed this process.
     * Public only because [send]'s default argument reads it; no platform calls
     * it, and nothing may branch on it outside this file.
     */
    fun revealedElapsedMs(): Long? = revealElapsedMs

    /**
     * iOS only: a NEW SESSION begins in a surviving process — a warm return
     * inside the bounded Tor keep-alive window, where AppState re-arms its
     * connect anchor and its report latch at the same moment. Without this the
     * second session's report would carry the FIRST session's reveal, measured
     * against the first session's anchor (the exact defect Android fixed on
     * 2026-10-23 by keeping its value per ViewModel). The previous session's
     * report can no longer be sleeping in its jitter here: `lock()` cancelled it
     * (IosAppController.lock → sessionWorkScope.cancelChildren) before the app ever
     * reached the background. Never logs, never touches the wire.
     */
    fun startNewRevealSession() {
        revealElapsedMs = null
    }

    /** Test seam only: the latch is process-scoped, so a test that sets it must clear it. */
    internal fun resetRevealForTest() {
        revealElapsedMs = null
    }

    /**
     * The `reveal` field's value, or null when it must be OMITTED: the same 5 s
     * rounding as [bucketSeconds], then FLOORED at this report's own [secs].
     *
     * The floor is the mirror image of `tor`'s cap. `tor` shares `secs`'s anchor
     * and is a PART of it, so it is capped above at `secs` to keep `secs - tor`
     * non-negative; `reveal` shares the same anchor and CONTAINS `secs`, so it
     * is floored below at `secs` to keep `reveal - secs` (the reveal gate the
     * relay derives) non-negative. Both defend the same property against the
     * same cause — two measurements taken off one clock at different moments —
     * and neither can be produced by rounding alone (`secs` rounds up too).
     */
    internal fun revealSecondsFor(revealMs: Long?, secs: Int): Int? {
        if (revealMs == null) return null
        return maxOf(bucketSeconds(revealMs), secs)
    }

    // -----------------------------------------------------------------------
    // The coded timeline (`log`) — all pure, all unit-pinned.
    //
    // Deliberately built from [ConnectionLog.Line.code] ALONE. Nothing here
    // reads [ConnectionLog.Line.text]: the panel's narration (which includes
    // Tor's own prose) must be structurally incapable of reaching the wire,
    // which is a stronger guarantee than sanitising it would be.
    // -----------------------------------------------------------------------

    /** One wire entry: a 5 s offset bucket plus a closed-vocabulary code. */
    internal data class TimelineEntry(val offsetSeconds: Int, val code: ConnectionLog.Code)

    /**
     * Seconds from the anchor, rounded UP to a multiple of [BUCKET_SECONDS] and
     * clamped into `[MIN_OFFSET_SECONDS, MAX_SECONDS]` — the same arithmetic
     * (and the same overflow early-outs) as [bucketTorSeconds], whose 0 floor
     * is the right one here (see [MIN_OFFSET_SECONDS]). Kept as its own named
     * function because the two meanings are unrelated: a change to the Tor
     * phase's floor must not silently re-round every timeline offset.
     */
    internal fun offsetSeconds(deltaMs: Long): Int = bucketTorSeconds(deltaMs)

    /**
     * The slice of [lines] a report may describe: only CODED lines, from the
     * ANCHOR (the first `TOR_START` or `TOR_REUSED` in the buffer, else the
     * first coded line)
     * up to and INCLUDING the END OF THE USER'S WAIT — and whatever the session
     * does after that (self-heal, NEWNYM, later probes, the lock) is none of the
     * relay's business. Empty when nothing is coded.
     *
     * The end of the wait is the first `FIRST_ROUNDTRIP` at or after the anchor
     * — and, since C4a, the first `REVEAL` at or after THAT when one has
     * already been buffered, because the contact list is what the user is
     * waiting for and it appears strictly later than the answer (the unread
     * prime gate, up to 10 s). Extending the window is deliberately
     * CONDITIONAL, never a wait: [send] takes its snapshot after the jitter
     * delay, so a reveal that has not happened by then simply leaves the window
     * closing at `FIRST_ROUNDTRIP` exactly as it did before — and the absence of
     * a `REVEAL` in the timeline is itself the (honest, unforgeable) statement
     * that the reveal outlived the report.
     *
     * The `TOR_START` lookup deliberately scans the WHOLE buffer rather than
     * assuming index 0: the panel's ring can already hold pre-Tor lines
     * (session lifecycle, warm-up), and the 300-line ring can equally have
     * evicted the `TOR_START` altogether — hence the first-coded-line fallback
     * instead of "no anchor ⇒ no report".
     */
    internal fun timelineWindow(lines: List<ConnectionLog.Line>): List<ConnectionLog.Line> {
        val coded = lines.filter { it.code != null }
        if (coded.isEmpty()) return emptyList()
        // TOR_REUSED (2026-10-23) is a warm session's start marker: Android's
        // keep-alive adopt (and, same day, iOS AppState.adoptKeptTor — the bounded
        // keep-alive's warm return) clears the ring and logs it instead of TOR_START. It
        // anchors exactly like TOR_START, so a self-heal restart's later
        // TOR_START cannot cut the warm session's own opening off the timeline.
        val torStart = coded.indexOfFirst {
            it.code == ConnectionLog.Code.TOR_START || it.code == ConnectionLog.Code.TOR_REUSED
        }
        val anchor = if (torStart >= 0) torStart else 0
        var end = coded.size - 1
        for (i in anchor..coded.lastIndex) {
            if (coded[i].code == ConnectionLog.Code.FIRST_ROUNDTRIP) {
                end = i
                break
            }
        }
        // …then on to the reveal, when this session already reached it. Searched
        // from the round trip forward, so a `REVEAL` belonging to an EARLIER
        // connect (an in-process re-auth unlock re-reveals the list) can never
        // pull the window backwards or past a second round trip.
        for (i in end..coded.lastIndex) {
            if (coded[i].code == ConnectionLog.Code.REVEAL) {
                end = i
                break
            }
        }
        return coded.subList(anchor, end + 1)
    }

    /**
     * [timelineWindow] turned into `(offset, code)` pairs, offsets measured
     * from the ANCHOR LINE'S OWN timestamp (so the first entry is always 0)
     * and forced NON-DECREASING.
     *
     * The monotonic clamp is not cosmetic: [ConnectionLog.Line.timestamp] is
     * wall clock (`currentTimeMillis`), and Tor's whole job at bootstrap
     * includes noticing the clock is wrong — an NTP/`CLOCK_JUMPED` correction
     * mid-connect would otherwise emit an offset that goes backwards, which is
     * both meaningless to the relay and a needless extra bit about this
     * device. A line that lands before its predecessor is pinned to the
     * predecessor's bucket.
     */
    internal fun timelineEntries(lines: List<ConnectionLog.Line>): List<TimelineEntry> {
        val window = timelineWindow(lines)
        if (window.isEmpty()) return emptyList()
        val anchorAt = window[0].timestamp
        val out = ArrayList<TimelineEntry>(window.size)
        var previous = MIN_OFFSET_SECONDS
        for (line in window) {
            val code = line.code ?: continue   // unreachable: the window is coded-only
            val offset = maxOf(previous, offsetSeconds(line.timestamp - anchorAt))
            previous = offset
            out.add(TimelineEntry(offset, code))
        }
        return out
    }

    /**
     * Brings [entries] down to [MAX_LOG_ENTRIES], in a fixed order so the
     * result is a deterministic function of the input:
     *
     *  1. **Always**, cap or no cap: drop an entry whose code AND bucket both
     *     equal the previous KEPT entry's. Tor emits a dozen
     *     `TOR_BOOTSTRAP_TAG` lines inside one 5 s bucket; on the wire they are
     *     one indistinguishable repeat, so sending them is pure noise — and
     *     dropping them lowers the entropy of the report rather than raising
     *     it. Only consecutive repeats collapse: `A B A` stays `A B A`.
     *  2. If STILL over: shed [isSheddableStreamCode] (`STREAM_*`) entries
     *     OLDEST FIRST. These are the highest-volume, lowest-signal ones — a
     *     hundred stream failures say the same thing the first two did, while
     *     the bootstrap/rendezvous phases they would otherwise push out are the
     *     whole point of the field.
     *  3. If STILL over: shed [isSheddableProbeCode] (every `PROBE_*` EXCEPT
     *     `PROBE_TIMEOUT`) NEWEST FIRST. Newest rather than oldest because the
     *     probes that bracket the START of the wait are what explain it; the
     *     ones nearest the answer are the least surprising entries in the whole
     *     report.
     *  4. If STILL over: drop the OLDEST entries. Offsets were computed against
     *     the anchor BEFORE any dropping, so a surviving entry keeps its true
     *     offset (the first entry simply need not be 0 any more).
     *
     * `PROBE_TIMEOUT` IS DELIBERATELY NOT SHEDDABLE. It is the
     * evidence the cold NEWNYM rung fires on — two consecutive full-budget
     * timeouts — so shedding it erases exactly the run that explains why a
     * `NEWNYM` appears in the same timeline, and made the rung's before/after
     * measurement unreadable on the very reports that needed it. Only rung 4,
     * the last resort, can still take one.
     *
     * No truncation marker is ever emitted: a marker would be a new wire token
     * whose only content is "this device had an unusual number of events",
     * which is exactly the sort of distinguisher this report avoids.
     */
    internal fun reduceTimeline(entries: List<TimelineEntry>): List<TimelineEntry> {
        val deduped = ArrayList<TimelineEntry>(entries.size)
        for (e in entries) {
            val prev = deduped.lastOrNull()
            if (prev != null && prev.code == e.code && prev.offsetSeconds == e.offsetSeconds) continue
            deduped.add(e)
        }
        if (deduped.size <= MAX_LOG_ENTRIES) return deduped

        // A keep-mask rather than three successive list rebuilds: the passes run
        // in opposite directions, and a mask keeps "which entry" unambiguous
        // across them (a rebuilt list would renumber between passes).
        val keep = BooleanArray(deduped.size) { true }
        var toShed = deduped.size - MAX_LOG_ENTRIES

        var i = 0
        while (toShed > 0 && i < deduped.size) {
            if (keep[i] && isSheddableStreamCode(deduped[i].code)) {
                keep[i] = false
                toShed--
            }
            i++
        }

        var j = deduped.lastIndex
        while (toShed > 0 && j >= 0) {
            if (keep[j] && isSheddableProbeCode(deduped[j].code)) {
                keep[j] = false
                toShed--
            }
            j--
        }

        var k = 0
        while (toShed > 0 && k < deduped.size) {
            if (keep[k]) {
                keep[k] = false
                toShed--
            }
            k++
        }

        val out = ArrayList<TimelineEntry>(MAX_LOG_ENTRIES)
        for (idx in deduped.indices) if (keep[idx]) out.add(deduped[idx])
        return out
    }

    /**
     * Shed first: the per-stream `STREAM_*` family, matched BY NAME PREFIX so a
     * code added to it later is covered without a second edit here.
     */
    internal fun isSheddableStreamCode(code: ConnectionLog.Code): Boolean =
        code.name.startsWith("STREAM_")

    /**
     * Shed second: the per-request `PROBE_*` family EXCEPT [ConnectionLog.Code.PROBE_TIMEOUT],
     * which is load-bearing evidence rather than volume — see [reduceTimeline].
     */
    internal fun isSheddableProbeCode(code: ConnectionLog.Code): Boolean =
        code.name.startsWith("PROBE_") && code != ConnectionLog.Code.PROBE_TIMEOUT

    /**
     * `,"log":[[0,"TOR_START"],[5,"TOR_BOOTSTRAP_TAG"]]` — the exact trailing
     * fragment [payload] appends, or `""` for an empty timeline (the key is
     * OMITTED, never sent as `[]`: "nothing was coded" and "the connect had no
     * phases" are different statements and neither needs a wire token).
     *
     * The code name goes through [jsonEscapeString] like every other string
     * here. It cannot need escaping — an enum name is `[A-Z_]` — but this body
     * is built by hand, and the day someone adds a code with a quote in it the
     * request must still be well-formed rather than silently malformed.
     */
    internal fun renderTimeline(entries: List<TimelineEntry>): String {
        if (entries.isEmpty()) return ""
        val sb = StringBuilder(entries.size * 32 + 8)
        sb.append(""","log":[""")
        for ((i, e) in entries.withIndex()) {
            if (i > 0) sb.append(',')
            sb.append('[').append(e.offsetSeconds).append(',').append(jsonEscapeString(e.code.name)).append(']')
        }
        sb.append(']')
        return sb.toString()
    }

    /**
     * The whole timeline pipeline: window ⇒ offsets ⇒ reduce ⇒ render. Pure —
     * it takes the lines rather than reading [ConnectionLog] itself, so it is
     * testable without touching a process-wide singleton, and [send] stays the
     * one place that decides WHEN the snapshot is taken.
     */
    fun timelineField(lines: List<ConnectionLog.Line>): String =
        renderTimeline(reduceTimeline(timelineEntries(lines)))

    /**
     * The EXACT request body, fixed key order `v` / `platform` / `app` /
     * `secs` / `tor` / `boot` / `reveal` / `log`: `{"v":1,"platform":"android","app":"1.6.11","secs":45}`,
     * with the phase split, `{"v":1,"platform":"android","app":"1.6.11","secs":45,"tor":20}`,
     * with both optional numbers,
     * `{"v":1,"platform":"android","app":"1.6.11","secs":45,"tor":20,"boot":38}`,
     * with the reveal, `{…,"boot":38,"reveal":50}`, and with the timeline,
     * `{…,"reveal":50,"log":[[0,"TOR_START"],[35,"SOCKS_READY"],[60,"FIRST_ROUNDTRIP"]]}`.
     *
     * `tor`, `boot` and `reveal` are each OMITTED, never sent as `null`/`-1`,
     * when this session cannot measure them (no Tor at all on the debug/direct
     * path, Tor never reached Connected, a platform that does not know when its
     * daemon came up, or — for `reveal` — a list that had not appeared yet when
     * the report was assembled): a missing key is unambiguous on the relay
     * side, whereas a sentinel would land in the same histogram as a real
     * measurement.
     *
     * [log] is the already-rendered trailing fragment from [timelineField] —
     * `""` (the key omitted) or `,"log":[…]` — and always lands LAST, after
     * `reveal`, so every pre-timeline body is byte-identical to what it was.
     *
     * Both string fields go through [jsonEscapeString] — not because either is
     * attacker-controlled today, but because this body is built by hand and an
     * unescaped quote would silently produce a malformed request rather than a
     * loud failure. Pure; pinned byte-for-byte by ConnectTelemetryTest.
     *
     * The [MAX_BODY_BYTES] re-check is belt and braces over [MAX_LOG_ENTRIES]
     * (which already bounds the fragment far below it): if the body would ever
     * exceed the relay's ceiling, the TIMELINE is dropped and the numbers are
     * still sent, because losing `secs`/`tor`/`boot` to a rejected request
     * would be the worse failure.
     */
    fun payload(
        platform: String,
        app: String,
        secs: Int,
        torSecs: Int? = null,
        bootSecs: Int? = null,
        revealSecs: Int? = null,
        log: String = "",
    ): String {
        val tor = if (torSecs == null) "" else ""","tor":$torSecs"""
        val boot = if (bootSecs == null) "" else ""","boot":$bootSecs"""
        val reveal = if (revealSecs == null) "" else ""","reveal":$revealSecs"""
        val head = """{"v":1,"platform":${jsonEscapeString(platform)},"app":${jsonEscapeString(app)},"secs":$secs$tor$boot$reveal"""
        if (log.isEmpty()) return "$head}"
        val body = "$head$log}"
        return if (body.encodeToByteArray().size <= MAX_BODY_BYTES) body else "$head}"
    }

    /**
     * Keeps only the characters a version string can legitimately contain and
     * caps the length at [MAX_APP_CHARS]. Anything else is DROPPED (never
     * replaced), so a malformed value degrades to a shorter string or to `""`
     * rather than smuggling arbitrary bytes into an unauthenticated body.
     */
    internal fun sanitizeAppVersion(raw: String): String {
        val sb = StringBuilder(MAX_APP_CHARS)
        for (c in raw) {
            if (sb.length >= MAX_APP_CHARS) break
            val ok = (c in '0'..'9') || (c in 'a'..'z') || (c in 'A'..'Z') || c == '.' || c == '-'
            if (ok) sb.append(c)
        }
        return sb.toString()
    }

    /** Uniform random delay in `[MIN_DELAY_MS, MAX_DELAY_MS]`, CSPRNG-drawn. */
    fun jitterDelayMs(): Long =
        MIN_DELAY_MS + secureRandomInt((MAX_DELAY_MS - MIN_DELAY_MS + 1L).toInt()).toLong()

    /**
     * Waits [delayMs], then POSTs one report and forgets about it.
     *
     * Returns whether the request was actually put on the wire (i.e. the
     * transport did not throw) — NOT whether the relay liked it. The response
     * code is deliberately never inspected or logged: 204 and 404 (mock relay)
     * and 500 are all the same outcome to this caller.
     *
     * Skips silently — no log, no ConnectionLog line — when there is no
     * transport, no relay configured, or the platform string is not one of the
     * two constants. Callers pass a nullable [http] precisely so "Tor is not up"
     * needs no branch of its own at the call site.
     *
     * The POST is blocking, so it runs on [ioDispatcher]; the delay is a real
     * suspension, so cancelling the caller's scope (lock / wipe / move quiesce)
     * cancels the report before it is sent.
     *
     * [torElapsedMs] is the milliseconds from the SAME connect start to the
     * moment Tor reported Connected / its SOCKS listener up for this session,
     * or `null` when unknown (no Tor, or a platform that cannot tell). It is
     * bucketed by [bucketTorSeconds] and then capped at `secs`: the two numbers
     * are measured off one anchor, so a `tor` larger than the total could only
     * come from clock disagreement, and shipping it would make `secs - tor`
     * (the rendezvous phase the relay derives) negative.
     *
     * [bootElapsedMs] is the milliseconds from this session's Tor PROCESS
     * start (app launch / speculative start — NOT unlock, and NOT the same
     * anchor as [elapsedMs]) to the moment Tor reported Connected, or `null`
     * when this session never started Tor / Tor never connected. It is
     * bucketed by [bucketBootSeconds] and, unlike `tor`, is NEVER capped at
     * `secs` — the two do not share an anchor, and a bootstrap that ran mostly
     * before unlock legitimately exceeds the post-unlock connect wait.
     *
     * [revealElapsedMs] is the `reveal` field's source (C4a): ms from the SAME
     * connect anchor as [elapsedMs] to the frame the contact list appeared in.
     * A PROVIDER, read after the jitter delay for exactly the reason
     * [logLines] is — the reveal normally lands AFTER the first relay answer
     * that armed this report, so a value captured at the call site would be
     * absent far more often than it is true. The default reads the
     * process-scoped [markRevealed] latch (iOS); Android passes a provider over
     * its per-SESSION field, because its report and anchor are per session.
     * Null (not yet revealed) omits the field; it is never waited for.
     *
     * [logLines] is the CODED TIMELINE source, read AFTER the jitter delay —
     * late on purpose, so the report describes the connect as it actually
     * finished (the panel's last lines land while this coroutine is sleeping),
     * and so neither platform has to collect or pass anything: the default
     * reads [ConnectionLog] itself, which is why this field needed no Android
     * or iOS change at all. A provider rather than a `List` parameter
     * precisely BECAUSE a default argument would be evaluated before the
     * delay. Tests pass their own lines and never touch the singleton.
     *
     * [debugModeEnabled] is the USER'S CONSENT: the report goes
     * out only while Debug mode ([DebugMode.isEnabled]) is on. Required, no
     * default — every caller must say where consent comes from (Android: the
     * ViewModel's `_debugMode` flow; iOS: `IosAppController.isDebugModeEnabled`,
     * belt-and-braces behind AppState's own `debugMode` gate). Read BEFORE the
     * jitter so an opted-out session skips the sleep entirely, and AGAIN after
     * it so a consent revoked during the 2-8 s window still stops the report —
     * the same "consent is not retroactive" rule the debug-log uploader
     * follows. A throwing provider counts as OFF: a wrong `false` costs one
     * diagnostic, a wrong `true` uploads without consent.
     */
    suspend fun send(
        http: RelayHttp?,
        relayBaseUrl: String,
        platform: String,
        appVersion: String,
        elapsedMs: Long,
        debugModeEnabled: () -> Boolean,
        torElapsedMs: Long? = null,
        bootElapsedMs: Long? = null,
        delayMs: Long = jitterDelayMs(),
        revealElapsedMs: () -> Long? = { revealedElapsedMs() },
        logLines: () -> List<ConnectionLog.Line> = { ConnectionLog.snapshot() },
    ): Boolean {
        if (http == null || relayBaseUrl.isEmpty()) return false
        if (platform != PLATFORM_ANDROID && platform != PLATFORM_IOS) return false
        if (!consented(debugModeEnabled)) return false
        val secs = bucketSeconds(elapsedMs)
        val torSecs = torElapsedMs?.let { minOf(bucketTorSeconds(it), secs) }
        val bootSecs = bootElapsedMs?.let { bucketBootSeconds(it) }
        if (delayMs > 0L) delay(delayMs)
        // Re-read AFTER the delay: Debug mode switched off during the jitter
        // window means no report (consent is not retroactive).
        if (!consented(debugModeEnabled)) return false
        // Read AFTER the delay, like the timeline below: the reveal usually
        // lands inside the jitter window. Degrades to "no reveal" on a throwing
        // provider for the same reason the timeline does.
        val revealSecs = try {
            revealSecondsFor(revealElapsedMs(), secs)
        } catch (_: Exception) {
            null
        }
        // Degrade to "no timeline" rather than throw: Android's call site is a
        // bare `viewModelScope.launch`, so an exception here would crash the app
        // on its first connect. `Exception` (not `Throwable`) and only around
        // NON-SUSPENDING work, so it cannot swallow the CancellationException a
        // lock / wipe / move-quiesce raises out of the delay above — that must
        // still abort the report.
        val log = try {
            timelineField(logLines())
        } catch (_: Exception) {
            ""
        }
        val sent = withContext(ioDispatcher) {
            postReport(http, relayBaseUrl, platform, appVersion, secs, torSecs, bootSecs, revealSecs, log)
        }
        if (sent) {
            // Fixed phrase + one number — nothing that identifies the device
            // (ConnectionLog's producer rule; it is visible in RELEASE builds).
            ConnectionLog.append(ConnectionLog.Kind.RELAY, "connect time reported: $secs s")
        }
        return sent
    }

    /** [debugModeEnabled] read with the fail-toward-off rule [send] documents. */
    private fun consented(debugModeEnabled: () -> Boolean): Boolean = try {
        debugModeEnabled()
    } catch (_: Exception) {
        false
    }

    /**
     * The bare POST, split out from [send] so the wire format (URL, method,
     * headers, body, timeout) is testable without a coroutine or a clock.
     * Never throws.
     */
    internal fun postReport(
        http: RelayHttp,
        relayBaseUrl: String,
        platform: String,
        appVersion: String,
        secs: Int,
        torSecs: Int? = null,
        bootSecs: Int? = null,
        revealSecs: Int? = null,
        log: String = "",
    ): Boolean = try {
        http.post(
            "$relayBaseUrl$PATH",
            payload(platform, sanitizeAppVersion(appVersion), secs, torSecs, bootSecs, revealSecs, log).encodeToByteArray(),
            CONTENT_TYPE,
            emptyMap(),
            HTTP_TIMEOUT_SECONDS,
        )
        true
    } catch (_: Exception) {
        // Fire-and-forget: a dead circuit is not an error anyone acts on, and
        // the message could name the relay host. Silent by design.
        false
    }
}

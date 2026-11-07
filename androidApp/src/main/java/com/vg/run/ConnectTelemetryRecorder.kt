package com.vg.run

import android.os.SystemClock
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * The anonymous connect-time report (ConnectTelemetry.kt, commonMain) for one
 * RunViewModel: the connect / Tor-process anchors, the `tor` / `boot` / `reveal`
 * phase stamps, the report itself, the reveal mark, the Debug-mode first log
 * flush and the pre-unlock boot observer. It owns its four jobs and six anchors;
 * its dependencies are handed in ([scope] is the ViewModel's `viewModelScope`;
 * [relayHttp] / [relayTransport] / [externalProxyMode] are read at use time).
 *
 * The report is sent once per ViewModel; it survives lockForReauth. Android never
 * resets [connectTelemetrySent], unlike iOS `beginWarmTorSession`, because the
 * ViewModel normally dies with the Activity. It SURVIVES lockForReauth by design:
 * the ViewModel lives on across an in-process re-auth lock, so the re-unlock sends
 * no second report — it is the same user wait.
 *
 * [now] is the monotonic clock (`SystemClock.elapsedRealtime`), injectable so the
 * set-once anchors are JVM-testable.
 */
internal class ConnectTelemetryRecorder(
    private val scope: CoroutineScope,
    private val isRelayReachable: StateFlow<Boolean>,
    private val contactsReady: StateFlow<Boolean>,
    private val debugMode: StateFlow<Boolean>,
    private val relayHttp: () -> RelayHttp?,
    private val relayTransport: () -> RelayHttp?,
    private val externalProxyMode: () -> Boolean,
    private val now: () -> Long = { SystemClock.elapsedRealtime() },
) {
    private var connectTelemetryJob: Job? = null

    /**
     * Monotonic anchor for "when this session's relay connect began"
     * ([android.os.SystemClock.elapsedRealtime], so a wall-clock/NTP step cannot
     * move it). Set ONCE per ViewModel by [markConnectStart] and never reset —
     * the ~100 s self-heal Tor restart, the manual Reconnect and a move
     * resume all re-enter `RunViewModel.connectViaTor`, and from the user's side that is still
     * ONE wait, not a fresh one. Null until the first connect attempt.
     */
    var connectStartElapsedMs: Long? = null
        private set

    /**
     * Once per ViewModel; survives lockForReauth. Never reset on lock (a re-auth
     * unlock sends no second report); a new foreground session builds a new
     * ViewModel and reports its own connect.
     */
    private var connectTelemetrySent = false

    /**
     * This session's `reveal` measurement: ms from [connectStartElapsedMs] to
     * the frame the contact list appeared in, set once by [armRevealMark]
     * through [ConnectTelemetry.latchedReveal]. Per ViewModel ON PURPOSE: it
     * used to live in ConnectTelemetry's process-scoped latch, so a later session in a surviving process (the Tor keep-alive's warm
     * return, above all) reported the FIRST session's reveal against its own
     * `secs`. Written on Main by [armRevealMark]; read by the report coroutine.
     */
    @Volatile
    private var revealElapsedMsThisSession: Long? = null

    /**
     * The TOR half of the connect wait: milliseconds from
     * [connectStartElapsedMs] to the first moment `RunViewModel._torState` became
     * `Connected` this session, or null while that has not happened (and on the
     * debug/direct path, which has no Tor — the `tor` field is then OMITTED
     * from the report rather than sent as a zero).
     *
     * Set ONCE, for the same reason the anchor is: a self-heal restart or a
     * manual Reconnect does not restart the user's wait, and re-measuring it
     * would report the LAST bootstrap instead of the one they waited through.
     *
     * **Zero is the interesting value**, not a missing measurement: a Tor that
     * the speculative pre-unlock start had already finished bootstrapping is
     * `Connected` on the monitor's very first (replayed) emission, i.e. within
     * milliseconds of the anchor — which is exactly the speculative start's
     * payoff, and the number that makes `secs - tor` (the rendezvous phase) the
     * honest remainder. Written and read on the Main thread only (the monitor
     * collector and [armConnectTelemetry] are both viewModelScope/Main).
     */
    private var torConnectedElapsedMs: Long? = null

    /**
     * Monotonic anchor for "when this session's Tor PROCESS was started"
     * ([android.os.SystemClock.elapsedRealtime]) — the `boot` field,
     * distinct from [connectStartElapsedMs]: Tor's process may
     * be launched well BEFORE the connect clock (the speculative pre-unlock
     * start overlaps credential entry), so this needs its own anchor rather
     * than reusing that one. Set ONCE per ViewModel, by whichever of
     * `RunViewModel.startSpeculativeTor` or the first fresh-instance branch of
     * `RunViewModel.connectViaTor` actually launches this session's Tor process — a
     * self-heal restart or a manual Reconnect that replaces the TorManager
     * instance does NOT move it, same "one wait" reasoning as
     * [connectStartElapsedMs]. Stays null forever on the debug/direct path
     * (no Tor at all), which is exactly when `boot` must be omitted.
     */
    private var torProcessStartedAtElapsedMs: Long? = null

    /**
     * The BOOT half of the connect wait (`boot` field): milliseconds
     * from [torProcessStartedAtElapsedMs] to the first moment Tor reported
     * `Connected` this session, or null while that has not happened (or on the
     * debug/direct path). Set ONCE ([firstBootStamp]) for the same "one wait"
     * reason as [torConnectedElapsedMs]. Unlike [torConnectedElapsedMs] it is
     * NEVER capped against anything — it shares no anchor with `secs`, so it
     * can legitimately exceed the post-unlock connect wait.
     *
     * Stamped by [armBootStamp] PRE-UNLOCK. It used to be written only
     * by `RunViewModel.startTorMonitor`, which is attached at unlock and is therefore
     * replayed an already-`Connected` state — so the number was
     * `max(true bootstrap, time-to-unlock)` and the relay's Android `boot`
     * histogram was really an unlock-latency histogram (dev: boot p50 40 s
     * against SOCKS_READY at 5 s).
     */
    private var bootConnectedElapsedMs: Long? = null

    /**
     * Records the start of this session's relay connect, the first time only.
     * Called from both [RunViewModel.onVaultOpened] branches — the Tor path (via
     * `RunViewModel.connectViaTor`) and the debug/emulator direct path — so the anchor exists
     * however the transport is built.
     *
     * Deliberately NOT anchored on `RunViewModel.startSpeculativeTor`: that bootstrap overlaps
     * the user's credential entry, and counting a slow typist's thinking time as
     * "the relay took N seconds" would make the number meaningless.
     */
    fun markConnectStart() {
        if (connectStartElapsedMs == null) {
            connectStartElapsedMs = now()
        }
    }

    /**
     * Sends the anonymous connect-time report once, on the FIRST
     * [isRelayReachable] `true` of this session — the same moment
     * `RunViewModel.armPushPromptForFirstRelayContact` fires, and the same evidence the
     * contact list is revealed on.
     *
     * Everything that makes this safe lives in [ConnectTelemetry]: no
     * capability, no auth, no identifier, 5-second buckets, a 2-8 s jitter, one
     * attempt, no persistence. Here we only supply the elapsed time, the
     * platform string and the app version, and we take the transport from the
     * same seam every other non-MessageManager relay call uses
     * (`RunViewModel.currentRelayHttp` — a null there simply means "no live transport",
     * and the report is dropped rather than retried).
     *
     * Cancelled with the session's other relay jobs (lock / wipe / move quiesce),
     * so a lock during the jitter window silently drops the report.
     *
     * DEBUG MODE ONLY: the report is sent only while the user's
     * Debug mode consent ([debugMode]) is on — [ConnectTelemetry.send] reads
     * `RunViewModel._debugMode` before and after its jitter and drops the report otherwise.
     * The once-per-session latch below is still set, so a consent granted later
     * in the same session does not produce a late report measured from a
     * connect the user never asked to be measured; the next session reports.
     * iOS sibling: AppState.checkRelayReachability's connect-telemetry block →
     * IosAppController.reportConnectTime.
     */
    private fun armConnectTelemetry() {
        connectTelemetryJob?.cancel()
        // External SOCKS proxy mode: no connect report at all. The user runs
        // this mode to see EVERY request Rún makes; an automatic one they did
        // not ask for has no place in it (and its Tor/boot split would be
        // meaningless — there is no embedded Tor). iOS skips it the same way.
        if (externalProxyMode()) return
        connectTelemetryJob = scope.launch {
            isRelayReachable.first { it }
            if (connectTelemetrySent) return@launch
            // Latched BEFORE the suspending send, so a reachability flap (or a
            // re-armed job after an in-process re-auth unlock) can never produce
            // a second report in this session.
            connectTelemetrySent = true
            val startedAt = connectStartElapsedMs ?: return@launch
            ConnectTelemetry.send(
                http = relayHttp(),
                relayBaseUrl = RelayConfig.BASE_URL,
                platform = ConnectTelemetry.PLATFORM_ANDROID,
                appVersion = BuildConfig.VERSION_NAME,
                elapsedMs = now() - startedAt,
                // Consent: the live Debug mode flag, re-read by send() after the
                // jitter so a toggle-off mid-window still stops the report.
                debugModeEnabled = { debugMode.value },
                // Phase split: null on the debug/direct path (no Tor) and in the
                // impossible case where the relay answered before Tor connected,
                // which omits the field rather than inventing a number.
                torElapsedMs = torConnectedElapsedMs,
                // boot: same omission rule, off the Tor-PROCESS anchor instead of
                // the connect anchor — see torProcessStartedAtElapsedMs.
                bootElapsedMs = bootConnectedElapsedMs,
                // THIS session's reveal, read after the jitter like the default
                // provider — never the process latch (see revealElapsedMsThisSession).
                revealElapsedMs = { revealElapsedMsThisSession },
            )
        }
    }

    private var revealMarkJob: Job? = null

    /**
     * THE END OF THE USER'S WAIT: one line and one measurement at the instant [contactsReady] first
     * turns true — i.e. the frame the contact list actually appears in.
     *
     * Why this is its own signal and not [isRelayReachable]: since the reveal
     * gate landed (6d997ef3) the list also waits for the connect-time unread
     * prime to settle (bounded by `RunViewModel.UNREAD_PRIME_REVEAL_CAP_MS`), and in 39 of 48
     * measured Android timelines that prime had NOT finished when the relay
     * answered. `secs` therefore stopped several seconds before the user saw
     * anything, and nothing measured the difference.
     *
     * [revealElapsedMsThisSession] is set-once per SESSION (this ViewModel —
     * not ConnectTelemetry's process latch, which only iOS may use) and is read
     * by the report AFTER its jitter delay, so a reveal that lands while the report
     * sleeps is still counted; one that outlives it omits the field rather than
     * delaying the report (see [ConnectTelemetry.send]).
     *
     * Re-armed on every unlock like [armConnectTelemetry]: the panel is cleared
     * on lock, so an in-process re-auth unlock should narrate its own reveal —
     * while the reveal value underneath stays on the FIRST connect of this
     * session. iOS sibling: `AppState.recomputeContactsReady`.
     */
    private fun armRevealMark() {
        revealMarkJob?.cancel()
        revealMarkJob = scope.launch {
            contactsReady.first { it }
            connectStartElapsedMs?.let {
                revealElapsedMsThisSession = ConnectTelemetry.latchedReveal(
                    revealElapsedMsThisSession,
                    now() - it,
                )
            }
            // Fixed phrase, no number and no identifier — the panel's own
            // timestamp is the number. iOS emits this string verbatim.
            ConnectionLog.append(
                ConnectionLog.Kind.RELAY,
                "contact list revealed",
                ConnectionLog.Code.REVEAL,
            )
        }
    }

    private var debugLogConnectJob: Job? = null

    /**
     * Debug mode (Settings → Debug mode): first anonymous log flush of the
     * session, armed on the SAME signal as [armConnectTelemetry] (the first
     * [isRelayReachable] `true`) and jittered the same way so the two are not
     * co-timed. A no-op whenever [debugMode] is off; re-armed by
     * [RunViewModel.onVaultOpened] like every other per-session relay job, and cancelled
     * alongside [connectTelemetryJob] on every path that tears the session's
     * relay jobs down. [DebugLogUploader.flush] is documented never to throw,
     * so this deliberately has no try/catch of its own — one would risk
     * swallowing a [CancellationException] from a lock/wipe
     * racing this coroutine instead of letting it propagate.
     */
    private fun armDebugLogUploadOnConnect() {
        debugLogConnectJob?.cancel()
        debugLogConnectJob = scope.launch {
            isRelayReachable.first { it }
            if (!debugMode.value) return@launch
            delay(2_000L + secureRandomInt(6_000).toLong())
            val transport = relayTransport() ?: return@launch
            withContext(Dispatchers.IO) {
                DebugLogUploader.flush(
                    transport,
                    ConnectTelemetry.PLATFORM_ANDROID,
                    BuildConfig.VERSION_NAME,
                    DebugLogUploader.REASON_CONNECT,
                )
            }
        }
    }

    /**
     * The pre-unlock BOOTSTRAP OBSERVER (see [armBootStamp]) — one number,
     * no side effects. Armed beside the speculative Tor start and cancelled on
     * the same paths as `RunViewModel.relayWarmupJob`.
     */
    private var bootStampJob: Job? = null

    /**
     * PRE-UNLOCK BOOTSTRAP OBSERVER — the only job of this
     * coroutine is to stamp [bootConnectedElapsedMs] at the instant Tor first
     * reports `Connected`.
     *
     * WHY IT EXISTS. `RunViewModel.startTorMonitor` is attached at UNLOCK, so on the common
     * path (speculative start, user types, Tor finishes bootstrapping while they
     * type) its collector is replayed an already-`Connected` state and the stamp
     * it takes is `now(unlock) − torProcessStart`, i.e.
     * `max(true bootstrap, time-to-unlock)`. The dev-relay device runs showed exactly that:
     * `boot` p50 40 s against SOCKS_READY at 5 s and CIRCUIT_OK at 10 s — the
     * relay's Android `boot` histogram was an UNLOCK-LATENCY histogram. iOS
     * never had the defect (its `TorManager.$state` sink is installed in
     * `AppState.init`, i.e. pre-unlock); this restores parity.
     *
     * Deliberately minimal — it is pre-unlock code:
     *  - it reads a `StateFlow` and writes ONE number. No vault, no
     *    [MessageManager], no relay call, no UI state, nothing that needs a
     *    session (the warm-up beside it remains the only pre-unlock network
     *    activity, unchanged);
     *  - it does NOT touch [torConnectedElapsedMs] (`tor` is measured off the
     *    post-unlock connect anchor by design) and does not move any anchor;
     *  - FIRST STAMP WINS ([firstBootStamp]): the ViewModel owns the value, so
     *    it survives activity recreation, and the post-unlock monitor's own
     *    stamp becomes a no-op rather than overwriting this with a later number.
     *    A self-heal restart / manual Reconnect never re-stamps either.
     *
     * Completes on the first `Connected`; cancelled where the pre-unlock
     * warm-up is (session teardown, and the fresh-instance branch of
     * `RunViewModel.connectViaTor` that stops the instance it is watching — that path
     * attaches the monitor at Tor start, so the stamp is honest there anyway).
     */
    fun armBootStamp(tor: TorManager) {
        bootStampJob?.cancel()
        bootStampJob = scope.launch {
            tor.state.first { it is TorManager.ConnectionState.Connected }
            markBootConnected()
        }
    }

    /**
     * Stamps [bootConnectedElapsedMs] the FIRST time Tor reports `Connected`
     * this session — from either the pre-unlock [armBootStamp] observer or
     * `RunViewModel.startTorMonitor`, whichever gets there first (the pre-unlock one does,
     * on every launch where the user is not already past the PIN). Both run on
     * Main, so the read-modify-write needs no lock.
     */
    fun markBootConnected() {
        bootConnectedElapsedMs = firstBootStamp(
            existingMs = bootConnectedElapsedMs,
            anchorMs = torProcessStartedAtElapsedMs,
            nowMs = now(),
        )
    }

    /**
     * The three per-unlock arms, in their old order: the connect-time report
     * (sent once per process after the first relay answer), the end of the
     * user's wait (torn down with every other per-session relay job), and the
     * Debug-mode first log flush (gated on [debugMode] internally).
     */
    fun armOnUnlock() {
        armConnectTelemetry()
        armRevealMark()
        armDebugLogUploadOnConnect()
    }

    /**
     * boot anchor: this session's Tor PROCESS start. Set-once, mirroring
     * [markConnectStart] — called by the speculative pre-unlock start and by the
     * fresh-instance branch of connectViaTor (the case where no speculative start
     * ran ahead of it); a later self-heal/Reconnect never moves it. See
     * [torProcessStartedAtElapsedMs].
     */
    fun markTorProcessStart() {
        if (torProcessStartedAtElapsedMs == null) {
            torProcessStartedAtElapsedMs = now()
        }
    }

    /**
     * Connect-telemetry phase split: the FIRST Connected of this session,
     * measured off the same anchor as the total. A Tor the speculative start
     * already finished lands here on the StateFlow's replayed first emission,
     * i.e. ~0 ms after the anchor — which is the honest report, not a missing
     * one. Set-once, so the self-heal restart / manual Reconnect never overwrite
     * it. See [torConnectedElapsedMs].
     */
    fun markTorConnected() {
        if (torConnectedElapsedMs == null) {
            val nowMs = now()
            connectStartElapsedMs?.let { anchor ->
                torConnectedElapsedMs = (nowMs - anchor).coerceAtLeast(0L)
            }
        }
    }

    /** Cancels the three per-unlock jobs [armOnUnlock] starts (lock, wipe, move quiesce). */
    fun cancelConnectJobs() {
        connectTelemetryJob?.cancel()
        revealMarkJob?.cancel()
        debugLogConnectJob?.cancel()
    }

    /** Cancels the pre-unlock boot observer ([armBootStamp]). */
    fun cancelBootStamp() {
        bootStampJob?.cancel()
    }

    // Read-only views for tests and the session-job coverage guard.
    internal val connectTelemetrySentForTest: Boolean get() = connectTelemetrySent
    internal val torConnectedElapsedMsForTest: Long? get() = torConnectedElapsedMs
    internal val torProcessStartedAtElapsedMsForTest: Long? get() = torProcessStartedAtElapsedMs
    internal val bootConnectedElapsedMsForTest: Long? get() = bootConnectedElapsedMs
}

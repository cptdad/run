package com.vg.run

import android.app.Application
import android.os.SystemClock
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.io.File

// ---------------------------------------------------------------------------
// TorManager — manages the embedded Tor process lifecycle.
//
// Runs the Tor binary directly (TorProcess.kt says why).
//
// The app is foreground-only: the ViewModel owns this TorManager and stops
// it when the Activity finishes on background. There is no foreground service,
// so Android 12+ is free to reap the Tor child process once the app is
// backgrounded — Tor re-bootstraps on the next launch (RunViewModel starts an
// instance SPECULATIVELY from its init block, before the vault is unlocked, and
// the unlock adopts it — see RunViewModel.startSpeculativeTor/connectViaTor).
//
// Bootstrap progress and the SOCKS listener port are read from Tor's NOTICE LOG
// FILE (`Log notice file <dataDir>/tor.log`), never from the process streams:
// stdout and stderr are merged (`redirectErrorStream(true)`) and discarded to
// /dev/null. Commands go over an AF_UNIX ControlSocket (cookie auth); async
// events over a SECOND control socket ([TorControlEventReader]).
//
// PORT-LOGGING POLICY (the one rule; other comments in this file point here):
// the EMBEDDED Tor's loopback SOCKS port (127.0.0.1:NNNN) may be logged for
// bootstrap diagnostics — it is local and non-sensitive. An EXTERNAL proxy's
// port is never logged, and no remote address / .onion host / fingerprint /
// circuit id is ever logged.
//
// Phase index (top to bottom):
//   session hooks (constructor) → companion constants → [ConnectionState] →
//   process + working-dir + retry fields → command-channel fields → rung
//   fields → [start] (one-shot retry) → [startAttempt] and its phases
//   (per-process reset, working dirs, spawn, notice-log tail to the SOCKS port,
//   control + event channels, [BootstrapWatcher] — the only Connected
//   publisher) → command channel (connect, startup kick, AUTHENTICATE, wire
//   helpers) → bootstrap-stall rung → NEWNYM → HSFETCH / relay address race /
//   descriptor hedge → hung onion-circuit rung (+ CLOSECIRCUIT) →
//   guard-channel + network-restore kicks → [stop] / [stopAndDiscardState] →
//   the control cookie (top level).
//
// Split out of this file (same package): TorrcWriter.kt (working-dir names,
// ephemera purge, torrc text), TorNoticeLogTail.kt (NOTICE-line parsers +
// complete-lines tail), TorProcess.kt (binary, spawn, notice-log wait, child
// termination), TorControlWire.kt (the command socket's stream-level read /
// write helpers). TorControlEvents.kt is the event socket.
// ---------------------------------------------------------------------------

class TorManager(
    private val application: Application,
    /**
     * The SESSION's descriptor hedge ([DescriptorHedge], 2026-10-12), RESOLVED AT
     * EVERY USE through the session owner's rebindable hooks
     * (`TorSessionHooks.descriptorHedge` → `RunViewModel.descriptorHedge`): every
     * TorManager of a session drives the same instance, so its never-replenished
     * budget survives a Tor restart inside the session; and a Tor kept warm into
     * the NEXT session (bounded keep-alive) drives that session's instance. A null
     * provider leaves the HS_DESC hook unwired; a null result is inert. iOS
     * sibling: `TorManager.descriptorHedge`, installed from
     * `IosAppController.descriptorHedge` — which is one per PROCESS, not per
     * session: a warm iOS return keeps its spent budget
     * (`AppState.beginWarmTorSession`). Which rule is intended is open (review P7).
     */
    private val descriptorHedge: (() -> DescriptorHedge?)? = null,
    /**
     * The hedge's session gate (`RunViewModel.relayAnsweredForCircuitWatchdog`):
     * has the session had a relay answer yet? The hedge acts only before it. Null
     * keeps the hedge inert. iOS sibling: `TorManager.descriptorHedgeAnsweredGate`.
     */
    private val descriptorHedgeAnswered: (() -> Boolean)? = null,
    /**
     * Descriptor-stage early recovery ([DescriptorHedge.Decision.stageStalled]):
     * handed to the session owner (`TorSessionHooks.onDescriptorStageStalled` →
     * `RunViewModel.onDescriptorStageStalled`), which spends the NEWNYM through
     * its shared early-NEWNYM gate — the session's NEWNYM budget lives there, not
     * here. Must not block. Null = inert. iOS sibling:
     * `TorManager.onDescriptorStageStalled`.
     */
    private val onDescriptorStageStalled: (() -> Unit)? = null,
    /**
     * Called (on an IO thread) right after an app-fired `SIGNAL NEWNYM` got its
     * `250` from Tor, whichever rung fired it — the session owner aborts the
     * current transport's in-flight probe/peek
     * ([MessageManager.noteNewCircuitRequested]). iOS sibling:
     * `TorManager.onNewCircuitAccepted`. Null = nothing to notify.
     */
    private val onNewCircuitAccepted: (() -> Unit)? = null,
    /**
     * Hung onion-circuit rung gate ([HsCircuitWatchdog]), installed by the
     * session owner (`RunViewModel.relayAnsweredForCircuitWatchdog`): has the
     * session had a relay answer yet? The rung acts only before it. Null keeps
     * the rung inert. iOS sibling: `TorManager.hsCircuitAnsweredGate`.
     */
    private val hsCircuitAnswered: (() -> Boolean)? = null,
    /**
     * Bootstrap-stall rung opt-in ([TorBootstrapStall], iOS sibling
     * `TorManager.bootstrapStallKickEnabled`), set by the session owner
     * (RunViewModel, for every instance it builds). It needs no session input —
     * a bootstrap below 100 % means this Tor process cannot have produced a
     * relay answer — so it is a switch, not a gate; every rule lives in the
     * shared predicate. False keeps an instance inert (the same null-is-inert
     * convention as [descriptorHedge]).
     */
    private val bootstrapStallKick: Boolean = false,
) {

    companion object {
        private const val BOOTSTRAP_TIMEOUT_MS = 90_000L

        // Control-channel (NEWNYM self-heal) tuning. Tor binds its ControlSocket
        // and writes the auth cookie very early in startup — well before it opens
        // the SOCKS listener we detect — so these bounded retries mostly absorb a
        // partial-write race on the cookie, not a genuinely absent socket.
        private const val CONTROL_CONNECT_ATTEMPTS = 20
        private const val CONTROL_CONNECT_RETRY_MS = 300L
        // SO_TIMEOUT on the control socket so a read never blocks forever if the
        // daemon wedges mid-reply. A read that times out leaves its reply in the
        // stream, so every caller drops the socket on it (TorControlWire.kt).
        private const val CONTROL_READ_TIMEOUT_MS = 3_000
        // (The reply-line cap is CONTROL_REPLY_MAX_BYTES in TorControlWire.kt.)
        /** Upper bound on holding Connected for the event subscription ([BootstrapWatcher.publishConnected]). */
        private const val EVENTS_SUBSCRIBE_HOLD_MS = 1_500L
        /** The only shape a pinned HSFETCH argument may have (HsDirLedger). */
        private val SERVER_ARGUMENT = Regex("SERVER=\\$[0-9A-F]{40}")
        /** The only shape an HSFETCH address may have (v3, no `.onion`). */
        private val V3_ADDRESS = Regex("[a-z2-7]{56}")
        /** Disable + re-enable the network in ONE write (one control-connection
         *  read, so the network is never left off across a main-loop turn). */
        private const val CMD_TOGGLE_NETWORK = "SETCONF DisableNetwork=1\r\nSETCONF DisableNetwork=0\r\n"
        /** Re-enable alone: the toggles' one retry and the startup kick. */
        private const val CMD_ENABLE_NETWORK = "SETCONF DisableNetwork=0\r\n"
        /** Fresh circuits ([requestNewCircuit]). */
        private const val CMD_NEWNYM = "SIGNAL NEWNYM\r\n"
        /** Read back the SOCKS listener a guard-channel kick re-bound. */
        private const val CMD_GETINFO_SOCKS_LISTENERS = "GETINFO net/listeners/socks\r\n"
    }

    /**
     * Tor lifecycle as seen by the session owner ([state]).
     *
     * | From                 | To                     | Where                                   |
     * |----------------------|------------------------|-----------------------------------------|
     * | Idle                 | Bootstrapping(0)       | [startAttempt], every attempt           |
     * | Bootstrapping(n)     | Bootstrapping(m < 100) | pre-SOCKS log tail, then the watcher (notice-log percent) |
     * | Bootstrapping        | Connected(port)        | the watcher's `publishConnected` — the ONLY publisher: percent reached 100, no SOCKS-port move pending (`connectedMayPublish`), SETEVENTS hold ≤ [EVENTS_SUBSCRIBE_HOLD_MS] |
     * | Bootstrapping        | Failed(…)              | "Tor log never appeared" / "No SOCKS port" / "Tor process died" / "Start failed: …" |
     * | Connected            | Failed("Tor process died") | the watcher, daemon exited after bootstrap |
     * | any                  | Idle                   | [stop] (a cancelled [start] writes nothing, so stop's Idle stands) |
     * | Failed (attempt 1)   | Idle → Bootstrapping(0)| [start]'s one-shot discard-and-retry    |
     *
     * Outside this class, RunViewModel's `_torState` also carries
     * `Failed("external proxy unreachable")` in external SOCKS proxy mode
     * (ExternalProxyModeSourceTest) — TorManager never writes that one.
     *
     * [Connected.socksPort] is the port the daemon had when Connected was
     * PUBLISHED. Only a bootstrap-stall kick BEFORE Connected changes it. After a
     * guard-channel / network-restore kick the listener moves but the state is
     * never republished: the live port is `SocksPortRedirect.resolve(original)`,
     * which every Tor client already follows per connection.
     */
    sealed class ConnectionState {
        data object Idle : ConnectionState()
        data class Bootstrapping(val progress: Int) : ConnectionState()
        data class Connected(val socksPort: Int) : ConnectionState()
        data class Failed(val error: String) : ConnectionState()
    }

    private val _state = MutableStateFlow<ConnectionState>(ConnectionState.Idle)
    val state: StateFlow<ConnectionState> = _state.asStateFlow()

    // Written on the IO-dispatched start()/startAttempt() coroutine, read AND
    // written by stop() — which RunViewModel calls from the Main thread
    // (torManager?.stop()). `@Volatile` so a stop() racing a start() on another
    // dispatcher always observes the latest assignment instead of a stale null
    // or a torn write.
    @Volatile private var torProcess: Process? = null

    /**
     * Set by [stop], cleared by [start]. There is a
     * window between `ProcessBuilder.start()` and the `torProcess = process`
     * assignment where a concurrent [stop] sees a null `torProcess` and destroys
     * nothing — leaving an orphaned Tor child alive for the life of the app.
     * `@Volatile` so the spawning thread observes a stop that happened on another.
     */
    @Volatile private var stopped = false

    // The post-bootstrap process watcher runs on its own
    // detached scope. Hold its Job so stop() can cancel it — otherwise a clean
    // stop() (which sets Idle) is clobbered ~1 s later when the watcher observes
    // the death IT caused and writes Failed("Tor process died"). Previously only
    // benign because RunViewModel happened to cancel the monitor first.
    // `@Volatile`: assigned from the IO-dispatched start() coroutine, cancelled
    // from stop() on the Main thread — same cross-dispatcher pattern as
    // [torProcess].
    @Volatile private var watcherJob: Job? = null

    /**
     * Tor's DataDirectory — STABLE across restarts, and deliberately PRESERVED
     * (2026-08-01). It holds the entry-guard `state` file plus
     * Tor's certs; keeping it means a relaunch reuses the same guards and the
     * cached consensus instead of re-sampling guards and re-fetching everything
     * cold. A cold Tor reaches "Bootstrapped 100%" in seconds but then cannot
     * complete an onion rendezvous for MINUTES, so every relaunch used to re-pay
     * that; and re-sampling entry guards on every launch defeats the entire point
     * of guards (an anonymity cost, not just a latency one).
     *
     * Trade-off: `tor_direct/` now survives an
     * ordinary background/relaunch, so an AFU image can show Tor was used. It is
     * still destroyed by EVERY wipe path — `WipeRoutine.wipePersistentState`
     * deletes both trees, and [stopAndDiscardState] deletes them again after the
     * daemon is confirmed dead. It lives in `filesDir` (`/data/user/<u>/<pkg>/`),
     * i.e. FBE **credential-encrypted** storage — unreadable before first unlock
     * — never `createDeviceProtectedStorageContext()`; and the app sets
     * `android:allowBackup="false"`, so it never leaves the device.
     *
     * Per-instance session subdirs are GONE with the per-stop wipe that motivated
     * them: a stable path is what makes reuse possible, and nothing
     * deletes a live dir on an ordinary stop any more.
     */
    private val dataDir = File(application.filesDir, "$TOR_ROOT_DIR_NAME/$TOR_DATA_DIR_NAME")

    /**
     * Tor's CacheDirectory (cached consensus + microdescriptors). Also stable and
     * preserved. Lives under `cacheDir`, so Android is free to evict it under
     * storage pressure — Tor simply re-fetches; the guard state that matters most
     * is in [dataDir] under `filesDir` and is durable.
     */
    private val cacheDir = File(application.cacheDir, "$TOR_ROOT_DIR_NAME/$TOR_CACHE_DIR_NAME")

    /**
     * One-shot latch for the corrupt-data-dir fallback in [start]. A preserved
     * DataDirectory is the one new way a start can fail that a fresh one could
     * not (a truncated `state` / half-written cache file from a power loss), so a
     * failed bootstrap discards it and retries EXACTLY once. Per instance, and a
     * fresh TorManager is created per session.
     *
     * `@Volatile` since the speculative pre-unlock start (P6b). The note that
     * used to sit here justified leaving it non-volatile on the grounds that the
     * retry was touched only on the IO dispatcher and was invisible outside this
     * class. The second half of that is no longer true: [isMidInternalRetry] is
     * read from the MAIN thread by RunViewModel's Tor restart paths, which must
     * not tear a just-wiped-and-recovering Tor down mid-retry. Both flags of the
     * retry latch are kept volatile so they can never drift apart under a reader
     * that sees one and not the other; same precedent as [torProcess] and
     * [stopped].
     */
    @Volatile private var purgedForRetry = false

    /**
     * True from the moment [start] COMMITS to its one-shot discard-and-retry
     * until that second attempt resolves. Surfaced as [isMidInternalRetry].
     *
     * Raised BEFORE [stopAndDiscardState], not merely before the second
     * [startAttempt]: the discard is part of the retry, and an external restart
     * landing inside it destroys the working dirs the retry is in the middle of
     * rebuilding — and can leave a second Tor child contending for a
     * DataDirectory lock the dying one has not released yet.
     */
    @Volatile private var midInternalRetry = false

    /**
     * True while [start]'s internal corrupt-state retry is in flight — i.e. while
     * this instance is ALREADY making a fresh bootstrap attempt on freshly
     * discarded working dirs.
     *
     * RunViewModel's external restart paths (`restartTor`, the ~100 s relay-stall
     * self-heal) DEFER while this is true rather than tearing Tor down: what they
     * would do is exactly what is already happening, and doing it on top of the
     * retry cancels the recovery just as it starts.
     */
    val isMidInternalRetry: Boolean get() = midInternalRetry

    /**
     * [SystemClock.elapsedRealtime] at the top of [start], or `0` before any
     * start.
     *
     * Exists so a consumer that ADOPTS an already-running instance (RunViewModel's
     * speculative pre-unlock start) can re-anchor its own bootstrap watchdogs to
     * when Tor really began instead of to when the vault happened to open: a Tor
     * 60 s into a stuck bootstrap must not be handed a fresh full-length grace
     * period just because the user was slow typing their PIN.
     *
     * Set once per [start], deliberately NOT per [startAttempt]: it measures the
     * whole "Tor has been trying" span as the user experiences it, internal retry
     * included. [SystemClock.elapsedRealtime] rather than a wall clock because it
     * is monotonic and unaffected by NTP or user clock changes.
     *
     * PER-INSTANCE, not per-session — a `forceFresh` restart creates a new
     * [TorManager] with its own fresh value. That is exactly why the `boot`
     * telemetry field (ConnectTelemetry.kt, 2026-09-11) does NOT read this
     * directly: `ConnectTelemetryRecorder.torProcessStartedAtElapsedMs` (owned
     * by RunViewModel, so still ViewModel-scoped) is a separate anchor captured
     * at the SAME moment (`RunViewModel.startSpeculativeTor` / the first
     * fresh-instance branch of `connectViaTor`) but set-once across the whole
     * session, so a mid-session restart cannot move it.
     */
    @Volatile
    var startedAtElapsedMs: Long = 0L
        private set

    // ---------------------------------------------------------------------
    // Control channel (SIGNAL NEWNYM self-heal — Android parity with iOS
    // `TorManager.requestNewCircuit` (TorManager.swift), which AppState's rungs
    // call).
    //
    // A cheap in-process circuit-recovery lever: a cookie-authenticated Tor
    // control channel over an AF_UNIX ControlSocket (`cp`) inside the
    // app-private, FBE-encrypted Tor data dir. RunViewModel's relay-stall
    // self-heal fires SIGNAL NEWNYM here as an escalation rung BEFORE the
    // expensive full-process restartTor() (kill + ~90 s cold re-bootstrap).
    //
    // HARD SECURITY CONSTRAINT: NEVER a TCP ControlPort. A localhost TCP
    // control listener is discoverable/bindable by any co-installed app and
    // regresses the hardening (SocksPort auto + control-socket readback). The socket + cookie live inside dataDir (filesDir/
    // tor_direct/data), which is app-private FBE storage and destroyed by
    // every wipe path — never world-accessible, never a network listener.
    //
    // Lazily/robustly established after SOCKS-port detection: a failed
    // control connect/auth NEVER fails Tor bring-up (Tor still works via
    // SOCKS without our control channel), it just degrades to
    // "restart-only self-heal, NEWNYM unavailable" exactly like today.
    // ---------------------------------------------------------------------

    /** Serialises the one control socket across the connect helper and every
     *  command (NEWNYM, HSFETCH, CLOSECIRCUIT, the two network toggles, the SOCKS
     *  read-back) — the write+read of a control command must be atomic on the
     *  shared stream. */
    private val controlMutex = Mutex()

    /** The authenticated control socket, or null when the channel is not up.
     *  `@Volatile`: published on the IO-dispatched connect coroutine, read by
     *  every command on any dispatcher and closed by [stop] on Main. */
    @Volatile private var controlSocket: android.net.LocalSocket? = null

    /** The detached coroutine that connects + authenticates the control
     *  channel. Cancelled by [stop] (same pattern as [watcherJob]). */
    @Volatile private var controlJob: Job? = null

    /**
     * The SECOND control connection, subscribed to Tor's async `650` events so
     * the onion half of a connect (descriptor fetch, intro, rendezvous, stream)
     * reaches the connection-log panel — see TorControlEvents.kt. Deliberately
     * NOT the [controlSocket] above: a `SETEVENTS` there would interleave event
     * lines into [readControlReplyOk]'s one-line NEWNYM/HSFETCH reply parsing.
     *
     * Purely diagnostic. Created after SOCKS detection, closed by [stop];
     * `@Volatile` for the same cross-dispatcher reason as [controlSocket].
     */
    @Volatile private var eventReader: TorControlEventReader? = null

    // ---------------------------------------------------------------------
    // Descriptor hedge (2026-10-12; iOS sibling TorManager.swift
    // checkDescriptorHedge). Decision: the SHARED [DescriptorHedge] (session-
    // scoped, constructor argument). Here only the ONE timer and the HSFETCH on
    // the COMMAND socket ([requestHsDescriptorFetchCode]). The event reader feeds
    // every HS_DESC of the relay's onion ([onRelayDescriptorEvent]); after each
    // event / NEWNYM / fire the timer is re-armed from
    // [DescriptorHedge.msUntilNextCheck]. Timer fields guarded by
    // [descriptorHedgeLock].
    // ---------------------------------------------------------------------

    private val descriptorHedgeLock = Any()
    /** The armed check, or null. Replaced (never stacked) on every re-arm. */
    private var descriptorHedgeJob: Job? = null
    /** Bumped on every re-arm / disarm so a check that already woke cannot run stale. */
    private var descriptorHedgeGen = 0L
    /** The relay's descriptor race (2026-10-23, [RelayAddressRace]): process-wide,
     *  it describes Tor's descriptor cache. Single address = inert (today's flow). */
    private val relayRace: RelayAddressRace = RelayEndpoints.race

    /** Which HSDirs served / failed the relay's descriptor in THIS Tor process
     *  (2026-10-08): the watchdog's HSFETCH is pinned to the last good one. ONE
     *  LEDGER PER CONFIGURED ADDRESS (2026-10-23 — each has its own HSDir set). Kept
     *  across NEWNYM on purpose; reset per [startAttempt]. Fingerprints inside are
     *  SENSITIVE — never logged. Thread-safe on its own. */
    private val hsDirLedger = HsDirLedgerSet(relayRace.slotCount)

    /** Hung intro / rendezvous circuit rung (2026-10-08): `CLOSECIRCUIT` the hung
     *  circuit so Tor retries it — no NEWNYM. Thread-safe; reset per
     *  [startAttempt]; circuit ids inside are never logged. */
    private val hsCircuitWatchdog = HsCircuitWatchdog()
    /** Every configured address of the relay, `HSFETCH` form — equality matching
     *  only, NEVER logged. */
    private val relayHsAddresses: List<String> = relayRace.hsFetchAddresses

    // ---------------------------------------------------------------------
    // Bootstrap-stall rung (2026-10-06; iOS sibling TorManager.swift
    // noteBootstrapProgressForStall / kickStalledBootstrap). The percent standing
    // still for [TorBootstrapStall.STALL_MS] inside the ladder → ONE pipelined
    // `SETCONF DisableNetwork=1` + `=0` on the COMMAND socket
    // ([kickStalledBootstrap]), at most [TorBootstrapStall.MAX_KICKS] per start
    // attempt. Progress arrives from BOTH the notice-log watcher (every 5th
    // percent) and the event socket's STATUS_CLIENT BOOTSTRAP (every step).
    //
    // THE SOCKS PORT MOVES. DisableNetwork closes the SOCKS listener and the
    // re-enable re-binds `SocksPort auto` on a NEW port (see TorBootstrapStall).
    // The watcher is the only publisher of Connected(port), so the two are
    // serialised under [bootStallLock]: a kick refuses once Connected has been
    // published ([connectedPublished]), and a kick that may have reached Tor
    // raises [socksMovePending], which holds Connected back until the watcher
    // has read Tor's NEW listener line — one written at or past
    // [kickLogMark], the log length captured before the command was written.
    // The old port is never handed out again; a lost line fails CLOSED (stays
    // Bootstrapping, the 90 s / 100 s ladder takes over).
    // All fields below are guarded by [bootStallLock].
    // ---------------------------------------------------------------------

    private val bootStallLock = Any()
    private var bootPctHighest = 0
    private var bootPctChangedAtMs = 0L
    private var bootKicksFired = 0
    /** [SystemClock.elapsedRealtime] of this attempt's last kick; 0 = none. */
    private var bootLastKickAtMs = 0L
    private var bootStallJob: Job? = null
    private var bootStallGen = 0L
    /** The watcher has published Connected(port) this attempt. */
    private var connectedPublished = false
    /** A kick may have moved the SOCKS listener; Connected waits for the new one. */
    private var socksMovePending = false
    /** Log length when the pending kick was written (see the header above). */
    private var kickLogMark = Long.MAX_VALUE

    /** [SystemClock.elapsedRealtime] of the last NEWNYM written to this Tor's
     *  control channel; 0 = none. The kick keeps
     *  [TorBootstrapStall.NEWNYM_SPACING_MS] from it. */
    @Volatile private var lastNewnymAtMs = 0L

    /**
     * Bootstraps Tor, reusing the preserved working dirs ([dataDir]).
     *
     * Narrow self-heal for the one failure mode preservation introduces: if the
     * attempt fails to yield a SOCKS port (Tor refused to start, died, or timed
     * out) and no [stop] intervened, the preserved dirs are DISCARDED and the
     * bootstrap is retried once, logged. Tor normally repairs its own cache, so
     * this should never fire — but a corrupt cache must degrade to a slow cold
     * start, never to a permanently unbootstrappable app.
     *
     * NOT re-entrant: a second concurrent call spawns a second Tor child against
     * the same DataDirectory. Exactly one [start] per instance.
     */
    suspend fun start(): Int {
        startedAtElapsedMs = SystemClock.elapsedRealtime()
        // Connection-log panel (release-visible, identifier-free by construction).
        ConnectionLog.append(ConnectionLog.Kind.SYSTEM, "Tor starting", ConnectionLog.Code.TOR_START)
        val port = startAttempt()
        if (port > 0 || stopped || purgedForRetry) return port
        purgedForRetry = true
        // P6b: publish the retry BEFORE the discard below, so an external
        // restarter observing this instance sees the whole recovery window —
        // discard included — and stands down for all of it.
        midInternalRetry = true
        platformLogWarn(
            "TorManager",
            "bootstrap failed with a preserved data dir — discarding it and retrying once",
        )
        // The user sees ~90 s of nothing followed by a second bootstrap from 0%;
        // without this line the panel makes that look like a hang rather than a
        // deliberate recovery. Kind.TOR (it is a daemon-lifecycle event, not a
        // session one) and no detail beyond the fixed phrase.
        ConnectionLog.append(
            ConnectionLog.Kind.TOR,
            "bootstrap retry after state discard",
            ConnectionLog.Code.TOR_INTERNAL_RETRY,
        )
        // Via stopAndDiscardState(), not a bare wipe: the failed attempt only
        // SIGTERMed its child, and a Tor still holding the DataDirectory lock
        // would fail the retry too. stop() waits for real exit first.
        stopAndDiscardState()
        return try {
            startAttempt()
        } finally {
            // Cleared however the attempt resolves — success, failure, or a
            // cancellation thrown out of it (which is what an external stop()
            // racing the retry looks like). A latch left stuck true would
            // disarm the external self-heal for the rest of the session.
            midInternalRetry = false
        }
    }

    /**
     * One bootstrap attempt: spawn, notice-log tail to the SOCKS port, control +
     * event channels, then the [BootstrapWatcher] (the only Connected publisher).
     * Returns the SOCKS port, or -1. Every phase is a function below, in order.
     */
    private suspend fun startAttempt(): Int {
        resetPerProcessState()
        _state.value = ConnectionState.Bootstrapping(0)
        platformLog("TorManager", "start() — beginning Tor initialization")
        try {
            val torBinary = locateTorBinary(application.applicationInfo.nativeLibraryDir)
            val files = prepareWorkingDirs()
            platformLog("TorManager", "starting Tor process...")
            val process = spawnTorChild(torBinary, files.torrc) ?: return -1
            if (!awaitNoticeLog(files.log)) return failAttempt(process, "Tor log never appeared")
            val socksPort = tailUntilSocksPort(process, files.log) ?: return failAttempt(process, "No SOCKS port")
            platformLog("TorManager", "SOCKS port detected: $socksPort")
            ConnectionLog.append(
                ConnectionLog.Kind.TOR,
                "SOCKS listener ready on port $socksPort",
                ConnectionLog.Code.SOCKS_READY,
            )
            val reader = startControlAndEventChannels(process)
            launchBootstrapWatcher(process, files.log, socksPort, reader)
            return socksPort
        } catch (e: kotlinx.coroutines.CancellationException) {
            onAttemptCancelled()
            throw e
        } catch (e: Exception) {
            return onAttemptFailed(e)
        }
    }

    /**
     * Per-Tor-child state, reset at the top of every attempt. A new Tor child
     * inside the SAME session: its HS state starts over, the session's hedge
     * budget does NOT (DescriptorHedge.resetForNewTorProcess).
     */
    private fun resetPerProcessState() {
        stopped = false                       // fresh run, clear any prior stop
        disarmDescriptorHedge()
        descriptorHedge?.invoke()?.resetForNewTorProcess()
        hsDirLedger.resetForNewTorProcess()
        hsCircuitWatchdog.resetForNewTorProcess()
        // A fresh Tor child has no descriptor: race the addresses again once it
        // is Connected (the winner stays the base URL until then).
        relayRace.noteTorHsStateReset()
        // A fresh Tor child owns fresh ports: forget any guard-channel kick's
        // listener move — the new number may even equal a blocked old one.
        SocksPortRedirect.reset()
        // ...and no circuit of any SOCKS isolation class: a rendezvous hedge's
        // adopted class (RendezvousHedge) is meaningless to the new child. iOS runs
        // tor_main once per process, so its class can only ever die with the process.
        SocksIsolation.reset()
        resetBootStall()
    }

    /** The torrc and notice log of one attempt, both inside [dataDir]. */
    private data class TorSessionFiles(val torrc: File, val log: File)

    /**
     * Readies the PRESERVED working dirs (see [dataDir]) and writes this attempt's
     * torrc. Deletes only stale sibling dirs and the per-session ephemera.
     */
    private fun prepareWorkingDirs(): TorSessionFiles {
        // Remove any tor_direct child that is NOT one of the two retained
        // working dirs — legacy per-session dirs (`s1`, `s2`, …) from builds
        // that wiped on every start, and anything a crashed launch stranded.
        purgeStaleTorDirs()
        // The dirs themselves are PRESERVED (see [dataDir]) — mkdirs is a
        // no-op when they already exist, and only the strictly per-session
        // files inside are removed.
        dataDir.mkdirs()
        cacheDir.mkdirs()
        purgeSessionEphemera(dataDir)
        val torrc = File(dataDir, "torrc")
        val logFile = File(dataDir, "tor.log")
        torrc.writeText(buildTorrc(dataDir.absolutePath, cacheDir.absolutePath, logFile.absolutePath))
        return TorSessionFiles(torrc, logFile)
    }

    /**
     * Spawns the Tor child ([spawnTorProcess]) and publishes it as [torProcess].
     * Null when a [stop] raced the spawn (the new child is already destroyed).
     */
    private fun spawnTorChild(torBinary: File, torrc: File): Process? {
        val process = spawnTorProcess(torBinary, torrc)
        torProcess = process
        // A stop() that landed inside the spawn window saw a null
        // torProcess and destroyed nothing. Now the spawner notices and cleans
        // up the child it just created, so no orphan survives the race.
        if (stopped) {
            platformLogWarn("TorManager", "stop() raced the spawn — destroying the new Tor child")
            try { process.destroy() } catch (_: Exception) {}
            torProcess = null
            return null
        }
        platformLog("TorManager", "Tor process started, PID alive=${process.isAlive}")
        return process
    }

    /** An attempt that cannot continue: publish Failed([reason]), SIGTERM the child, -1. */
    private fun failAttempt(process: Process, reason: String): Int {
        _state.value = ConnectionState.Failed(reason)
        process.destroy()
        return -1
    }

    /**
     * Tails the notice log until the SOCKS listener line (or [BOOTSTRAP_TIMEOUT_MS],
     * or the child's death). Returns the port, or null.
     *
     * The percent must ALWAYS be presented while connecting: the watcher
     * only starts once this loop returns, so every early "Bootstrapped NN%"
     * line is published from here (else the UI would sit at Bootstrapping(0)
     * for this whole phase). The Connected(socksPort) transition stays
     * solely in the [BootstrapWatcher] (never published from here, even at
     * pct>=100) so the post-bootstrap-death contract is unaffected.
     */
    private suspend fun tailUntilSocksPort(process: Process, logFile: File): Int? {
        var detectedPort = -1
        val tail = TorNoticeLogTail(logFile)
        val socksPort = withTimeoutOrNull(BOOTSTRAP_TIMEOUT_MS) {
            while (process.isAlive) {
                for (line in tail.pollLines()) {
                    TorNoticeLog.parseSocksListenerPort(line)?.let { detectedPort = it }
                    val progress = TorNoticeLog.parseBootstrapProgress(line)
                    if (progress != null) {
                        // Percent + the closed-vocabulary phase TAG only. The
                        // daemon runs with SafeLogging 1, but the SUMMARY prose
                        // that used to be appended here is free-form text on a
                        // release-visible panel — dropped at the producer, not
                        // left to ConnectionLog.redact() (defence in depth).
                        // The CODE is the mapped phase group (C2b,
                        // TorBootstrapPhase) so a bootstrap stall is
                        // attributable on the wire, where only the code
                        // travels; an unknown tag keeps the old catch-all.
                        ConnectionLog.append(
                            ConnectionLog.Kind.TOR,
                            TorNoticeLog.bootstrapLogLine(progress),
                            TorBootstrapPhase.codeFor(progress.tag),
                        )
                        if (progress.percent < 100) {
                            _state.value = ConnectionState.Bootstrapping(progress.percent)
                        }
                    }
                }
                if (detectedPort > 0) break
                delay(200)
            }
            detectedPort
        }
        if (socksPort == null || socksPort <= 0) {
            platformLogError("TorManager", "no SOCKS port detected (timeout=${BOOTSTRAP_TIMEOUT_MS}ms, process.alive=${process.isAlive})")
            return null
        }
        return socksPort
    }

    /**
     * Brings up the command channel and the event channel, both off the
     * bootstrap path. Returns the event reader (the watcher holds Connected for
     * its SETEVENTS).
     */
    private fun startControlAndEventChannels(process: Process): TorControlEventReader {
        // Establish the cookie-authenticated control channel for the
        // SIGNAL NEWNYM self-heal. Launched on its OWN detached coroutine
        // so it never delays bootstrap and its failure is non-fatal — Tor
        // is already usable via SOCKS. See [connectControlChannel] /
        // [requestNewCircuit]. Cancelled by [stop] (which also closes the
        // socket) just like [watcherJob].
        controlJob = CoroutineScope(Dispatchers.IO).launch { connectControlChannel() }

        // The ONION half of the connect, on its OWN control connection (see
        // TorControlEvents.kt for why it must not share the command socket).
        // Diagnostics only: start() never waits on it and its failure only
        // costs panel detail, never connectivity.
        val reader = TorControlEventReader(
            dataDir = dataDir,
            torAlive = { !stopped && process.isAlive },
            relayRace = if (descriptorHedge == null) null else relayRace,
            onRelayDescriptorEvent = ::onRelayDescriptorEvent,
            // Bootstrap-stall rung: the event stream reports every percent
            // step, the notice log only every 5th — same granularity iOS
            // sees. Only the integer arrives (TorBootstrapStall parser).
            onBootstrapProgress = if (bootstrapStallKick) ::noteBootstrapProgressForStall else null,
            onControlEvent = if (hsCircuitAnswered == null) null else ::onHsCircuitEvent,
        )
        eventReader = reader
        reader.start()
        return reader
    }

    /**
     * Continues tailing the log in the background for bootstrap state updates
     * ([BootstrapWatcher]). Once bootstrapped, the log file is deleted to avoid
     * leaving forensic evidence of Tor usage on disk.
     */
    private fun launchBootstrapWatcher(process: Process, logFile: File, socksPort: Int, reader: TorControlEventReader) {
        val watcher = BootstrapWatcher(process, logFile, socksPort, reader)
        watcherJob = CoroutineScope(Dispatchers.IO).launch { watcher.run() }
    }

    /**
     * The post-SOCKS notice-log watcher — the ONLY publisher of Connected (see
     * [ConnectionState]). Then keeps watching the process after bootstrap so a
     * later death is reflected.
     */
    private inner class BootstrapWatcher(
        private val process: Process,
        private val logFile: File,
        socksPort: Int,
        private val reader: TorControlEventReader,
    ) {
        private val tail = TorNoticeLogTail(logFile)
        private var bootstrapped = false
        // The port Connected will carry. Starts as the detected one and
        // changes only if a bootstrap-stall kick moved the listener (see
        // the rung's header) — adopted from Tor's own NEW listener line.
        private var currentSocksPort: Int = socksPort
        // Tor reached 100 % while a kick's listener move was still
        // unconfirmed: Connected is held until the new port is known.
        private var doneAwaitingPort = false

        suspend fun run() {
            while (process.isAlive) {
                for ((lineStart, line) in tail.pollLinesAt()) {
                    if (bootstrapped) break
                    onLine(lineStart, line)
                }
                if (onPollEnd()) break
                delay(500)
            }
            if (!bootstrapped) {
                platformLogError("TorManager", "Tor process died before bootstrap completed")
                _state.value = ConnectionState.Failed("Tor process died")
                logFile.delete()
            } else {
                awaitPostBootstrapDeath()
            }
        }

        private suspend fun publishConnected() {
            // HS_DESC capture (2026-10-08): the first onion request of the
            // session follows Connected within milliseconds, and its
            // HS_DESC REQUESTED/RECEIVED name the HSDir the HsDirLedger
            // pins re-fetches to. The event socket subscribes right after
            // SOCKS detection — normally long before 100 % — but a warm
            // daemon can finish bootstrapping first. Hold Connected until
            // SETEVENTS is live, bounded: a reader that cannot subscribe
            // completes the signal itself, and the cap keeps a stuck one
            // from ever delaying the connect by more than this.
            if (!reader.subscribed.isCompleted) {
                withTimeoutOrNull(EVENTS_SUBSCRIBE_HOLD_MS) { reader.subscribed.await() }
            }
            bootstrapped = true
            platformLog("TorManager", "CONNECTED — SOCKS5 on port $currentSocksPort")
            // iOS sibling: TorManager.swift's circuit-established
            // observer logs its own CIRCUIT_OK TOR line (`circuit established`,
            // no port).
            ConnectionLog.append(
                ConnectionLog.Kind.TOR,
                "circuit established - connected, SOCKS5 on port $currentSocksPort",
                ConnectionLog.Code.CIRCUIT_OK,
            )
            _state.value = ConnectionState.Connected(currentSocksPort)
            // Several onion addresses (2026-10-23): race their descriptors
            // now — HS_DESC is subscribed (held above). No-op for one
            // address; the control-channel connect covers a socket that is
            // not up yet.
            if (controlSocket != null) launchRelayAddressRace()
        }

        private suspend fun onLine(lineStart: Long, line: String) {
            TorNoticeLog.parseSocksListenerPort(line)?.let { port ->
                if (adoptMovedSocksListener(lineStart)) {
                    platformLog("TorManager", "SOCKS listener re-bound after the bootstrap re-kick: $currentSocksPort -> $port")
                    currentSocksPort = port
                }
            }
            if (doneAwaitingPort) {
                if (connectedMayPublish()) publishConnected()
                return
            }
            val progress = TorNoticeLog.parseBootstrapProgress(line) ?: return
            val pct = progress.percent
            // NEVER the raw NOTICE line: its timestamp is LOCAL time
            // (`Sep 14 14:34:55.612 [notice] …`) sitting next to this
            // buffer's UTC prefix, which leaks the device's timezone on
            // every launch — and Debug mode (user-consented) now uploads
            // redacted LogBuffer lines to the relay even in RELEASE
            // builds, so this is no longer a dev-only log. Use the same
            // identifier-free percent+tag reduction as the connection-log
            // line just below.
            platformLog("TorManager", "bootstrap: ${TorNoticeLog.bootstrapLogLine(progress)}")
            // Phase-group code, same mapping as the pre-SOCKS
            // tail ([tailUntilSocksPort], C2b) — one table, both call sites.
            ConnectionLog.append(
                ConnectionLog.Kind.TOR,
                TorNoticeLog.bootstrapLogLine(progress),
                TorBootstrapPhase.codeFor(progress.tag),
            )
            if (bootstrapStallKick) noteBootstrapProgressForStall(pct)
            if (pct >= 100) {
                if (connectedMayPublish()) {
                    publishConnected()
                } else {
                    doneAwaitingPort = true
                    platformLog("TorManager", "bootstrap done — holding Connected until the re-bound SOCKS listener is read")
                }
            } else {
                _state.value = ConnectionState.Bootstrapping(pct)
            }
        }

        /** End of one poll. True = bootstrapped (log deleted), stop polling. */
        private suspend fun onPollEnd(): Boolean {
            // A kick that turned out NOT to reach Tor clears the pending
            // move without any log line arriving — re-check once per poll.
            if (!bootstrapped && doneAwaitingPort && connectedMayPublish()) publishConnected()
            if (bootstrapped) {
                logFile.delete()
                return true
            }
            return false
        }

        /**
         * Keep watching the Tor process AFTER bootstrap. A Connected(socksPort)
         * left standing after Tor died would keep MessageManager dialing
         * 127.0.0.1:<socksPort> — a freed port a local app could bind
         * (relay-capability-token leak / metadata DoS). Reflect a
         * post-bootstrap death so the Connected(port) state is torn down
         * (RunViewModel nulls MessageManager on a non-Connected state),
         * parity with iOS's stale-port handling.
         */
        private suspend fun awaitPostBootstrapDeath() {
            while (process.isAlive) { delay(1000) }
            platformLogWarn("TorManager", "Tor process died after bootstrap — marking disconnected")
            _state.value = ConnectionState.Failed("Tor process died")
        }
    }

    /**
     * A CANCELLED start is not a failure. The old generic catch wrote
     * Failed("Start failed: …cancelled"), which clobbered the Idle a
     * concurrent stop() had just published — leaving the UI showing a Tor
     * error after a perfectly clean shutdown. Still destroy the child we
     * spawned; the caller rethrows so structured concurrency sees the cancellation.
     */
    private fun onAttemptCancelled() {
        platformLog("TorManager", "start() cancelled — cleaning up without a Failed state")
        try { torProcess?.destroy() } catch (_: Exception) {}
        torProcess = null
    }

    /**
     * An unexpected throw between spawn and bootstrap
     * otherwise leaves the spawned Tor child running (torProcess was set) — the
     * Failed branch upstream only nulls MessageManager, it doesn't stop(). Destroy
     * the child here so a failed start can't leak a live Tor process.
     */
    private fun onAttemptFailed(e: Exception): Int {
        platformLogError("TorManager", "start() failed: ${e.javaClass.simpleName}")
        try { torProcess?.destroy() } catch (_: Exception) {}
        torProcess = null
        _state.value = ConnectionState.Failed("Start failed: ${e.message}")
        return -1
    }

    // ---------------------------------------------------------------------
    // Command channel: connect + AUTHENTICATE, the startup kick, and the wire
    // helpers every command below uses (see the field block's header).
    // ---------------------------------------------------------------------

    /**
     * Connects the AF_UNIX ControlSocket and AUTHENTICATEs with the cookie, with
     * bounded retries. Best-effort: on exhaustion it logs and returns, leaving
     * [controlSocket] null (restart-only self-heal). Never fails Tor bring-up.
     *
     * The cookie is required to be EXACTLY [TOR_CONTROL_COOKIE_LEN] bytes before
     * we authenticate (mirror of iOS P4a): AUTHENTICATE is effectively one-shot,
     * so a short read of a cookie Tor is still writing must RETRY, never be sent
     * as the secret.
     */
    private suspend fun connectControlChannel() {
        val socketFile = File(dataDir, TOR_CONTROL_SOCKET_NAME)
        val cookieFile = File(dataDir, TOR_CONTROL_COOKIE_NAME)
        var attempt = 0
        // The startup kick is tried on the FIRST authenticated socket only: a
        // kick whose reply was lost drops that socket, and the reconnect below
        // must not risk the same stall again (the kick is only a latency lever).
        var kickPending = true
        while (attempt < CONTROL_CONNECT_ATTEMPTS && !stopped) {
            attempt++
            // Require the socket present AND a full-length cookie before trying.
            val cookie = readTorControlCookie(cookieFile)
            if (cookie == null || !socketFile.exists()) {
                // Zero the copy of an unused cookie (each iteration re-reads it).
                cookie?.fill(0)
                delay(CONTROL_CONNECT_RETRY_MS)
                continue
            }
            val sock = try {
                android.net.LocalSocket().apply {
                    connect(
                        android.net.LocalSocketAddress(
                            socketFile.absolutePath,
                            android.net.LocalSocketAddress.Namespace.FILESYSTEM,
                        ),
                    )
                    setSoTimeout(CONTROL_READ_TIMEOUT_MS)
                }
            } catch (e: Exception) {
                platformLogWarn("TorManager", "control socket connect failed (attempt $attempt/$CONTROL_CONNECT_ATTEMPTS): ${e.javaClass.simpleName}")
                cookie.fill(0)
                delay(CONTROL_CONNECT_RETRY_MS)
                continue
            }
            val authed = try {
                authenticateControl(sock, cookie)
            } catch (e: Exception) {
                platformLogWarn("TorManager", "control AUTHENTICATE threw: ${e.javaClass.simpleName}")
                false
            } finally {
                // Same as the event reader: the byte copy of the auth secret is
                // zeroed once used (the hex String sent with AUTHENTICATE lives
                // until GC; it cannot be zeroed).
                cookie.fill(0)
            }
            if (authed) {
                var kickDropped = false
                controlMutex.withLock {
                    // Replace defensively: a stop() may have raced us.
                    controlSocket?.let { try { it.close() } catch (_: Exception) {} }
                    if (stopped) {
                        try { sock.close() } catch (_: Exception) {}
                        controlSocket = null
                    } else {
                        controlSocket = sock
                        // STARTUP KICK (2026-10-26): still inside the lock, before any
                        // other user can share the socket — see sendStartupKick. Only
                        // while Tor is still bootstrapping; a daemon that is already
                        // Connected has nothing left to hurry.
                        if (kickPending && _state.value !is ConnectionState.Connected) {
                            kickPending = false
                            if (!sendStartupKick(sock)) {
                                // Never reuse a socket whose reply was not read.
                                try { sock.close() } catch (_: Exception) {}
                                controlSocket = null
                                kickDropped = true
                            }
                        }
                    }
                }
                if (kickDropped && !stopped) {
                    delay(CONTROL_CONNECT_RETRY_MS)
                    continue
                }
                if (controlSocket != null) {
                    platformLog("TorManager", "control channel authenticated — NEWNYM self-heal available")
                    // Connected was published before the control channel came up:
                    // the descriptor race starts here instead (idempotent).
                    if (_state.value is ConnectionState.Connected) launchRelayAddressRace()
                }
                return
            }
            // Full-length cookie but auth rejected: not a partial-write race, and
            // unlikely to self-correct — but a bounded retry is cheap.
            try { sock.close() } catch (_: Exception) {}
            delay(CONTROL_CONNECT_RETRY_MS)
        }
        platformLogWarn(
            "TorManager",
            "control channel unavailable after $attempt attempt(s) — restart-only self-heal (NEWNYM disabled for this session)",
        )
    }

    /**
     * STARTUP KICK (2026-10-26, connect-time lever): one no-op
     * `SETCONF DisableNetwork=0` right after AUTHENTICATE.
     *
     * WHY: Tor arms a fixed ONE-SECOND timer when it enters its main loop and runs
     * none of its periodic events before it fires — including the one that builds
     * the first circuit (`mainloop.c` `initialize_periodic_events_cb`, which Tor
     * itself annotates "for backward-compatibility reasons; it might not actually
     * be necessary"). Any successful SETCONF rescans the periodic events at once
     * (`config.c` `set_options` → `periodic_events_on_new_options` →
     * `periodic_event_enable` → `mainloop_event_activate`), so re-asserting the
     * torrc's own `DisableNetwork 0` launches the first guard connection within
     * milliseconds of this call instead of ~1.05 s later — measured on prod debug
     * sessions as a flat 1.02–1.09 s between "control channel authenticated" and
     * the first "or connection launched" on BOTH platforms.
     *
     * SAFE: the value does not change, so no guard or circuit reset
     * (`config.c` resets those only on guard-related option changes) and the
     * `SocksPort auto` listener is reused, not rebound. Fail-safe: a refused
     * reply simply leaves Tor's own timer to fire as before; a LOST one (false)
     * also costs the socket — the caller reconnects once, without a second kick.
     * Caller holds
     * [controlMutex]; this socket never carries async 650s (no SETEVENTS here),
     * so the one-line reply read cannot be confused by an event.
     */
    private fun sendStartupKick(sock: android.net.LocalSocket): Boolean {
        // A lost reply (timeout, over-long line, I/O) may still arrive later and
        // would then be read as the NEXT command's reply — the stream is out of
        // sync, so the caller drops this socket (TorControlWire.kt's rule).
        return when (torControlStartupKick(sock.inputStream, sock.outputStream, CMD_ENABLE_NETWORK)) {
            StartupKickResult.APPLIED -> {
                platformLog("TorManager", "startup kick: SETCONF DisableNetwork=0 -> 250 OK")
                true
            }
            StartupKickResult.REFUSED -> {
                platformLog("TorManager", "startup kick: SETCONF DisableNetwork=0 -> rejected")
                true
            }
            StartupKickResult.DROP -> {
                platformLogWarn("TorManager", "startup kick: no reply read — dropping the control socket; Tor's own 1 s timer stands")
                false
            }
        }
    }

    /** Sends `AUTHENTICATE <hex-cookie>` and returns whether Tor answered `250`. */
    private fun authenticateControl(sock: android.net.LocalSocket, cookie: ByteArray): Boolean {
        val hex = bytesToHex(cookie)
        sock.writeCommand("AUTHENTICATE $hex\r\n")
        return readControlReplyOk(sock)
    }

    /**
     * Reads one CRLF-terminated control reply line and returns whether it starts
     * with `250` (success). Bounded by [CONTROL_REPLY_MAX_BYTES]. AUTHENTICATE,
     * SIGNAL NEWNYM and SETCONF each reply with a single line, so the first line
     * is sufficient.
     */
    private fun readControlReplyOk(sock: android.net.LocalSocket): Boolean =
        readControlReplyCode(sock) == 250

    /** ONE reply line's 3-digit status (-1 if malformed / EOF). Same one-line
     *  read as always: async 650s never reach this socket (no SETEVENTS here).
     *  Throws on a read timeout and on an over-long line (TorControlWire.kt):
     *  both leave reply bytes in the stream, and every caller drops the socket
     *  on a throw. */
    private fun readControlReplyCode(sock: android.net.LocalSocket): Int =
        torControlReadCode(sock.inputStream)

    /** One whole control reply (`250-…` lines up to the final `250 …`), bounded.
     *  Async 650s never reach the command socket (no SETEVENTS on it). Throws
     *  like [readControlReplyCode], and on a reply with no final line within
     *  [CONTROL_REPLY_MAX_LINES] lines. */
    private fun readControlReplyLines(sock: android.net.LocalSocket): List<String> =
        torControlReadLines(sock.inputStream)

    /**
     * Writes one complete control [command] (already CRLF-terminated) and flushes
     * it — the single write path of the COMMAND socket. Throws like the stream
     * does; every caller owns its own drop-the-socket disposal.
     */
    private fun android.net.LocalSocket.writeCommand(command: String) {
        torControlWrite(outputStream, command)
    }

    // ---------------------------------------------------------------------
    // Bootstrap-stall rung — see the field block's header for the design.
    // ---------------------------------------------------------------------

    private fun resetBootStall() {
        synchronized(bootStallLock) {
            bootStallGen++
            bootStallJob?.cancel()
            bootStallJob = null
            bootPctHighest = 0
            bootPctChangedAtMs = SystemClock.elapsedRealtime()
            bootKicksFired = 0
            bootLastKickAtMs = 0L
            connectedPublished = false
            socksMovePending = false
            kickLogMark = Long.MAX_VALUE
        }
    }

    private fun disarmBootStall() {
        synchronized(bootStallLock) {
            bootStallGen++
            bootStallJob?.cancel()
            bootStallJob = null
        }
    }

    /**
     * The watcher asks before publishing Connected: may it, and if so it is
     * now CLAIMED (a kick evaluating after this refuses — the port is out).
     * False while a kick's listener move is unconfirmed.
     */
    private fun connectedMayPublish(): Boolean = synchronized(bootStallLock) {
        if (socksMovePending) return@synchronized false
        connectedPublished = true
        true
    }

    /**
     * A SOCKS listener line at [lineStart]: is it the NEW listener of a pending
     * kick (written at or past [kickLogMark])? If so the move is confirmed and
     * the caller adopts the port. Tor's original line (earlier offset) and any
     * line when no kick is pending are ignored — the detected port stands.
     */
    private fun adoptMovedSocksListener(lineStart: Long): Boolean = synchronized(bootStallLock) {
        if (!socksMovePending || lineStart < kickLogMark) return@synchronized false
        socksMovePending = false
        kickLogMark = Long.MAX_VALUE
        true
    }

    /**
     * Bootstrap progress from either source (log watcher / event socket).
     * Only an INCREASE of the highest percent is progress (Tor's own counter is
     * monotone; a WARN event re-reporting the current step is not). Re-arms the
     * stall timer on every increase and cancels it at 100 %.
     *
     * Runs on TWO threads: the notice-log watcher's IO coroutine and the event
     * reader's coroutine. Everything it touches is guarded by [bootStallLock].
     */
    internal fun noteBootstrapProgressForStall(percent: Int) {
        if (!bootstrapStallKick) return
        synchronized(bootStallLock) {
            if (stopped || percent <= bootPctHighest) return
            bootPctHighest = percent
            bootPctChangedAtMs = SystemClock.elapsedRealtime()
            armBootStallLocked()
        }
    }

    /** (Re)schedules the stall check from the shared predicate. Under [bootStallLock]. */
    private fun armBootStallLocked() {
        bootStallGen++
        bootStallJob?.cancel()
        bootStallJob = null
        val wait = bootStallWaitMsLocked()
        if (wait == TorBootstrapStall.NO_KICK) return
        val gen = bootStallGen
        bootStallJob = CoroutineScope(Dispatchers.IO).launch {
            delay(wait)
            val due = synchronized(bootStallLock) {
                if (gen != bootStallGen || stopped) return@launch
                bootStallJob = null
                val now = bootStallWaitMsLocked()
                when {
                    now == TorBootstrapStall.NO_KICK -> return@launch
                    now > 0L -> { armBootStallLocked(); return@launch }
                    else -> bootPctHighest
                }
            }
            kickStalledBootstrap(due)
        }
    }

    private fun bootStallWaitMsLocked(): Long {
        val now = SystemClock.elapsedRealtime()
        val newnymAt = lastNewnymAtMs
        return TorBootstrapStall.msUntilKick(
            percent = bootPctHighest,
            msSinceProgress = now - bootPctChangedAtMs,
            msSinceLastKick = if (bootLastKickAtMs == 0L) TorBootstrapStall.NEVER else now - bootLastKickAtMs,
            msSinceLastNewnym = if (newnymAt == 0L) TorBootstrapStall.NEVER else now - newnymAt,
            kicksFired = bootKicksFired,
        )
    }

    /**
     * The kick: `SETCONF DisableNetwork=1` and `SETCONF DisableNetwork=0` in ONE
     * write on the COMMAND socket (Tor runs both inside one read of the control
     * connection — the network is never left disabled across a main-loop turn,
     * and the second command cannot be lost alone). Then both one-line replies.
     * The result mapping is on [KickOutcome].
     */
    private suspend fun kickStalledBootstrap(percent: Int) {
        toggleNetworkWhileBootstrapping(percent, forNetworkRestore = false)
    }

    /**
     * The re-kick body. [forNetworkRestore] = [kickForNetworkRestore]'s call: the
     * same claim / write / listener-move handling, but it spends none of the
     * rung's budget ([bootKicksFired], [bootLastKickAtMs] — the rung's gates stay
     * exactly as they were) and writes the restore phrases instead of the rung's
     * coded lines. What it does reset is the progress clock: the percent stood
     * still because the network was gone, and a rung kick seconds after this one
     * would close the connections Tor just reopened.
     */
    private suspend fun toggleNetworkWhileBootstrapping(percent: Int, forNetworkRestore: Boolean): KickOutcome {
        if (stopped || midInternalRetry) return KickOutcome.NOT_SENT
        val label = if (forNetworkRestore) "network-restore kick" else "bootstrap re-kick"
        val logFile = File(dataDir, "tor.log")
        // Claim the listener move BEFORE anything reaches Tor, under the same lock
        // the watcher publishes Connected under: from here on Connected waits.
        // Also refused while an EARLIER kick's move is still unconfirmed: a second
        // move on top of it would make the earlier new-listener line, if it ever
        // arrived, look like this one's — and that port would already be closed.
        val claimed = synchronized(bootStallLock) {
            if (connectedPublished || stopped || socksMovePending) false
            else {
                socksMovePending = true
                kickLogMark = logFile.length()
                true
            }
        }
        if (!claimed) return KickOutcome.NOT_CLAIMED
        val outcome: KickOutcome = if (controlSocket == null) KickOutcome.NOT_SENT else controlMutex.withLock {
            val sock = controlSocket ?: return@withLock KickOutcome.NOT_SENT
            withContext(Dispatchers.IO) {
                try {
                    sock.writeCommand(CMD_TOGGLE_NETWORK)
                } catch (e: Exception) {
                    platformLogWarn("TorManager", "$label: write failed (${e.javaClass.simpleName}) — dropping the control socket")
                    try { sock.close() } catch (_: Exception) {}
                    controlSocket = null
                    return@withContext KickOutcome.NOT_SENT
                }
                try {
                    val disabledOk = readControlReplyOk(sock)
                    var enabledOk = readControlReplyOk(sock)
                    if (disabledOk && !enabledOk) {
                        platformLogWarn("TorManager", "$label: re-enable refused — retrying it once")
                        sock.writeCommand(CMD_ENABLE_NETWORK)
                        enabledOk = readControlReplyOk(sock)
                    }
                    platformLog("TorManager", "$label: DisableNetwork=1 -> ${if (disabledOk) "250 OK" else "rejected"}, =0 -> ${if (enabledOk) "250 OK" else "rejected"}")
                    if (disabledOk) KickOutcome.APPLIED else KickOutcome.REFUSED
                } catch (e: Exception) {
                    // Same disposal as requestNewCircuit/requestHsFetchForAddress:
                    // an unread reply must never be taken as a later command's 250.
                    platformLogWarn("TorManager", "$label: reply unreadable (${e.javaClass.simpleName}) — treating as applied, dropping the control socket")
                    try { sock.close() } catch (_: Exception) {}
                    controlSocket = null
                    KickOutcome.APPLIED
                }
            }
        }
        if (forNetworkRestore) {
            when (outcome) {
                KickOutcome.APPLIED -> {
                    synchronized(bootStallLock) {
                        bootPctChangedAtMs = SystemClock.elapsedRealtime()
                        if (!stopped) armBootStallLocked()
                    }
                    NetworkRestoreKick.logKickSent()
                }
                else -> synchronized(bootStallLock) {
                    socksMovePending = false
                    kickLogMark = Long.MAX_VALUE
                }
            }
            return outcome
        }
        when (outcome) {
            KickOutcome.APPLIED -> {
                val n = synchronized(bootStallLock) {
                    bootKicksFired++
                    bootLastKickAtMs = SystemClock.elapsedRealtime()
                    if (!stopped) armBootStallLocked()
                    bootKicksFired
                }
                ConnectionLog.append(ConnectionLog.Kind.STALL, TorBootstrapStall.kickLine(percent, n), ConnectionLog.Code.TOR_BOOT_KICK)
            }
            KickOutcome.NOT_SENT, KickOutcome.REFUSED -> {
                // Nothing reached Tor's listeners (or Tor refused the disable):
                // the detected port stands, so release a held Connected.
                synchronized(bootStallLock) {
                    socksMovePending = false
                    kickLogMark = Long.MAX_VALUE
                }
                ConnectionLog.append(ConnectionLog.Kind.STALL, TorBootstrapStall.skipLine(percent), ConnectionLog.Code.TOR_BOOT_KICK_SKIP)
            }
            KickOutcome.NOT_CLAIMED -> {}
        }
        return outcome
    }

    /**
     * The re-kick's result ([toggleNetworkWhileBootstrapping]); for the rung:
     *  - NOT_SENT (no socket, write threw) or REFUSED (the FIRST SETCONF refused)
     *    → NOT fired: no budget spent, one TOR_BOOT_KICK_SKIP line, no re-arm
     *    until the percent moves (no retry storm);
     *  - APPLIED (written and the first `250`, or written and the reply
     *    unreadable — Tor has the bytes and executes both) → FIRED: budget spent,
     *    TOR_BOOT_KICK line, the listener move stays pending until the watcher
     *    reads the new port, and the timer re-arms for the second (last) kick.
     *  - NOT_CLAIMED = refused before anything was written (Connected already
     *    out, or an earlier move still unconfirmed) — no line, nothing to release.
     * A refused SECOND SETCONF would leave the network disabled; it is retried
     * once on the spot, and otherwise the Android 100 s restart rung recovers.
     * Logs percent and counts only.
     */
    private enum class KickOutcome { APPLIED, NOT_SENT, REFUSED, NOT_CLAIMED }

    /**
     * Asks Tor for FRESH circuits (`SIGNAL NEWNYM`) over the authenticated
     * control channel — a cheap, in-process circuit-recovery lever that does NOT
     * tear down or re-bootstrap the daemon. Returns `true` only on a `250` reply.
     *
     * The escalation rung BEFORE [RunViewModel]'s full [restartTor]: each new
     * OkHttp/onion stream rides a new circuit, so a NEWNYM can clear a wedged
     * `.onion` rendezvous (relay up, our circuit dead/dirty — e.g. multi-device
     * Tor contention) without paying the ~90 s cold re-bootstrap.
     *
     * Returns `false` (never throws) when the control channel is not up — the
     * common degraded case (connect/auth failed, or the daemon died) — so the
     * caller escalates to the full restart. Thread-safe: the whole write+read is
     * serialised under [controlMutex] on [Dispatchers.IO].
     *
     * CAVEAT (UNVALIDATED on-device): NEWNYM's benefit for the *reachability-flake*
     * class is unproven — the iOS NEWNYM tried 2026-07-06 did NOT fix the
     * cross-multi3 load flake. It IS a legitimate self-heal for a genuinely
     * dead/dirty circuit. This is a cheap rung that can't hurt (the full restart
     * still follows if it doesn't help); effectiveness pending device validation.
     * Do not oversell it.
     */
    suspend fun requestNewCircuit(): Boolean {
        // Cheap pre-check off the lock: a null socket means "no NEWNYM available".
        if (controlSocket == null) {
            platformLogWarn("TorManager", "requestNewCircuit: control channel down — NEWNYM unavailable, restart-only self-heal")
            return false
        }
        val accepted = controlMutex.withLock {
            val sock = controlSocket ?: return@withLock false
            try {
                withContext(Dispatchers.IO) {
                    sock.writeCommand(CMD_NEWNYM)
                    // Bootstrap-stall rung spacing: stamped once the NEWNYM
                    // has reached Tor, whatever its reply.
                    lastNewnymAtMs = SystemClock.elapsedRealtime()
                    val ok = readControlReplyOk(sock)
                    platformLog("TorManager", "requestNewCircuit: SIGNAL NEWNYM -> ${if (ok) "250 OK" else "rejected"}")
                    ok
                }
            } catch (e: Exception) {
                platformLogWarn("TorManager", "requestNewCircuit: NEWNYM failed (${e.javaClass.simpleName}) — dropping the control socket so the caller escalates to restart")
                // The socket is almost certainly dead (daemon gone). Drop it so
                // future calls short-circuit to false and the stall watch restarts.
                try { sock.close() } catch (_: Exception) {}
                controlSocket = null
                false
            }
        }
        // Outside controlMutex: the follow-ups may send nothing on this socket,
        // but they must never extend the command lock either.
        if (accepted) onNewnymAccepted()
        return accepted
    }

    /**
     * A `SIGNAL NEWNYM` this app sent was accepted (`250`). Tor has purged the
     * client's HS state: the pending descriptor fetches are cancelled and the
     * descriptor cache is gone, so the hedge's in-flight count and episode start
     * over ([DescriptorHedge.noteNewnym]) — its session BUDGET does not (a
     * renewable bound is not a bound). Then the session owner aborts the
     * transport's in-flight probe/peek. iOS sibling: `TorManager.onNewnymAccepted`.
     */
    private fun onNewnymAccepted() {
        disarmDescriptorHedge()
        descriptorHedge?.invoke()?.noteNewnym()
        // Pending fetches were cancelled by Tor; good/bad HSDirs are KEPT — NEWNYM
        // purges Tor's HSDir memory, not ours (that is what the pin is for).
        hsDirLedger.noteNewnym()
        // NEWNYM killed every circuit: drop circuit tracking, guard 2 s.
        hsCircuitWatchdog.noteNewnym()
        // NEWNYM purged the descriptor cache: re-race the relay's addresses (the
        // current winner stays the base URL until the new race decides). No-op
        // for a single address.
        relayRace.noteTorHsStateReset()
        launchRelayAddressRace()
        notifyNewCircuits()
    }

    /**
     * Asks Tor to FETCH the relay's hidden-service descriptor now (`HSFETCH`),
     * over the same authenticated control channel [requestNewCircuit] uses.
     * Returns `true` only on a `250` reply.
     *
     * The pre-unlock rendezvous warm-up's first step (lever 1, [RelayWarmup]): a
     * v3 descriptor is never cached on disk by Tor, so every process pays one
     * HSDir fetch before it can even begin a rendezvous. `HSFETCH` starts that
     * fetch WITHOUT needing a stream — i.e. before the warm-up's `GET /` — and
     * needs nothing but the onion address the app already compiles in. Purely an
     * optimisation: the GET triggers the same fetch on its own, so every failure
     * path here is a silent no-op.
     *
     * [relayUrl] is a URL, not an address, and the extraction is deliberately
     * strict ([RelayWarmup.v3OnionAddress]): the string is written into a command
     * on an AUTHENTICATED control socket, where CR/LF would be command injection.
     * A non-onion / malformed / v2 URL simply yields `false`.
     *
     * NEVER logs the address (nor does it appear in any ConnectionLog line) —
     * the relay's onion is deliberately kept out of git, the logs and the bug
     * report.
     */
    suspend fun requestHsDescriptorFetch(relayUrl: String): Boolean =
        requestHsDescriptorFetchCode(relayUrl, serverArgument = null) == 250

    /**
     * The pre-unlock warm-up's descriptor step. ONE address: exactly the old
     * single `HSFETCH` of [RelayConfig.BASE_URL]. SEVERAL (2026-10-23): the
     * descriptor race ([startRelayAddressRace]) — a no-op when this Tor state was
     * already raced (normally at Connected).
     */
    suspend fun requestRelayDescriptorFetch(): Boolean =
        if (relayRace.isRacing) startRelayAddressRace() else requestHsDescriptorFetch(RelayConfig.BASE_URL)

    /**
     * SEVERAL ONION ADDRESSES (2026-10-23, [RelayAddressRace]): one bare
     * `HSFETCH <addr>` per configured address, all at once, on the COMMAND
     * socket. The first `HS_DESC RECEIVED` decides the session's base URL
     * ([onRelayDescriptorEvent]). Once per Tor HS state (process start / accepted
     * NEWNYM); returns whether any fetch was accepted. Needs the control channel:
     * without it nothing is begun, so a later trigger can still race. Never logs
     * an address — the race logs its own fixed phrases.
     */
    internal suspend fun startRelayAddressRace(): Boolean {
        if (!relayRace.isRacing || stopped || controlSocket == null) return false
        var accepted = 0
        for (address in relayRace.beginRace()) {
            if (requestHsFetchForAddress(address, serverArgument = null) == 250) accepted++
        }
        return accepted > 0
    }

    private fun launchRelayAddressRace() {
        if (!relayRace.isRacing) return
        CoroutineScope(Dispatchers.IO).launch { startRelayAddressRace() }
    }

    /**
     * [requestHsDescriptorFetch] returning Tor's reply CODE (-1 = not sent / no
     * reply), optionally pinned to one HSDir: [serverArgument] is
     * [HsDirLedger.pinnedServerArgument]'s `SERVER=$<40 hex>` (strictly validated
     * there and re-checked here — it goes onto an AUTHENTICATED socket). The
     * argument is SENSITIVE: never logged, only written into the command.
     */
    internal suspend fun requestHsDescriptorFetchCode(relayUrl: String, serverArgument: String?): Int {
        // Cheap pre-checks off the lock: no control channel (the connect
        // coroutine may still be retrying, or it failed) and no usable address
        // both mean "skip", exactly like a NEWNYM with no socket.
        if (controlSocket == null) return -1
        val address = RelayWarmup.v3OnionAddress(relayUrl) ?: return -1
        return requestHsFetchForAddress(address, serverArgument)
    }

    /** [requestHsDescriptorFetchCode] for an address already in `HSFETCH` form
     *  ([RelayAddressRace.beginRace]). Re-validated: strict 56-char base32, the
     *  value goes onto an AUTHENTICATED socket. Never logged. */
    private suspend fun requestHsFetchForAddress(address: String, serverArgument: String?): Int {
        if (controlSocket == null) return -1
        if (!V3_ADDRESS.matches(address)) return -1
        if (serverArgument != null && !SERVER_ARGUMENT.matches(serverArgument)) return -1
        val command = if (serverArgument == null) "HSFETCH $address" else "HSFETCH $address $serverArgument"
        return controlMutex.withLock {
            val sock = controlSocket ?: return@withLock -1
            try {
                withContext(Dispatchers.IO) {
                    sock.writeCommand("$command\r\n")
                    val code = readControlReplyCode(sock)
                    platformLog("TorManager", "requestHsDescriptorFetch: HSFETCH -> ${if (code == 250) "250 OK" else "rejected ($code)"}")
                    code
                }
            } catch (e: Exception) {
                platformLogWarn("TorManager", "requestHsDescriptorFetch: HSFETCH failed (${e.javaClass.simpleName}) — dropping the control socket")
                // Same disposal as [requestNewCircuit], and for a stronger
                // reason: a throw here is most likely a read timeout, which
                // leaves an unread reply that a LATER NEWNYM would consume as
                // its own "250" — a false success on the self-heal path. The
                // stream's state is unknown, so it must not be reused; the
                // degraded mode (restart-only self-heal) is already documented.
                try { sock.close() } catch (_: Exception) {}
                controlSocket = null
                -1
            }
        }
    }

    /**
     * Descriptor-hedge input, called on the event reader's coroutine for every
     * `HS_DESC` REQUESTED / RECEIVED / FAILED of the relay's onion (parsed by the
     * shared [RelayDescriptorWatchdog.parseEvent]). Never blocks: it feeds the
     * [HsDirLedger] and the [DescriptorHedge] and re-arms the one timer.
     */
    internal fun onRelayDescriptorEvent(event: RelayDescriptorEvent) {
        hsDirLedger.observe(event)
        // The race first: it decides the winner (and may switch the session's
        // base URL) and whether the event is the hedge's business at all — a
        // loser's REQUESTED after the race was decided is not a descriptor miss.
        val observation = relayRace.observe(event)
        if (!observation.feedHedge) return
        val hedge = descriptorHedge?.invoke() ?: return
        hedge.observe(event.action, DescriptorHedge.nowMs())
        armDescriptorHedge(hedge)
    }

    /** (Re-)arms the single check from [DescriptorHedge.msUntilNextCheck]; null
     *  there = nothing to wait for until the next event. */
    private fun armDescriptorHedge(hedge: DescriptorHedge) {
        synchronized(descriptorHedgeLock) {
            val gen = ++descriptorHedgeGen
            descriptorHedgeJob?.cancel()
            descriptorHedgeJob = null
            if (stopped) return
            val delayMs = hedge.msUntilNextCheck(DescriptorHedge.nowMs()) ?: return
            descriptorHedgeJob = CoroutineScope(Dispatchers.IO).launch {
                delay(delayMs)
                synchronized(descriptorHedgeLock) {
                    if (gen != descriptorHedgeGen) return@launch
                    descriptorHedgeJob = null
                }
                // A kept Tor re-bound to a new session between arm and fire:
                // never spend the previous session's hedge.
                if (descriptorHedge?.invoke() !== hedge) return@launch
                checkDescriptorHedge(hedge)
            }
        }
    }

    private fun disarmDescriptorHedge() {
        synchronized(descriptorHedgeLock) {
            descriptorHedgeGen++
            descriptorHedgeJob?.cancel()
            descriptorHedgeJob = null
        }
    }

    /**
     * A check is due: ask the shared [DescriptorHedge.due] (which charges the
     * session budget for whatever it hands out), send that `HSFETCH` on the
     * COMMAND socket (never the event socket), re-arm. FIRST = bare (Tor keeps
     * its HSDir selection and its recently-asked filter); SECOND = the old
     * watchdog's pinned sequence (stall booked -> pin -> 551/552 -> plain, the
     * plain retry charged too). Fixed phrases only — never the address or a pin.
     */
    private suspend fun checkDescriptorHedge(hedge: DescriptorHedge) {
        if (stopped || midInternalRetry) return
        val answered = descriptorHedgeAnswered ?: return
        val d = hedge.due(DescriptorHedge.nowMs(), answered(), DescriptorHedge.isHedgeEnabled())
        DescriptorHedge.logDecision(d)
        if (d.stageStalled) {
            try {
                onDescriptorStageStalled?.invoke()
            } catch (e: Exception) {
                platformLogWarn("TorManager", "descriptor-stage hook threw: ${e::class.simpleName}")
            }
        }
        when (d.stage) {
            null -> {}
            DescriptorHedge.Stage.FIRST -> {
                // Several addresses: the next unresolved one while the race is
                // open, else the winner (one address: slot 1, as before).
                val target = relayRace.urlAt(relayRace.hedgeTargetSlot())
                val code = requestHsDescriptorFetchCode(target, serverArgument = null)
                DescriptorHedge.logSent(DescriptorHedge.Stage.FIRST, d.spent)
                if (code != 250) platformLogWarn("TorManager", "descriptor hedge — HSFETCH unavailable (control channel down or refused)")
            }
            DescriptorHedge.Stage.SECOND -> {
                // The stalled HSDir(s) become "bad" BEFORE the pin is chosen, so a
                // pinned directory that itself stalled is never chosen again.
                hsDirLedger.noteStallFired()
                val slot = relayRace.hedgeTargetSlot()
                val target = relayRace.urlAt(slot)
                val ledger = hsDirLedger.forSlot(slot)
                val server = ledger.pinnedServerArgument()
                var code = requestHsDescriptorFetchCode(target, server)
                var spent = d.spent
                if (server != null && RelayDescriptorWatchdog.isPinRejectedReply(code)) {
                    // 551/552: that HSDir left the consensus / is no longer an
                    // HSDir. Forget it; the plain retry is one more charged HSFETCH.
                    ledger.dropPin()
                    HsDirLedger.logPinDropped()
                    if (hedge.tryChargeRetry()) {
                        spent++
                        code = requestHsDescriptorFetchCode(target, serverArgument = null)
                    }
                } else if (server != null && code == 250) {
                    HsDirLedger.logPinned()
                }
                DescriptorHedge.logSent(DescriptorHedge.Stage.SECOND, spent)
                if (code != 250) platformLogWarn("TorManager", "descriptor hedge — HSFETCH unavailable (control channel down or refused)")
            }
        }
        armDescriptorHedge(hedge)
    }

    // ---------------------------------------------------------------------
    // Hung onion-circuit rung (2026-10-08; iOS sibling TorManager.swift
    // scheduleHsCircuitCheck / checkHsCircuits). Decision: the shared
    // [HsCircuitWatchdog]; here only the timer and the CLOSECIRCUIT on the
    // COMMAND socket (never the event socket).
    // ---------------------------------------------------------------------

    /** Event-reader hook: feed the watchdog, schedule a check if it armed one.
     *  Runs on the event reader's coroutine (IO), once per raw event line. */
    internal fun onHsCircuitEvent(raw: String) {
        if (stopped) return
        val delayMs = hsCircuitWatchdog.observe(raw, relayHsAddresses) ?: return
        scheduleHsCircuitCheck(delayMs)
    }

    private fun scheduleHsCircuitCheck(delayMs: Long) {
        CoroutineScope(Dispatchers.IO).launch {
            delay(delayMs)
            checkHsCircuits()
        }
    }

    /** A deadline passed: ask the shared decision, send the closes it hands out,
     *  re-schedule for whatever is still armed. Fixed phrases only. */
    private suspend fun checkHsCircuits() {
        if (stopped || midInternalRetry) return
        val answered = hsCircuitAnswered ?: return
        val decision = hsCircuitWatchdog.due(answered())
        var streamClosed = false
        for (closure in decision.closures) {
            HsCircuitWatchdog.logClosing(closure.kind)
            val code = closeCircuit(closure.commandArgument())
            // 552 = "Unknown circuit": already gone. Never retried either way.
            if (code != 250) platformLog("TorManager", "circuit close not applied (${if (code == 552) "already gone" else "refused"})")
            if (closure.kind == HsCircuitWatchdog.Closure.Kind.STREAM) streamClosed = true
        }
        if (decision.budgetSpentNow) HsCircuitWatchdog.logBudgetSpent()
        if (decision.channelKick) kickGuardChannels()
        // STREAM rule: the closed circuit carried the probe's (or the peek's)
        // stream, which now fails FAST. Book it like a NEWNYM abort — re-probe at
        // once, no timeout/fast-failure bookkeeping — instead of letting a
        // watchdog close break the cold rung's evidence run. Same hook the
        // NEWNYM path uses; the NEWNYM ledgers are NOT touched (no NEWNYM ran).
        if (streamClosed) notifyNewCircuits()
        hsCircuitWatchdog.msUntilNextDeadline()?.let { scheduleHsCircuitCheck(it) }
    }

    /** `CLOSECIRCUIT <id>` on the COMMAND socket; Tor's reply code, -1 if not
     *  sent. The id is re-validated (digits only — it goes onto an AUTHENTICATED
     *  socket) and never logged. Same disposal on a throw as [requestNewCircuit]. */
    private suspend fun closeCircuit(circuitId: String): Int {
        if (controlSocket == null || !HsCircuitWatchdog.isValidCircuitId(circuitId)) return -1
        return controlMutex.withLock {
            val sock = controlSocket ?: return@withLock -1
            try {
                withContext(Dispatchers.IO) {
                    sock.writeCommand("CLOSECIRCUIT $circuitId\r\n")
                    readControlReplyCode(sock)
                }
            } catch (e: Exception) {
                platformLogWarn("TorManager", "CLOSECIRCUIT failed (${e.javaClass.simpleName}) — dropping the control socket")
                try { sock.close() } catch (_: Exception) {}
                controlSocket = null
                -1
            }
        }
    }

    // ---------------------------------------------------------------------
    // Guard-channel kick (C4, 2026-10-09; iOS sibling TorManager.swift
    // kickGuardChannels). Decision: the shared [HsCircuitWatchdog] (two closes on
    // one first hop, or the close budget spent with another stall; 1 per Tor
    // process; >= 10 s after a NEWNYM; before the first relay answer). Here:
    // `SETCONF DisableNetwork=1` + `=0` on the COMMAND socket — every OR
    // connection (the wedged guard channel included) is closed and re-opened to
    // the SAME guards; guards, consensus, descriptors and identity are kept —
    // then `GETINFO net/listeners/socks`, because the re-enable re-binds
    // `SocksPort auto` on a NEW port. Every Tor client follows the move through
    // [SocksPortRedirect] (no transport is rebuilt). Fixed phrases only; this
    // path logs neither port (the file-header port-logging policy would allow the
    // embedded loopback port — the kick simply has no need to).
    // ---------------------------------------------------------------------

    private suspend fun kickGuardChannels() {
        toggleNetworkWhileConnected(forNetworkRestore = false)
    }

    /**
     * The guard-channel kick body. [forNetworkRestore] = the network-restore
     * caller ([kickForNetworkRestore]): it logs its own phrases and reports a
     * skip by returning false instead of writing the watchdog's skip line. The
     * watchdog's gates (before the first answer, one per Tor process) live in
     * [HsCircuitWatchdog.due] and are untouched by this path: it never consumes
     * the watchdog's kick, it only renews the close budget like any kick.
     */
    private suspend fun toggleNetworkWhileConnected(forNetworkRestore: Boolean): Boolean {
        if (stopped || midInternalRetry) return false
        val oldPort = (_state.value as? ConnectionState.Connected)?.socksPort
        if (oldPort == null || controlSocket == null) {
            if (!forNetworkRestore) HsCircuitWatchdog.logKick(HsCircuitWatchdog.CHANNEL_KICK_SKIP_PHRASE)
            return false
        }
        // The network-restore phrase is logged AFTER the control exchange below, once the
        // toggle really reached Tor — a half-dead control socket must not read as "kick
        // sent". The watchdog's own phrase keeps its place.
        if (!forNetworkRestore) HsCircuitWatchdog.logKick(HsCircuitWatchdog.CHANNEL_KICK_PHRASE)
        // Streams in flight die with their channels: abort them now (booked like a
        // NEWNYM abort, never as fast failures), and block the old port so nothing
        // connects to it while it is closed.
        notifyNewCircuits()
        SocksPortRedirect.beginMove(oldPort)
        val newPort: Int? = controlMutex.withLock {
            val sock = controlSocket ?: return@withLock null
            withContext(Dispatchers.IO) {
                try {
                    sock.writeCommand(CMD_TOGGLE_NETWORK)
                    val disabledOk = readControlReplyOk(sock)
                    var enabledOk = readControlReplyOk(sock)
                    if (!enabledOk) {
                        // A refused re-enable would leave the network off for this
                        // process: retry it once (a no-op if it is already on).
                        sock.writeCommand(CMD_ENABLE_NETWORK)
                        enabledOk = readControlReplyOk(sock)
                    }
                    platformLog("TorManager", "${if (forNetworkRestore) "network-restore kick" else "guard-channel kick"}: DisableNetwork=1 -> ${if (disabledOk) "250 OK" else "rejected"}, =0 -> ${if (enabledOk) "250 OK" else "rejected"}")
                    if (!enabledOk) return@withContext null
                    // Refused =1: nothing was closed, the listener never moved.
                    if (!disabledOk) return@withContext oldPort
                    sock.writeCommand(CMD_GETINFO_SOCKS_LISTENERS)
                    SocksPortRedirect.parseGetinfoSocksPort(readControlReplyLines(sock))
                } catch (e: Exception) {
                    // Same disposal as every command here: an unread reply must
                    // never be taken as a later command's.
                    platformLogWarn("TorManager", "${if (forNetworkRestore) "network-restore kick" else "guard-channel kick"} failed (${e.javaClass.simpleName}) — dropping the control socket")
                    try { sock.close() } catch (_: Exception) {}
                    controlSocket = null
                    null
                }
            }
        }
        if (newPort != null && SocksPortRedirect.completeMove(oldPort, newPort)) {
            if (newPort != oldPort) HsCircuitWatchdog.logKick(HsCircuitWatchdog.SOCKS_MOVED_PHRASE)
        } else {
            // Fail CLOSED: the old port stays blocked (requests fail fast, never
            // reach a squatter); the 100 s Tor-restart rung recovers.
            HsCircuitWatchdog.logKick(HsCircuitWatchdog.SOCKS_LOST_PHRASE)
        }
        // New channel epoch: the close budget is renewed (bounded — one kick per
        // Tor process). iOS sibling: TorManager.swift, same line.
        if (hsCircuitWatchdog.noteChannelKick()) HsCircuitWatchdog.logBudgetRenewed()
        // A request that slipped into the gap is abandoned too, then re-probed on
        // the moved port.
        notifyNewCircuits()
        // null = the control write threw or DisableNetwork=0 was refused: nothing reached
        // Tor and the SOCKS port is blocked fail-closed. The caller maps false to CONTROL_DOWN.
        val sent = newPort != null
        if (forNetworkRestore && sent) NetworkRestoreKick.logKickSent()
        return sent
    }

    /**
     * NETWORK-RESTORE KICK (2026-10-25, [NetworkRestoreKick]; iOS sibling
     * TorManager.swift `kickForNetworkRestore`): the session owner saw the phone's
     * default network come back. One `SETCONF DisableNetwork=1` / `=0` toggle so
     * Tor reopens its OR connections NOW instead of waiting out its own guard
     * retry schedule (chain:push Case A: GUARD_UP ~10 min after the restore).
     *
     * Through the two existing toggle paths, chosen by state, so the SOCKS
     * listener move is handled exactly as they handle it:
     *  - Connected → the guard-channel kick body (in-flight streams aborted via
     *    the new-circuit hook, the port move followed through
     *    [SocksPortRedirect]);
     *  - Bootstrapping → the bootstrap re-kick body (Connected held until the
     *    re-bound listener line is read).
     * Neither path's own budget or gate is spent or consulted: no
     * [HsCircuitWatchdog] kick, no [TorBootstrapStall] kick count. Returns null
     * when the toggle reached Tor, else why not (the caller logs it).
     *
     * Suspends on the caller's coroutine (RunViewModel's network-restore check);
     * the socket I/O itself runs on [Dispatchers.IO] under [controlMutex].
     */
    suspend fun kickForNetworkRestore(): NetworkRestoreKick.SkipReason? {
        if (stopped) return NetworkRestoreKick.SkipReason.TOR_NOT_RUNNING
        if (midInternalRetry) return NetworkRestoreKick.SkipReason.TOR_RETRYING
        if (controlSocket == null) return NetworkRestoreKick.SkipReason.CONTROL_DOWN
        return when (_state.value) {
            is ConnectionState.Connected ->
                if (toggleNetworkWhileConnected(forNetworkRestore = true)) null
                else NetworkRestoreKick.SkipReason.CONTROL_DOWN
            is ConnectionState.Bootstrapping -> {
                val percent = synchronized(bootStallLock) { bootPctHighest }
                when (toggleNetworkWhileBootstrapping(percent, forNetworkRestore = true)) {
                    KickOutcome.APPLIED -> null
                    KickOutcome.REFUSED -> NetworkRestoreKick.SkipReason.REFUSED
                    KickOutcome.NOT_SENT -> NetworkRestoreKick.SkipReason.CONTROL_DOWN
                    KickOutcome.NOT_CLAIMED -> NetworkRestoreKick.SkipReason.PORT_HANDOUT
                }
            }
            else -> NetworkRestoreKick.SkipReason.TOR_NOT_RUNNING
        }
    }

    /** The session owner's NEWNYM-abort hook (aborts in-flight probe/peek, new
     *  epoch) WITHOUT touching the NEWNYM ledgers — no NEWNYM ran. */
    private fun notifyNewCircuits() {
        try {
            onNewCircuitAccepted?.invoke()
        } catch (e: Exception) {
            platformLogWarn("TorManager", "new-circuit hook threw: ${e::class.simpleName}")
        }
    }

    /**
     * ORDINARY teardown: kills the Tor child and PRESERVES its working dirs (see
     * [dataDir] for the decision and its forensic cost). Wipe paths must
     * call [stopAndDiscardState] instead — this one deliberately deletes nothing.
     *
     * Mostly called on the MAIN thread (RunViewModel's session teardown) and
     * BLOCKS its caller for up to ~3 s (`waitFor` 2 s, then 1 s after
     * `destroyForcibly`).
     */
    fun stop() {
        platformLog("TorManager", "stop() called — destroying Tor process (working dirs preserved)")
        ConnectionLog.append(ConnectionLog.Kind.SYSTEM, "Tor stopping", ConnectionLog.Code.TOR_STOP)
        // Latch BEFORE anything else so a start() racing us in its spawn
        // window observes the stop and cleans up its own child.
        stopped = true
        // Cancel the watcher BEFORE destroy() — while the process is still
        // alive it is parked in `delay()` (a cancellation point), so it can never
        // reach the post-death Failed() write and clobber the Idle we set below.
        watcherJob?.cancel()
        watcherJob = null
        // Tear down the control channel too: cancel the connect coroutine
        // and close the socket. close() is safe from any thread and unblocks
        // a read parked in any command; the `@Volatile` null makes
        // future NEWNYM calls short-circuit to false so the caller escalates
        // to a full restart. The socket lives inside the working dir that a
        // wipe deletes, so nothing durable is left behind.
        controlJob?.cancel()
        controlJob = null
        try { controlSocket?.close() } catch (_: Exception) {}
        controlSocket = null
        // Same teardown for the event reader's own socket + coroutine. Closed
        // BEFORE the child is signalled so the reader sees a deliberate close
        // (it gives up silently) rather than a drop it would try to reconnect.
        try { eventReader?.close() } catch (_: Exception) {}
        eventReader = null
        disarmDescriptorHedge()
        disarmBootStall()
        val p = torProcess
        var childGone = false
        try {
            // SIGTERM, then SIGKILL; never throws (see terminateTorChild).
            childGone = terminateTorChild(p)
        } finally {
            // Always, whatever the termination did: a stale torProcess or a
            // missing Idle would leave the session owner seeing a live Tor.
            torProcess = null
            // The notice log was deleted only from
            // inside the watcher — which this method cancels first — so every session
            // that ended before "Bootstrapped 100%" (backgrounding mid-bootstrap is
            // ordinary, and speculative Tor starts BEFORE unlock) left a timestamped
            // launch record in CE storage until the next start. Purge the session
            // ephemera here too, strictly AFTER the child is confirmed dead so a
            // dying daemon cannot re-create the file; otherwise the next start()'s
            // purge removes it. Idempotent, best-effort.
            if (childGone) purgeSessionEphemera(dataDir)
            _state.value = ConnectionState.Idle
            platformLog("TorManager", "Tor stopped, state=Idle")
        }
    }

    /**
     * WIPE-PATH teardown: [stop] the daemon and then DESTROY the preserved
     * working dirs. The ordinary [stop] deliberately keeps them (see [dataDir]);
     * this is the variant every wipe must use.
     *
     * Deleting AFTER stop() — not before — is what makes it stick: stop() waits
     * for the child to actually exit (SIGTERM, then SIGKILL), so nothing is left
     * alive to recreate a file behind the delete. `WipeRoutine.wipePersistentState`
     * already deleted the same two trees earlier on the wipe path, while Tor was
     * still running; this is the second, confirmed pass.
     */
    fun stopAndDiscardState() {
        stop()
        wipeWorkingDirs()
    }

    /**
     * Deletes BOTH Tor working-dir trees outright. Called only by
     * [stopAndDiscardState]: every wipe path, and [start]'s one-shot corrupt-dir
     * fallback. Never on an ordinary stop.
     */
    private fun wipeWorkingDirs() {
        try {
            File(application.filesDir, TOR_ROOT_DIR_NAME).deleteRecursively()
            File(application.cacheDir, TOR_ROOT_DIR_NAME).deleteRecursively()
        } catch (e: Exception) {
            platformLogWarn("TorManager", "Tor working-dir discard failed: ${e.javaClass.simpleName}")
        }
    }

    /**
     * Deletes every `tor_direct` child that is not one of the two RETAINED
     * working dirs: the legacy per-session dirs (`s1`, `s2`, …) minted by builds
     * that wiped on every start, plus anything a crashed launch stranded. The
     * retained dirs are preserved on purpose — see [dataDir].
     */
    private fun purgeStaleTorDirs() {
        val bases = listOf(
            File(application.filesDir, TOR_ROOT_DIR_NAME) to TOR_DATA_DIR_NAME,
            File(application.cacheDir, TOR_ROOT_DIR_NAME) to TOR_CACHE_DIR_NAME,
        )
        for ((base, keep) in bases) {
            try {
                val names = base.listFiles()?.map { it.name } ?: continue
                for (name in staleTorDirsToPurge(names, keep)) {
                    File(base, name).deleteRecursively()
                }
            } catch (e: Exception) {
                platformLogWarn("TorManager", "stale Tor dir purge failed: ${e.javaClass.simpleName}")
            }
        }
    }

    // NOTE (2026-07-31): the warm-Tor-cache snapshot/load pair that used to live
    // here is DELETED. It persisted Tor's guard + consensus state across wakes
    // under a deliberately weak-gated Keystore key so an FCM-woken poll could
    // skip a cold bootstrap; that poll runner went with the poll-manifest
    // removal, leaving the only weak-gated key surface in the app with no caller.
    // [LegacyTorWarmCache] destroys the artifacts on installs that still carry
    // them. Tor state IS persisted between sessions again since 2026-08-01 — but
    // as PLAIN files in credential-encrypted app storage that every wipe path
    // deletes (see [dataDir]), NOT re-sealed under a key usable while the phone is
    // locked. Do NOT reintroduce such a cache here without re-deriving its key
    // class from scratch.
}

/**
 * Tor's `AUTHENTICATION_COOKIE_LEN` (control_auth.c): the control auth cookie is
 * exactly 32 bytes. Any other length is a partial read of a file Tor is still
 * writing and must NEVER be authenticated (mirror of iOS P4a).
 */
internal const val TOR_CONTROL_COOKIE_LEN = 32

/**
 * Reads the control auth cookie, returning it ONLY if it is exactly
 * [TOR_CONTROL_COOKIE_LEN] bytes. Any other length is a partial write of a
 * file Tor is still creating — return null so the caller retries and NEVER
 * authenticates with a short read (mirror of iOS P4a). Shared by both control
 * sockets: [TorManager.connectControlChannel] (commands) and
 * [TorControlEventReader] (events).
 */
internal fun readTorControlCookie(cookieFile: File): ByteArray? =
    try {
        if (!cookieFile.exists()) null
        else cookieFile.readBytes().takeIf { it.size == TOR_CONTROL_COOKIE_LEN }
    } catch (_: Exception) {
        null
    }
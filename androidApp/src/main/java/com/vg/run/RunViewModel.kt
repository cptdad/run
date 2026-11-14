package com.vg.run

import android.app.Application
import android.os.SystemClock
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.conflate
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull

/**
 * NEW-phone import state, owned by [RunViewModel] rather than the composition so
 * the run survives a rotation (docs/device-move.md: process death is a rescan,
 * a rotation is not).
 */
sealed class MoveImportUiState {
    data object Idle : MoveImportUiState()
    data class Running(val step: MoveImportStep) : MoveImportUiState()
    data class Done(val contacts: Int, val groups: Int) : MoveImportUiState()
    data class Failed(val error: MoveError) : MoveImportUiState()
}

/**
 * Why a background-notification enable attempt failed, so the settings modal
 * can show copy the user can ACT on instead of one generic line. Only the
 * UnifiedPush path distinguishes causes today; FCM's failures are all
 * [RELAY]-shaped from the user's point of view.
 */
enum class PushEnableFailure {
    /** No UnifiedPush distributor app is installed. */
    NO_DISTRIBUTOR,

    /**
     * A distributor IS installed but selecting it failed — the connector's
     * `tryUseCurrentOrDefaultDistributor`/`tryPickDistributor` reported false
     * or threw. Distinct from [NO_DISTRIBUTOR] because the old copy ("install
     * ntfy from F-Droid") was actively misleading here: it sent the user off
     * to install an app they already have, for a failure that is ours. The
     * known concrete cause is the wedged connector DB handle a same-process
     * wipe used to leave behind (SQLITE_READONLY_DBMOVED — fixed at the
     * source by `UnifiedPushSupport.closeConnectorDbHandle`, but kept honest
     * here as the residual for any selection failure, since a restart always
     * clears that class).
     */
    DISTRIBUTOR_SELECTION,

    /**
     * The distributor's push server requires a VAPID-signed request, which the
     * relay does not mint in v1. Distinct because "check your connection" is
     * actively misleading here — the fix is a different distributor.
     */
    VAPID_UNSUPPORTED,

    /** The distributor refused or dropped the registration. */
    DISTRIBUTOR_REFUSED,

    /** The distributor never answered with a usable endpoint. */
    NO_ENDPOINT,

    /** An address was obtained, but the relay registration did not land. */
    RELAY,
    ;

    companion object {
        /**
         * The honest classification for a FAILED distributor selection:
         * [NO_DISTRIBUTOR] only when no distributor is actually installed,
         * [DISTRIBUTOR_SELECTION] when one is (so the copy must not tell the
         * user to install what they already have). Pure so the plain-JVM tier
         * can pin it ([UnifiedPushWipeWedgeSourceTest]); the caller supplies
         * `UnifiedPushSupport.isAvailable(...)` — a live re-probe, never a
         * cached answer, per that function's kdoc.
         */
        fun forFailedDistributorSelection(distributorInstalled: Boolean): PushEnableFailure =
            if (distributorInstalled) DISTRIBUTOR_SELECTION else NO_DISTRIBUTOR
    }
}

// ---------------------------------------------------------------------------
// RunViewModel — shared state holder for the current session.
//
// Transport selection: if RelayConfig.BASE_URL contains ".onion", Tor is
// started in-process and owned by this ViewModel. The app is foreground-only:
// MainActivity.onStop() finishes the Activity on background, which clears the
// ViewModel (onCleared → lockSession(stopTor = true)). That teardown either stops
// Tor or, when MainActivity.onStop armed the bounded keep-alive (tier below
// MAXIMUM, Tor Connected, no wipe), HANDS the live instance to
// TorKeepAliveHolder.parkOnTeardown for at most TorKeepAlive.KEEP_ALIVE_MS (~2
// min) under TorKeepAliveService, so a quick return can adopt it. Nothing else of
// the session outlives the ViewModel; past the keep-alive, Tor re-bootstraps on
// the next launch.
//
// Tor now starts SPECULATIVELY, from this ViewModel's init block, so the
// bootstrap overlaps credential entry instead of following it; the unlock
// ADOPTS that live instance rather than destroying it. See
// [startSpeculativeTor] and [connectViaTor]. Nothing vault-dependent exists
// before onVaultOpened — the pre-unlock window is a bare TorManager and
// nothing else.
// ---------------------------------------------------------------------------

class RunViewModel(application: Application) : AndroidViewModel(application) {

    /**
     * Every SESSION job below is a slot in this registry (`by sessionJobs.slot()`),
     * and both teardowns stop them all with one `sessionJobs.cancelAll()`. Declared
     * first, because a slot property's delegate is created when its declaration
     * initializes. See [SessionJobs].
     */
    private val sessionJobs = SessionJobs()

    companion object {
        // 3 consecutive missed health checks (~24-36s at the jittered 8-12s
        // cadence) before declaring the relay unreachable — rides out
        // concurrent-load onion-stream flaps; a genuine outage still surfaces
        // within ~half a minute. Parity with iOS AppState.
        private const val RELAY_UNREACHABLE_STREAK_LIMIT = 3

        /**
         * Backstop cadence of [consentTickJob] (the old screen poller's cadence).
         * The event-driven refreshes surface a parked invite within milliseconds;
         * this only bounds the cases none of them sees.
         */
        private const val CONSENT_TICK_MS = 4_000L

        /**
         * Mirrors `ReferralManager.MAX_PENDING_RELAY_EVENTS`
         * (a `private const val` in ReferralManager.kt — not visible from this
         * platform layer, hence the duplicated literal rather than an import).
         * [_referralRelayEvents] must stay bounded to the SAME cap commonMain's own
         * pre-hook buffer uses, or an unreachable second leg (dead peer inbox) can
         * grow this RAM list without limit: the dedupe that would otherwise collapse
         * re-delivered accepts only arms on a SUCCESSFUL relay, so every failed
         * redrive still fires [ReferralManager.onIntroRelayed] once per delivery
         * attempt. Keep this value in lockstep with the commonMain constant if it
         * ever changes.
         */
        private const val MAX_PENDING_REFERRAL_RELAY_EVENTS = 8

        /**
         * Minimum wall-time between two COUNTED reachability misses, at the health
         * loop's steady-state 8 s floor. Every steady-state cycle (8-12 s) still
         * counts one miss; a COLD cycle re-probing every 1-2 s
         * ([MessageManager.relayHealthDelayMs]) cannot add extra bumps inside the
         * window. That is what keeps "3 misses" meaning ~24 s of real time — and
         * every escalation built on it — exactly where it was before the cold
         * cadence was shortened. Parity with iOS AppState.minStreakBumpIntervalMs.
         */
        private const val MIN_STREAK_BUMP_INTERVAL_MS = 8_000L

        /**
         * How long a Tor bootstrap may run before the UI admits it is not going
         * well — see [torBootstrapStalled]. Mirrors
         * `TorManager.BOOTSTRAP_TIMEOUT_MS` (the budget Tor itself gets before
         * "No SOCKS port") and iOS `AppState.torBootstrapStallSec`, so all three
         * numbers move together.
         */
        const val TOR_BOOTSTRAP_STALL_MS = 90_000L

        /**
         * How long the relay may stay unreachable before the ONE automatic Tor
         * restart fires ([startRelayStallWatch]). Deliberately just PAST Tor's own
         * ~90 s bootstrap timeout, so an in-progress bootstrap is never
         * interrupted — only a stuck or failed one. Was an inline literal; named
         * because the re-anchoring below subtracts from it.
         */
        private const val RELAY_SELF_HEAL_RESTART_MS = 100_000L

        // BOOTSTRAP-STALL RUNG — the cheap rung UNDER the two
        // above, owned by TorManager itself (enabled by `bootstrapStallKick =
        // true` on every instance this ViewModel builds; iOS sibling
        // `TorManager.bootstrapStallKickEnabled`, set by AppState). When the
        // bootstrap percent stands still for `TorBootstrapStall.STALL_MS` (20 s)
        // inside the ladder (5 % ≤ p < 100 %), TorManager re-kicks the network
        // with ONE pipelined `SETCONF DisableNetwork=1` / `=0` on the command
        // control connection — every OR / directory connection is closed and the
        // stalled directory fetch is relaunched on a fresh one; guards, consensus
        // and state are kept, no process restart. At most
        // `TorBootstrapStall.MAX_KICKS` (2) per start attempt, never within
        // `TorBootstrapStall.NEWNYM_SPACING_MS` (10 s) of a NEWNYM. Evidence: a
        // Pixel sat ~100 s at 50–69 % loading_descriptors (fresh consensus, guard
        // up) until the restart below, which then bootstrapped in 5 s. These two
        // constants are UNCHANGED and remain the backstop. Connection-log codes
        // TOR_BOOT_KICK / TOR_BOOT_KICK_SKIP.

        /** How long the post-restart Tor session gets before the contact list
         *  escalates to [RelayConnectPhase.Stalled] and offers manual Reconnect. */
        private const val RELAY_SELF_HEAL_STALL_MS = 90_000L

        /**
         * CHEAP escalation rung before the expensive full Tor restart: after the
         * relay has been unreachable long enough, ask Tor for fresh circuits
         * (`SIGNAL NEWNYM`, in-process, no re-bootstrap) and probe for one
         * reachability cycle before falling through to [restartTor]. Bounded by
         * [RELAY_NEWNYM_MAX_TRIES] so it can never loop forever before escalating.
         *
         * [RELAY_NEWNYM_PROBE_MS] ≈ one reachability cycle (the check runs every
         * 8-12 s and recovers `isRelayReachable` on the FIRST success), so a
         * NEWNYM that helps flips reachable and `collectLatest` cancels the whole
         * escalation before [restartTor] is ever reached.
         *
         * CAVEAT (unvalidated on-device): NEWNYM's benefit for the
         * reachability-FLAKE class is UNPROVEN — the iOS NEWNYM tried 2026-07-06
         * did NOT fix the cross-multi3 load flake. It IS a legitimate self-heal
         * for a genuinely dead/dirty circuit. Framed as a cheap rung that can't
         * hurt (the full restart still follows); effectiveness pending device
         * validation. Total added time-to-restart is bounded at
         * MAX_TRIES × PROBE_MS (~24 s), and is ZERO when the control channel is
         * down (NEWNYM returns false immediately → straight to restart).
         */
        private const val RELAY_NEWNYM_MAX_TRIES = 2
        private const val RELAY_NEWNYM_PROBE_MS = 12_000L

        /**
         * Floor for a watchdog delay RE-ANCHORED onto an already-running Tor
         * bootstrap (see [reanchoredDelayMs]).
         *
         * Never zero. A Tor whose elapsed bootstrap already exceeds the full
         * window is by definition at or past `TorManager.BOOTSTRAP_TIMEOUT_MS`,
         * i.e. entering its own internal corrupt-state retry — which the self-heal
         * that consumes this number DEFERS to anyway — and firing at t+0 would
         * decide before the adoption's freshly attached monitor has even delivered
         * its first (replayed) state.
         */
        private const val MIN_REANCHORED_WATCHDOG_MS = 5_000L

        /** SharedPreferences file backing the plaintext [NotificationLevel]
         *  selector (vendor-push tier) — public so WipeRoutine can list it by
         *  name without constructing a KeyValueStore just to read one. */
        const val NOTIFICATION_LEVEL_PREFS_NAME = "notification_level_prefs"

        /** SharedPreferences file backing [DebugMode] (Settings → Debug mode)
         *  — its own file, not `vault_selector_prefs`, same reasoning as
         *  [NOTIFICATION_LEVEL_PREFS_NAME]: non-secret, and must be readable
         *  pre-unlock ([RunApplication.onCreate]'s [DebugMode.applyAtStartup]
         *  call runs before any vault exists). Public so WipeRoutine can list
         *  it by name. */
        const val DEBUG_MODE_PREFS_NAME = "debug_mode_prefs"

        /** SharedPreferences file backing the EXTERNAL SOCKS PROXY setting
         *  ([ExternalTorProxy.PREF_KEY], ExternalTorProxy.kt commonMain). Its own
         *  file, same reasoning as [DEBUG_MODE_PREFS_NAME]: it must be readable
         *  PRE-UNLOCK — the ViewModel's construction decides from it whether the
         *  speculative embedded-Tor start may run at all. Public so WipeRoutine
         *  can delete it by name on every wipe path. */
        const val EXT_TOR_PROXY_PREFS_NAME = "ext_tor_proxy_prefs"

        /** External proxy mode's TCP reachability check budget. A loopback/LAN
         *  listener answers a connect in milliseconds; this only bounds a
         *  black-holed LAN address. */
        private const val EXT_PROXY_REACHABILITY_TIMEOUT_MS = 5_000

        /** Cadence for the Debug-mode periodic log flush tick (Settings →
         *  Debug mode), for as long as the relay health loop it shares a
         *  lifecycle with ([startRelayCheck]) is running. Matches
         *  [DebugLogUploader]'s own "roughly once a second" cursor-tick design
         *  (it is cursor-based and incremental, so an idle tick with nothing
         *  new to send is a cheap no-op, not a wasted upload). */
        private const val DEBUG_LOG_PERIODIC_INTERVAL_MS = 1_000L

        /** Ceiling on the Debug-mode FINAL flush at lock/teardown
         *  ([lockSession]). This one runs on the calling thread (runBlocking —
         *  see the call site for why), which on the re-auth path is the UI
         *  thread, so it is a hard cap on how long a lock can visibly stall.
         *  Paired with a skip-entirely gate when the session's last health
         *  probe failed, so the budget is only ever spent on a circuit that
         *  just answered.
         *  iOS sibling: the `sem.wait(timeout:)` in `AppState.lock()`. */
        private const val DEBUG_LOG_LOCK_FLUSH_TIMEOUT_MS = 1_500L

        /**
         * How long the post-unlock move import waits for a live transport before
         * handing `MoveManager` a null one (docs/device-move.md phone B step 4a).
         * The import runs seconds after a FRESH provision, so Tor is normally still
         * bootstrapping; this is deliberately a bit past
         * [TOR_BOOTSTRAP_STALL_MS] + the hidden-service handshake, so the honest
         * "no relay" error is reported only when there really is none.
         */
        private const val MOVE_IMPORT_TRANSPORT_WAIT_MS = 150_000L
    }

    private val cryptoProvider = CryptoProvider(application)
    private val selectorStore = KeyValueStore(application, VAULT_SELECTOR_PREFS_NAME)

    // The wrong-PIN counter lives in its OWN SharedPreferences file, not
    // alongside the credential hashes in vault_selector_prefs.
    // Why: persisting the counter before PIN evaluation used to race the
    // emergency wipe — an async flush could recreate vault_selector_prefs
    // *with the credential hashes* after deleteSharedPreferences ran (the
    // 2026-05-11 regression). A counter-only file can only ever be resurrected
    // as a counter, which is harmless and in fact self-healing (a stale
    // count >= MAX just re-triggers the wipe on next launch).
    private val pinAttemptsStore = KeyValueStore(application, "pin_attempts_prefs")

    // Debug mode (Settings → Debug mode, DebugMode.kt commonMain): opt-in
    // anonymous diagnostic-log upload to the relay. Own prefs file, same
    // reasoning as [NOTIFICATION_LEVEL_PREFS_NAME] — non-secret and must be
    // readable without an open vault ([RunApplication.onCreate] reads/applies
    // it before any vault exists). Read once at construction; [setDebugMode]
    // is the only writer thereafter, keeping [_debugMode] and the persisted
    // value in lockstep.
    private val debugModeStore = KeyValueStore(application, DEBUG_MODE_PREFS_NAME)
    private val _debugMode = MutableStateFlow(DebugMode.isEnabled(debugModeStore, cryptoProvider))
    val debugMode: StateFlow<Boolean> = _debugMode.asStateFlow()

    /** Settings → Debug mode toggle (consent dialog confirm).
     *
     *  The flag is taken from [DebugMode.setEnabled]'s RETURN VALUE, never from
     *  the requested `on`: turning it OFF can fail to persist (a store that
     *  refuses the delete AND the explicit "0" overwrite), and the row must then
     *  keep showing ON rather than claim a revocation the next launch will
     *  undo. iOS sibling: `AppState.setDebugMode(_:)`. */
    fun setDebugMode(on: Boolean) {
        _debugMode.value = DebugMode.setEnabled(debugModeStore, cryptoProvider, on)
    }

    // -----------------------------------------------------------------------
    // External SOCKS proxy mode (ExternalTorProxy.kt, commonMain)
    //
    // Read ONCE, here, at construction — i.e. before [init] runs
    // [startSpeculativeTor] — from its own pre-unlock prefs file. A change made
    // in Settings is persisted for the NEXT launch only; nothing switches live.
    //
    // While [externalProxyMode] is true the embedded Tor is NEVER constructed:
    // [startSpeculativeTor] returns before touching it (and stops a Tor kept warm
    // by a previous non-external session), [connectViaTor] diverts to
    // [connectViaExternalProxy], [startRelayStallWatch] to a rung-free watch, and
    // [newTorManager] — the single construction site — refuses outright as the
    // last line. With no TorManager every NEWNYM rung, the warm-up, the descriptor
    // hedge, the keep-alive and the bootstrap watchdogs are inert by construction
    // (each starts with `torManager ?: return`).
    //
    // FAIL CLOSED both ways: a stored value that does not authenticate, parse or
    // read is still external mode (messaging disabled, never "fall back to the
    // built-in Tor"), and an unreachable proxy leaves messaging unavailable.
    // -----------------------------------------------------------------------

    private val externalProxyStore = KeyValueStore(application, EXT_TOR_PROXY_PREFS_NAME)

    /**
     * This launch's stored setting, device-key SEALED
     * ([ExternalTorProxy.readStored] — a planted plaintext value is
     * UNAUTHENTICATED and reads as INVALID, never as an address to dial).
     * Android's store read has no transient-failure mode worth retrying (iOS
     * re-reads a Keychain "unknown" up to 3 times); an UNREADABLE device key
     * fails closed for this launch.
     */
    private val externalProxyRead: ExternalTorProxy.StoredRead =
        ExternalTorProxy.readStored(externalProxyStore, cryptoProvider)

    /** External proxy mode is ON for this launch (valid or not). The embedded Tor must never start. */
    val externalProxyMode: Boolean = externalProxyRead.modeOn

    /** This launch's proxy, or null (mode off, or mode on with an invalid/unreadable stored value). */
    val externalProxy: ExternalTorProxyConfig? = externalProxyRead.config

    /** UI status of external proxy mode for THIS session. */
    enum class ExternalProxyStatus { OFF, INVALID, UNREADABLE, CHECKING, REACHABLE, UNREACHABLE }

    private val _externalProxyStatus = MutableStateFlow(
        when (externalProxyRead.state) {
            ExternalTorProxy.StoredState.OFF -> ExternalProxyStatus.OFF
            ExternalTorProxy.StoredState.INVALID -> ExternalProxyStatus.INVALID
            ExternalTorProxy.StoredState.UNREADABLE -> ExternalProxyStatus.UNREADABLE
            ExternalTorProxy.StoredState.VALID -> ExternalProxyStatus.CHECKING
        }
    )
    val externalProxyStatus: StateFlow<ExternalProxyStatus> = _externalProxyStatus.asStateFlow()

    /** The in-flight reachability check + transport wiring ([connectViaExternalProxy]). */
    private var extProxyConnectJob: Job? by sessionJobs.slot()

    /**
     * What is persisted NOW (may differ from [externalProxy] after a Save this
     * session — it applies at the next launch). Settings-screen read: one prefs
     * read + one device-key AEAD open, the same cost [DebugMode.isEnabled] pays
     * on Main at construction.
     */
    fun savedExternalProxy(): ExternalTorProxyConfig? =
        ExternalTorProxy.readStored(externalProxyStore, cryptoProvider).config

    /**
     * Seals and persists ([config] non-null) or clears ([config] null) the
     * external proxy setting for the NEXT launch; read back through the same
     * path the next launch uses. False when it did not verifiably land, or a
     * wipe already ran in this process (a write after a wipe would re-create
     * a file the wipe just deleted). Call off the main thread.
     */
    fun saveExternalProxy(config: ExternalTorProxyConfig?): Boolean {
        if (ProcessWipeLatch.wipedThisProcess) return false
        return ExternalTorProxy.writeStored(externalProxyStore, cryptoProvider, config)
    }

    // -----------------------------------------------------------------------
    // Vault selector + PIN-attempt stores
    // -----------------------------------------------------------------------

    val vaultSelector = VaultSelector(
        store = selectorStore,
        crypto = cryptoProvider,
        vaultFactory = androidVaultFactory(application),
        // Lever B: the DB-key OUTER layer can be hardware auth-bound (opt-in via
        // Settings). The credential verifier + pre-PIN counters are NOT routed
        // through this — they keep using cryptoProvider directly, so a counter
        // read never triggers a biometric prompt (the key split).
        dbKeyProtector = AndroidDbKeyProtector(application, cryptoProvider),
        // The live vault handle, for the SQLCipher key
        // rotation a credential TIER UPGRADE (PIN → passphrase) performs. Read
        // through a lambda, not captured: [vault] is nulled on lock/wipe and
        // re-assigned on every unlock, and the rotation must see the CURRENT one (or
        // none, in which case it skips silently).
        vaultProvider = { vault },
        // VaultSelector has CLOSED that handle because a re-key
        // did not verifiably commit (its codec write context can no longer be
        // trusted — see VaultSelector.retireRekeyedVaultHandle). Latch the signal;
        // MainActivity collects it and performs the same whole-session teardown as
        // the Lever-C auto-lock (finishAndRemoveTask → onCleared), which is what
        // "locked" means on Android. Fires on the change-credential worker thread —
        // MutableStateFlow.value is thread-safe.
        onRekeyHandleRetired = { _vaultSessionRetired.value = true },
    )

    // The "counter established" marker goes in the
    // fate-shared selectorStore (vault_selector_prefs — holds the wrapped DB key),
    // NOT pinAttemptsStore, so deleting the counter file to reset the throttle is
    // detected as tamper (the marker survives) while deleting the marker's file
    // would destroy the DB-key wrap and make the vault unopenable anyway.
    // Un-rollable monotonic sample so a FORWARD wall-clock jump can't
    // reset the rolling wrong-credential / change-PIN windows (the forward sibling
    // of the existing backward-clamp defense). elapsedRealtime is kernel uptime,
    // which is NOT user-writable; a real reboot resets it, which windowRolled()
    // detects as "uptime went backwards" and falls back to the wall clock — so no
    // separate reboot id is needed. bootId is fixed to 0: the original
    // source, Settings.Global.BOOT_COUNT, was adb/shell-writable with no root
    // (WRITE_SECURE_SETTINGS), so an attacker could forge a reboot signal to force
    // the wall-clock fallback WITHOUT rebooting and reset the window. Dropped — kernel uptime alone is the trusted input.
    private val monotonicSampler: () -> MonotonicSample? = {
        MonotonicSample(SystemClock.elapsedRealtime(), 0L)
    }

    // vaultWrapKeyInAnchorStore=VAULT_DBKEY_STORAGE_KEY supplies the "vault
    // configured" signal read straight from the fate-shared vault_selector_prefs.
    // An absent counter with the MARKER surviving while the wrap is present is a
    // DELETION → wipe; an absent counter with NO marker on a configured vault is a
    // legacy / unmigrated / interrupted-provision vault → establish-on-read (never
    // wipe). So correctness no longer depends on the onVaultOpened establish — the
    // pre-unlock read self-heals a fresh/legacy vault to count 0.
    val pinAttempts = PinAttemptsStore(
        pinAttemptsStore, cryptoProvider, selectorStore,
        vaultWrapKeyInAnchorStore = VAULT_DBKEY_STORAGE_KEY,
        monotonicNow = monotonicSampler,
    )

    // Daily change-PIN abuse counter (shares pin_attempts_prefs so the same
    // wipe routine clears it). Triggers an emergency wipe after MAX_PER_DAY
    // change-PIN attempts in a 24h window — bounds penalty-free PIN probing
    // through the change-PIN flow (which is exempt from the unlock auto-wipe).
    // Anchored + monotonic like pinAttempts; a legacy / first-ever
    // change-PIN establishes-on-read (marker absent → record + arm, never wipe),
    // so the onVaultOpened establish() is an optimisation, not load-bearing.
    val changePinAttempts = ChangePinAttemptStore(
        pinAttemptsStore, cryptoProvider,
        anchorStore = selectorStore,
        vaultWrapKeyInAnchorStore = VAULT_DBKEY_STORAGE_KEY,
        monotonicNow = monotonicSampler,
    )

    // First-open push-notification prompt. Set by [onVaultOpened] from the
    // shared, one-shot [consumePushPromptOnce] vault-meta latch (see
    // PushPromptOnboarding.kt) — true only on the very first unlock this
    // vault has ever seen. Rendered by ContactListScreen (it owns
    // showNotificationSettings, the carousel this prompt's "Yes" opens),
    private val _showPushPrompt = MutableStateFlow(false)
    val showPushPrompt: StateFlow<Boolean> = _showPushPrompt.asStateFlow()

    fun dismissPushPrompt() {
        _showPushPrompt.value = false
    }

    // In-app update nudge. Set from the
    // relay health loop (startRelayCheck) once per session when the relay's
    // advertised version (MessageManager.newerRelayVersion(), a RAM latch off
    // the first successful relay response) is newer than this build AND the
    // per-day-per-version vault throttle (UpdateNudge.kt) allows it. Rendered
    // by ContactListScreen at the LOWEST priority of the three dialogs — see
    // the gating comment there. Non-null value is the version string to show
    // (already re-rendered from the parsed triple — never the raw header).
    private val _showUpdateNudge = MutableStateFlow<String?>(null)
    val showUpdateNudge: StateFlow<String?> = _showUpdateNudge.asStateFlow()

    fun dismissUpdateNudge() {
        _showUpdateNudge.value = null
    }

    /**
     * Whether the running install came from the Play Store — computed lazily
     * ONCE per instance (the installer of record cannot change without a
     * reinstall). Gates the update-nudge dialog's store button (by design,
     * non-Play installs get an info-only modal, no store egress).
     *
     * `getInstallSourceInfo` (API 30+) / `getInstallerPackageName` (29, the
     * app's actual minSdk) are both nullable and neither is documented as
     * throw-free across every OEM, so this is wrapped in try/catch and a null
     * result — FAILS CLOSED to `false` (info-only) on any doubt, never assumes
     * a store install it cannot prove.
     */
    val isPlayInstall: Boolean by lazy {
        // e2e-only escape hatch (TestHooks.handleTestForceStoreInstall,
        // `--ez TEST_FORCE_STORE_INSTALL true`): a sideloaded/emulator debug
        // build has no real Play Store installer of record, so the two-button
        // variant below could otherwise never be exercised there. The release
        // TestHooks stub always reports `forceStoreInstall = false`, so this
        // branch is a no-op in a shipped APK.
        if (TestHooks.forceStoreInstall) {
            true
        } else {
            try {
                val app = getApplication<Application>()
                val installer = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.R) {
                    app.packageManager.getInstallSourceInfo(app.packageName).installingPackageName
                } else {
                    @Suppress("DEPRECATION")
                    app.packageManager.getInstallerPackageName(app.packageName)
                }
                isPlayInstaller(installer)
            } catch (_: Exception) {
                false
            }
        }
    }

    /**
     * Opens the Play Store listing for an update. `market://` only — there is NO `https://play.google.com/...` fallback:
     * an unresolvable `market://` (no Play Store app) means info-only, not a
     * browser-history row naming this app's package. Started from the
     * application context ([FLAG_ACTIVITY_NEW_TASK]) since this is a
     * ViewModel, not an Activity.
     */
    fun openPlayStoreForUpdate() {
        try {
            getApplication<Application>().startActivity(
                android.content.Intent(android.content.Intent.ACTION_VIEW, android.net.Uri.parse(PLAY_STORE_MARKET_URI))
                    .addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
            )
        } catch (_: Exception) {
            // No handler for market:// (ActivityNotFoundException) or a
            // work-profile/MDM policy refusing it (SecurityException) — stay
            // info-only, no egress, never crash on the tap.
        }
    }

    /** Unlock-time read of the push-prompt latch against the CURRENTLY OPEN
     *  [vault]. Never throws — see [consumePushPromptOnce]'s kdoc; false if
     *  no vault is open (unreachable in practice, only called right after a
     *  successful unlock/provision/recovery from [onVaultOpened]). */
    fun consumePushPromptOnce(): Boolean = vault?.let { consumePushPromptOnce(it) } ?: false

    private var pushPromptJob: Job? by sessionJobs.slot()
    private var pushPromptOfferedThisSession = false
    /** Set with [_requestReviewFlow]; the push prompt yields to the native review sheet (see the gate). */
    private var reviewSheetRequestedThisSession = false

    /**
     * Raises the one-shot first-open push prompt the first time [isRelayReachable]
     * turns true this session (gate: [pushPromptDueOnRelayContact], commonMain).
     * The vault-meta latch is consumed only then, so a session that never reaches
     * the relay keeps it for the next one. A session that already requested the
     * store-review sheet skips (latch untouched — asks next session). Armed at
     * unlock, cancelled with the session's other relay jobs (lock / wipe /
     * teardown). iOS sibling: AppState.checkRelayReachability's push-prompt block.
     */
    private fun armPushPromptForFirstRelayContact() {
        pushPromptJob?.cancel()
        pushPromptOfferedThisSession = false
        pushPromptJob = viewModelScope.launch {
            isRelayReachable.collect { reachable ->
                if (!pushPromptDueOnRelayContact(
                        relayReachable = reachable,
                        alreadyOfferedThisSession = pushPromptOfferedThisSession,
                        reviewSheetRequestedThisSession = reviewSheetRequestedThisSession,
                    )
                ) return@collect
                pushPromptOfferedThisSession = true
                val openVault = vault ?: return@collect
                // Vault meta read+write — off the main thread, like every other
                // post-unlock vault touch in this file.
                val due = withContext(Dispatchers.IO) {
                    consumePushPromptOnce(openVault)
                }
                if (due) _showPushPrompt.value = true
            }
        }
    }

    val isDeviceCompromised: Boolean = IntegrityCheck.isCompromised

    var vault: VaultDatabase? = null
        private set

    /**
     * Periodic random re-auth at MAXIMUM (docs/periodic-reauth-design.md):
     * `SystemClock.elapsedRealtime()` deadline for the NEXT forced re-lock,
     * armed in [onVaultOpened] when [ReauthPolicy.isEnabled] and cleared by
     * [lockSession] on every lock — so it can never be read against a null
     * vault, and a locked/PIN-screen state never carries a stale deadline into
     * the next unlock's arm (which recomputes it fresh either way).
     * MainActivity's watchdog reads this alongside Lever C's idle timeout and
     * fires whichever is nearer; [startLockPolicyBackstop] reads it too, so the
     * deadline holds while no Activity is attached.
     */
    var reauthDeadlineElapsedMs: Long? = null
        private set

    /**
     * Lever C's idle clock (`SystemClock.elapsedRealtime()` of the last user
     * interaction). It lives HERE, not in MainActivity, so a configuration-change
     * recreation of the Activity neither resets it nor drops its evaluator: see
     * [LockPolicyBackstop] for the attack this closes (security review it3, S2 F1).
     * MainActivity writes it on every interaction and on an ordinary resume.
     */
    @Volatile
    var lastInteractionElapsedMs: Long = SystemClock.elapsedRealtime()
        private set

    fun noteUserInteraction() {
        lastInteractionElapsedMs = SystemClock.elapsedRealtime()
    }

    /**
     * Set by MainActivity.onPause when the pause is a configuration change, read
     * once by the next instance's onResume: a resume that only follows a rotation
     * or a uiMode change is not a user interaction, so it must not reset
     * [lastInteractionElapsedMs]. Main thread only.
     */
    private var configChangeRecreationPending = false

    fun markConfigurationChangeRecreation() {
        configChangeRecreationPending = true
    }

    fun consumeConfigurationChangeRecreation(): Boolean {
        val pending = configChangeRecreationPending
        configChangeRecreationPending = false
        return pending
    }

    /**
     * PROCESS-scoped (this ViewModel's whole life, never cancelled by a lock): the
     * Activity-independent evaluator of both lock deadlines. Started at the end of
     * [init]; see [LockPolicyBackstop] and [startLockPolicyBackstop].
     */
    private var lockPolicyBackstopJob: Job? = null

    /**
     * Keyboard privacy scales with the protection tier (a product decision;
     * see [ComposerKeyboardPolicy]): true keeps
     * ConversationScreen/GroupConversationScreen's message composer in
     * `KeyboardType.Password` (no IME learning/suggestions, no emoji key on
     * most Android keyboards); false switches to `KeyboardType.Text` with
     * autocorrect off. Defaults strict and is re-read in [onVaultOpened] —
     * the tier can only change via the Protection screen, which re-provisions
     * (and therefore re-unlocks) — mirroring [reauthDeadlineElapsedMs].
     */
    var strictComposerKeyboard: Boolean = true
        private set

    var messageManager: MessageManager? = null
        private set

    /** Group chat orchestration. Lives exactly as long as the unlocked vault;
     *  reads the CURRENT messageManager via the provider lambda, so Tor
     *  reconnects (which recreate the manager) need no re-wiring. */
    var groupManager: GroupManager? = null
        private set

    /** Referral/vouching (referral.md). Created on unlock alongside groupManager;
     *  the group control poll feeds it referral controls via onReferralControl. */
    var referralManager: ReferralManager? = null
        private set

    /** The Maximum shield (MaximumShield.kt): built with the session managers, passed to
     *  each MessageManager (receiver) and read by the contact list / conversation title. */
    var maximumShield: MaximumShield? = null
        private set

    // -----------------------------------------------------------------------
    // Move to new device (docs/device-move.md)
    // -----------------------------------------------------------------------

    /**
     * The platform half of the move (`MoveSessionControl`): push unregistration,
     * the session quiesce/resume, and the live relay transport. Declared in its
     * own file (MoveSessionControlAndroid.kt) — every method here is a one-line
     * delegate to the `move*` members below, which is where the reasoning lives.
     */
    private val moveSession: MoveSessionControl by lazy { AndroidMoveSessionControl(this) }

    /**
     * Lazy so a session that never moves pays nothing, and so construction
     * happens on first USE (post-unlock, where the vault is open) rather than at
     * ViewModel construction, where `MoveManager.init`'s frozen-state read would
     * see a null vault. The delegate is held separately from the property so the
     * teardown paths can ask `isInitialized()` instead of constructing one just
     * to scrub it.
     */
    private val moveExportAuthGate = MoveExportAuthGate()
    private val moveManagerDelegate = lazy {
        MoveManager(
            vault = { vault },
            session = moveSession,
            platformTag = MigrationBundle.FROM_ANDROID,
            exportAuthGate = moveExportAuthGate,
        )
    }
    private val moveManagerImpl: MoveManager by moveManagerDelegate

    /** The move state machine. `MoveManagerApi` is the surface both UIs use. */
    val moveManager: MoveManagerApi get() = moveManagerImpl

    /**
     * NEW-phone side: the scanned/pasted handle, held in RAM ONLY (never the
     * vault, never SecurePrefs — docs/device-move.md phone B step 2). It carries
     * the read capability AND the one-time code, so persisting it would put the
     * whole transfer key on disk on a phone that has not even provisioned yet.
     *
     * Living on the ViewModel (not in a composable `remember`) is what makes the
     * import survive a screen rotation — the Activity is recreated, this object is
     * not. A PROCESS death is a different matter and deliberately so: the handle
     * is gone, the user rescans the (still valid, TTL permitting) code on the old
     * phone. That is the same fail-direction as `MainActivity.onStop` →
     * `finishAndRemoveTask` → `onCleared`, which tears this ViewModel down with
     * everything else on every background.
     */
    var pendingMoveHandle: MoveHandle? = null
        private set

    fun setPendingMoveHandle(handle: MoveHandle?) {
        pendingMoveHandle = handle
    }

    /** UI-facing state of the post-unlock import run ([startPendingMoveImport]). */
    private val _moveImportState = MutableStateFlow<MoveImportUiState>(MoveImportUiState.Idle)
    val moveImportState: StateFlow<MoveImportUiState> = _moveImportState.asStateFlow()

    /** ViewModel-scoped so neither an export nor an import dies with a rotation. */
    private var moveOpJob: Job? by sessionJobs.slot()

    /** The 10 s transfer peek. Its own job, so a slow peek can never make the
     *  cancel button look dead. */
    private var movePollJob: Job? by sessionJobs.slot()

    /**
     * True while this device is the OLD phone of a move (or is running the export
     * that makes it one): every poll loop stays down and no push registration is
     * made, while Tor and the MessageManager stay ALIVE because the transfer inbox
     * still needs them ([MoveSessionControl.quiesce]'s contract — see
     * [moveQuiesceSession]).
     *
     * Read on the Main thread by the loop starters and written by the quiesce /
     * resume / unlock paths, all of which hop to Main.
     */
    private var moveQuiesced = false

    // -----------------------------------------------------------------------
    // Connect state (Tor + relay reachability flows)
    // -----------------------------------------------------------------------

    private var torMonitorJob: Job? by sessionJobs.slot()

    /**
     * The Job for the currently in-flight `tor.start()` launch. Tracked so a torManager swap can cancel the OLD instance's
     * start() coroutine instead of leaving it to keep running past torManager?.
     * stop() — it must not outlive its replacement. A plain cancel() is
     * sufficient: TorManager's own stopped/purgedForRetry guards already make
     * start() abstain after an external stop, so this only closes the
     * bookkeeping gap, not a correctness hole.
     */
    private var torStartJob: Job? by sessionJobs.slot()

    /** The single in-process TorManager, owned by this ViewModel. */
    private var torManager: TorManager? = null

    private val _torState = MutableStateFlow<TorManager.ConnectionState>(TorManager.ConnectionState.Idle)
    val torState: StateFlow<TorManager.ConnectionState> = _torState.asStateFlow()

    private val _isRelayReachable = MutableStateFlow(false)
    val isRelayReachable: StateFlow<Boolean> = _isRelayReachable.asStateFlow()

    /**
     * The connect-time unread prime ([startUnreadPrime]) has SETTLED for this
     * transport: its FIRST per-contact result landed, or the pass ended
     * without emitting anything (no contacts, every peek failed, cancelled), or
     * it was skipped, or the [UNREAD_PRIME_REVEAL_CAP_MS] backstop counted from
     * the first relay answer ran out. Reset wherever [_relayHandshakeComplete]
     * is (per transport). Every write goes through [settleUnreadPrime], which
     * owns the shared rules in [ConnectReveal].
     */
    private val _unreadPrimeSettled = MutableStateFlow(false)
    private var unreadPrimeCapJob: Job? by sessionJobs.slot()

    /**
     * Settles the unread-prime half of [contactsReady] — the ONLY place that
     * flips it true. The decision (is this the first event? does it narrate
     * PRIME_CAP?) lives in [ConnectReveal.primeSettle] so iOS's
     * `AppState.settleUnreadPrime` reveals on exactly the same evidence.
     *
     * The flip is a compare-and-set because the callers are on DIFFERENT
     * threads: [ConnectReveal.PrimeEvent.FIRST_DOT] and
     * [ConnectReveal.PrimeEvent.PASS_ENDED] arrive on the prime's I/O worker
     * while [ConnectReveal.PrimeEvent.CAP] arrives on Main. Losing the race
     * must cost nothing more than a line, and never a DUPLICATE line.
     *
     * Deliberately does NOT cancel [unreadPrimeCapJob] (that job is the CAP
     * caller itself on one path, and its own guard re-reads the flag before it
     * narrates anything).
     */
    private fun settleUnreadPrime(event: ConnectReveal.PrimeEvent) {
        val outcome = ConnectReveal.primeSettle(_unreadPrimeSettled.value, event)
        if (!outcome.settles) return
        if (!_unreadPrimeSettled.compareAndSet(expect = false, update = true)) return
        // A settle that came from an answered peek is a relay answer in its own
        // right — see [_relayFirstAnswer]. Read off the manager's latch, never
        // inferred from the event kind: PASS_ENDED with every peek failed settles
        // the prime but has proven nothing about the relay.
        if (messageManager?.hasCompletedRelayRoundTrip() == true) _relayFirstAnswer.value = true
        if (outcome.logCapLine) {
            LogBuffer.append("W", "ViewModel", "unread prime reveal cap hit — revealing contacts without it")
            // PRIME_CAP: the reveal was held by a wedged peek, not by the
            // network — without a code this line was invisible to the connect
            // timeline. iOS emits the identical phrase.
            ConnectionLog.append(
                ConnectionLog.Kind.RELAY,
                "unread prime cap ${ConnectReveal.UNREAD_PRIME_REVEAL_CAP_SEC} s — revealing contacts",
                ConnectionLog.Code.PRIME_CAP,
            )
        } else {
            LogBuffer.append(
                "D", "ViewModel",
                "unread prime settled (${event.name.lowercase().replace('_', ' ')}) — contacts may reveal",
            )
        }
    }

    /**
     * The gate's OTHER "relay answered" source (connect-time lever):
     * this transport's first completed onion round trip as seen by the prime —
     * the first /peek 2xx IS a relay answer, and on prod it lands before the
     * parallel health probe (the only thing that used to flip
     * [_isRelayReachable]) by 130 ms at p50 and up to 500 ms. Flipped in
     * [settleUnreadPrime] off `MessageManager.hasCompletedRelayRoundTrip()`, reset
     * per transport alongside [_unreadPrimeSettled]. [isRelayReachable] itself is
     * untouched: the outage banner and send enablement still wait for the probe.
     * iOS sibling: `AppState.recomputeContactsReady`.
     */
    private val _relayFirstAnswer = MutableStateFlow(false)

    /**
     * THE contact-list reveal gate (user requirement): the relay has
     * answered AND the unread prime has settled, so every "message waiting" dot
     * is already in [unreadCounts] in the frame the runestone lights and the
     * contacts appear — never a list first and dots trickling in a beat later.
     * [isRelayReachable] stays the raw outage signal (relay-trouble banner,
     * send enablement, the conversation screens); only the list screen's
     * connect transition keys on this. Eagerly shared so the screen sees the
     * current value on its first composition. The predicate itself is
     * [ConnectReveal.contactsReady], shared with iOS's
     * `AppState.recomputeContactsReady`.
     */
    val contactsReady: StateFlow<Boolean> = combine(
        _isRelayReachable, _relayFirstAnswer, _unreadPrimeSettled,
    ) { reachable, answered, settled ->
        ConnectReveal.contactsReady(relayAnswered = reachable || answered, primeSettled = settled)
    }.stateIn(viewModelScope, SharingStarted.Eagerly, false)

    /**
     * The anonymous connect-time report, its anchors and phase stamps, the reveal
     * mark, the Debug-mode first flush and the pre-unlock boot observer. Declared
     * BELOW [isRelayReachable], [contactsReady] and [debugMode] (initializers run
     * in text order) and above `init {}`.
     */
    private val telemetry = ConnectTelemetryRecorder(
        scope = viewModelScope,
        isRelayReachable = isRelayReachable,
        contactsReady = contactsReady,
        debugMode = debugMode,
        relayHttp = { currentRelayHttp() },
        relayTransport = { messageManager?.relayTransport() },
        externalProxyMode = { externalProxyMode },
    )


    /**
     * "We have actually talked to the relay on this Tor session" — latched on the
     * first COMPLETED `.onion` round-trip (MessageManager.hasCompletedRelayRoundTrip),
     * NOT on Tor's `Bootstrapped 100%`.
     *
     * Bootstrap only proves Tor reached the directory system and built *a* circuit;
     * the hidden-service descriptor fetch + rendezvous with the relay's onion happens
     * afterwards and routinely takes several more seconds. The UI used to call itself
     * connected (ring solid, pulse stopped, connect flash) the instant Tor said 100%,
     * so a cold start claimed connectivity while every request was still failing.
     * This is the honest signal, and iOS's visible "connected" claim is already gated
     * on the same evidence (litVisible ← isRelayReachable), so this restores parity.
     *
     * Unlike [isRelayReachable] it never flaps back to false on a transient miss — it
     * is reset only when the transport itself is torn down (Tor restart / lock / wipe).
     */
    private val _relayHandshakeComplete = MutableStateFlow(false)
    val relayHandshakeComplete: StateFlow<Boolean> = _relayHandshakeComplete.asStateFlow()
    private var relayCheckJob: Job? by sessionJobs.slot()

    /**
     * Backstop for [contactsReady]: how long after the FIRST relay answer the
     * list waits for the unread prime before revealing anyway. 3 s —
     * the gate now releases on the prime's FIRST per-contact result, so this
     * only ever covers a genuinely wedged peek. THE number lives in
     * [ConnectReveal.UNREAD_PRIME_REVEAL_CAP_MS], which iOS's
     * `AppState.unreadPrimeRevealCapSec` reads too, because it is printed into
     * a panel line both platforms must emit word for word.
     */
    private val UNREAD_PRIME_REVEAL_CAP_MS = ConnectReveal.UNREAD_PRIME_REVEAL_CAP_MS
    /** Debug mode (Settings → Debug mode) periodic log upload — same
     *  start/cancel sites as [relayCheckJob] (see [startRelayCheck]), so a
     *  move-freeze pause or a Tor restart pauses/resumes it identically. */
    private var debugLogPeriodicJob: Job? by sessionJobs.slot()
    // Guards the update-nudge evaluation in [startRelayCheck] to AT MOST ONCE
    // per ViewModel instance ("session" — the app is foreground-only and this
    // ViewModel is fully torn down on background), so the vault throttle
    // (shouldShowUpdateNudge/markUpdateNudgeShown) is never read on every
    // 8-12s health-check tick.
    private var updateNudgeEvaluated = false
    // Guards the in-app store-review evaluation in [startRelayCheck] to AT
    // MOST ONCE per ViewModel instance/session — same shape as
    // updateNudgeEvaluated above, and evaluated at the SAME tick (right after
    // it), so the ordering rule ("never in the same session as the push
    // prompt or the update nudge") reads the two other prompts' CURRENT,
    // already-settled state rather than racing their own decisions. See
    // ReviewPromptPolicy.kt (commonMain) for the actual gates.
    private var reviewPromptEvaluated = false
    // One-shot per-session signal that ContactListScreen consumes to
    // actually invoke ReviewManagerFactory — a ViewModel cannot call
    // launchReviewFlow(activity, info) itself (Play In-App Review needs an
    // Activity, not just an Application Context). Set only once ↓ in
    // [startRelayCheck]; [consumeRequestReviewFlow] resets it so it can never
    // re-fire the launch on a later recomposition.
    private val _requestReviewFlow = MutableStateFlow(false)
    val requestReviewFlow: StateFlow<Boolean> = _requestReviewFlow.asStateFlow()

    /** ContactListScreen calls this immediately after it has (attempted to)
     *  launch the Play In-App Review flow for a fired [requestReviewFlow]. */
    fun consumeRequestReviewFlow() {
        _requestReviewFlow.value = false
    }

    private var controlPollJob: Job? by sessionJobs.slot()
    // One-shot parallel /peek sweep fired the instant transport wires up, racing
    // the badge dot ahead of the control poll's first jittered cycle (3-7s+).
    // See [startUnreadPrime].
    private var unreadPrimeJob: Job? by sessionJobs.slot()

    // Relay-connect self-heal + stall UX. While the relay stays
    // unreachable, escalate Connecting → (auto-restart Tor once) → Stalled, at which
    // point the contact list offers a manual Reconnect. Only meaningful while the relay
    // is unreachable; the moment it's reachable the phase resets (and the UI is hidden).
    enum class RelayConnectPhase { Connecting, Stalled }
    private val _relayConnectPhase = MutableStateFlow(RelayConnectPhase.Connecting)
    val relayConnectPhase: StateFlow<RelayConnectPhase> = _relayConnectPhase.asStateFlow()
    private var relayStallJob: Job? by sessionJobs.slot()

    /**
     * How many COLD-TRANSPORT NEWNYMs ([maybeFireEarlyNewnym]) this session
     * has fired. Bounded by [MessageManager.EARLY_NEWNYM_MAX_FIRES].
     *
     * Lives on the ViewModel, not on the MessageManager, on purpose: a Tor
     * restart or a re-wire builds a NEW MessageManager, and the cap is per
     * SESSION (one user wait), exactly like [ConnectTelemetryRecorder.connectStartElapsedMs] which it is
     * measured against. Deliberately NOT reset by [restartTor] or
     * [reconnectRelay] for the same reason. Counts only this rung's fires — the
     * heavier [startRelayStallWatch] rung keeps its own independent counter.
     */
    private var earlyNewnymsFired = 0

    /**
     * How many of [earlyNewnymsFired] were the COLD rung's own fires
     * ([maybeFireEarlyNewnym]), as opposed to the warm-up rotation. Picks
     * the cold rung's 35 s / 80 s floor; the cap stays on [earlyNewnymsFired]
     * (see [MessageManager.shouldFireEarlyNewnym]).
     * Same per-session scope. iOS sibling: `AppState.coldRungNewnymsFired`.
     */
    private var coldRungNewnymsFired = 0

    /**
     * Budgets of the WARM-TRANSPORT NEWNYM rung ([maybeFireWarmNewnym]) — per
     * dark run and per rolling hour, accounted by the shared commonMain
     * [WarmNewnymLedger] so iOS (`IosAppController.warmNewnymLedger`) spends
     * them identically. ViewModel-scoped for the same reason as
     * [earlyNewnymsFired]: a Tor restart / re-wire builds a new MessageManager,
     * and the hourly cap must survive it. Independent of [earlyNewnymsFired]
     * (the cold rung + warm-up budget) and of [startRelayStallWatch]'s own
     * per-outage counter.
     */
    private val warmNewnymLedger = WarmNewnymLedger()

    /**
     * Set-once SESSION latch: the relay has answered at least once this session
     * ([_isRelayReachable] or [_relayHandshakeComplete] ever true). Input to the
     * shared warm-up rotation gate ([MessageManager.shouldFireWarmupNewnym]),
     * which must refuse once the session has reached the relay. Lives here, not
     * on the MessageManager, because a Tor restart / re-wire builds a fresh
     * manager whose own round-trip latch starts false again. Never reset — same
     * per-session scope as [earlyNewnymsFired]. iOS sibling:
     * `AppState.relayAnsweredThisSession`.
     */
    private var relayAnsweredThisSession = false

    /**
     * The SESSION's descriptor hedge ([DescriptorHedge]), handed to
     * every [TorManager] this ViewModel builds (speculative and post-unlock alike —
     * a stalled pre-unlock fetch is the same stall the first probe would wait on).
     * One per ViewModel = one per foreground session (MainActivity.onStop tears the
     * whole session down), so its budget of [DescriptorHedge.HSDESC_FETCH_BUDGET]
     * hedge HSFETCHes is NOT replenished by a NEWNYM or by a Tor restart inside the
     * session — only a new session starts a new one. Its gate is
     * [relayAnsweredForCircuitWatchdog] (no relay answer yet this session). iOS
     * sibling: `IosAppController.descriptorHedge`. Declared ABOVE `init` on
     * purpose: init calls startSpeculativeTor, which hands it to a TorManager.
     */
    private val descriptorHedge = DescriptorHedge()

    /**
     * PRE-CONNECT Tor bootstrap stall — the Android sibling of iOS
     * `AppState.torBootstrapStalled` (App Store review 2.1 on 0.8.159: both
     * platforms' pre-connect surfaces spun forever with no honest feedback).
     *
     * Set when Tor has been starting for [TOR_BOOTSTRAP_STALL_MS] without reaching
     * Connected, so the contact list and Add Contact can say "this network may be
     * blocking it" instead of an endless "Connecting…".
     *
     * INFORMATIONAL ONLY — this watchdog never stops or restarts Tor. The single
     * auto-restart stays where it was, in [startRelayStallWatch] (which
     * deliberately waits past Tor's own ~90s bootstrap timeout so an in-progress
     * bootstrap is never interrupted). It retracts itself the moment Tor connects,
     * and [RelayConnectPhase.Stalled] outranks it in the UI.
     */
    private val _torBootstrapStalled = MutableStateFlow(false)
    val torBootstrapStalled: StateFlow<Boolean> = _torBootstrapStalled.asStateFlow()
    private var torStallJob: Job? by sessionJobs.slot()

    /**
     * One-shot latch for [startSpeculativeTor] — a second construction would
     * orphan the first Tor child and race it for the same DataDirectory lock.
     * Plain `Boolean`, not `@Volatile`/atomic: the only writer and the only
     * readers are on the Main thread ([init] and, defensively, any future
     * ViewModel-scoped call site). Never reset — a session gets exactly one
     * speculative start, and every subsequent Tor decision runs through
     * [connectViaTor].
     */
    private var speculativeTorStarted = false

    /**
     * The pre-unlock rendezvous warm-up (see [armPreUnlockRelayWarmup]).
     * Armed exactly once, beside the speculative Tor start; cancelled by every
     * teardown ([lockSession], [performEmergencyWipe]) and by the fresh-instance
     * branch of [connectViaTor], whose `stop()` retires the Tor it was waiting on.
     */
    private var relayWarmupJob: Job? by sessionJobs.slot()

    /** One-shot: the next [startRelayStallWatch] uses the full first window. Main thread. */
    private var relayStallWatchFullFirstWindow = false

    /** Bumped after every network-restore kick attempt; the opt-out ladder's
     *  backoff ends early when it moves ([PushRegistration.awaitBackoffOrWake]). */
    private val networkRestoreEpoch = MutableStateFlow(0L)

    /**
     * The network-restore hook ([NetworkRestoreMonitor]); the action is
     * [performNetworkRestoreKick]. Declared ABOVE init on purpose: init registers
     * the callback, and Kotlin runs property initializers and init blocks in
     * textual order.
     */
    private val networkRestore = NetworkRestoreMonitor(application, viewModelScope) {
        performNetworkRestoreKick()
    }

    init {
        // SPECULATIVE TOR: bootstrap CONCURRENTLY with the user typing their
        // credential; the unlock then ADOPTS the live instance (see
        // [connectViaTor]) rather than destroying it.
        //
        // ViewModel-scoped, NOT composable-scoped, deliberately: the PIN screen
        // recomposes freely, so a Composable-scoped trigger (LaunchedEffect,
        // remember) could double-fire and spawn a second Tor child.
        //
        // Ordering safety — every launch-time wipe runs strictly BEFORE this
        // ViewModel can exist, so no wipe can ever land on top of a speculative
        // Tor it did not know about. MainActivity.onCreate does, in order:
        // the ProcessWipeCover check (early-returns without ever building a
        // ViewModel), TestHooks.handleTestWipe, InactivityWipe.checkAndWipeIfNeeded
        // and the orphaned-credential self-heal — and only then first constructs
        // RunViewModel (for the vaultSessionRetired collector, and the same
        // instance again via viewModel() inside setContent).
        //
        // Every MID-session teardown already covers this new pre-unlock window
        // with ZERO changes, because the speculative start writes the SAME
        // [torManager] and [torStartJob] fields the unlock path uses and both
        // teardowns are unconditional on them: [onCleared] goes through
        // lockSession(stopTor = true), which cancels torStartJob (with every
        // session job) and then stops Tor or parks a Connected instance in the
        // bounded keep-alive (a still-bootstrapping speculative one is never
        // Connected, so it is stopped); [performEmergencyWipe] cancels
        // torStartJob and calls torManager.stopAndDiscardState() (which is what
        // makes the wrong-credential budget wipe safe while a speculative
        // bootstrap is in flight).
        //
        // Bounded Tor keep-alive (TorKeepAlive.kt): bind THIS session's callbacks
        // into the rebindable hooks every TorManager is built with BEFORE the
        // speculative start, which may adopt a Tor kept warm from the previous
        // session — that instance must call back into this ViewModel, never into
        // the cleared one that built it.
        TorKeepAliveHolder.hooks.bind(
            owner = this,
            descriptorHedge = { descriptorHedge },
            onDescriptorStageStalled = ::onDescriptorStageStalled,
            onNewCircuitAccepted = ::onNewCircuitAccepted,
            hsCircuitAnswered = ::relayAnsweredForCircuitWatchdog,
        )
        // Several onion addresses (RelayAddressRace): when the
        // descriptor race moves the session to a different address, the probe /
        // batch peek in flight is queued on the loser's descriptor — abort it and
        // re-probe on the winner. Process-wide race, this session's hook (iOS
        // sibling: IosAppController's init). Inert with one address.
        RelayEndpoints.race.bindSwitchListener(this) { messageManager?.noteRelayAddressSwitched() }
        startSpeculativeTor()
        // Network-restore kick: ViewModel-scoped like the Tor it kicks.
        networkRestore.register()
        // Last, so every field the backstop reads is initialized before its
        // first evaluation (it also sleeps before evaluating).
        startLockPolicyBackstop()
    }

    /**
     * Evaluates the periodic re-auth and Lever C deadlines on `viewModelScope`,
     * independent of any Activity (security review it3, S2 F1). The Activity's
     * watchdog stays the primary (countdown overlay, full teardown); this fires
     * [lockForReauth] at a passed re-auth deadline, and at Lever C's deadline plus
     * [LockPolicyBackstop.ACTIVITY_GRACE_MS] when no Activity locked first. Lever C
     * stays compiled out of debug builds here too, matching MainActivity.
     */
    private fun startLockPolicyBackstop() {
        lockPolicyBackstopJob?.cancel()
        lockPolicyBackstopJob = viewModelScope.launch {
            var sleepMs = LockPolicyBackstop.MAX_CHECK_INTERVAL_MS
            while (isActive) {
                delay(sleepMs)
                val open = vault != null
                val decision = LockPolicyBackstop.decide(
                    nowElapsedMs = SystemClock.elapsedRealtime(),
                    vaultOpen = open,
                    reauthDeadlineElapsedMs = reauthDeadlineElapsedMs,
                    idleTimeoutMs = if (open && !BuildConfig.DEBUG) {
                        CredentialPolicy.autoLockTimeoutMs(vaultSelector.protectionLevelForEnforcement())
                    } else {
                        null
                    },
                    lastInteractionElapsedMs = lastInteractionElapsedMs,
                )
                when (decision.action) {
                    LockPolicyBackstop.Action.REAUTH_LOCK -> {
                        LogBuffer.append("W", "ViewModel", "periodic re-auth (backstop) — locking vault")
                        lockForReauth()
                    }
                    LockPolicyBackstop.Action.IDLE_LOCK -> {
                        // No Activity got there first (it would have finished the
                        // task). The in-process lock closes the vault and wipes the
                        // keyset the same way; the PIN screen shows on return.
                        LogBuffer.append("W", "ViewModel", "inactivity auto-lock (backstop) — locking vault")
                        lockForReauth()
                    }
                    LockPolicyBackstop.Action.NONE -> Unit
                }
                sleepMs = decision.nextCheckInMs
            }
        }
    }

    // -----------------------------------------------------------------------
    // Session UI state (vault events, referral events, lock/wipe flags, unread +
    // signal maps)
    // -----------------------------------------------------------------------

    // Bumped whenever the background control poll drained something — an
    // invite/roster/leave/announce may have changed vault contents while NO
    // navigation happened. Vault-querying screens (contact list) key their
    // loads on this so a group appears the moment its invite is applied.
    private val _vaultEvents = MutableStateFlow(0)
    val vaultEvents: StateFlow<Int> = _vaultEvents.asStateFlow()

    // Introducer-side info modal (ContactListScreen): fed by
    // ReferralManager.onIntroRelayed when an introducee's accept lands on us
    // and is passed on to the other introducee. FIFO queue, RAM-only — a
    // whole-session teardown on background dropping an undelivered entry is
    // fine; this is informational, not a consent gate (nothing to redrive).
    //
    // Was unbounded (`it + event`), which defeated
    // commonMain's own MAX_PENDING_RELAY_EVENTS=8 pre-hook cap — when an
    // introduction's second leg is unreachable the success-only dedupe in
    // ReferralManager never arms, so every re-delivered accept appended
    // another entry (two aliases pinned in RAM) and queued another modal.
    // [appendReferralRelayEvent] now dedupes on introId and bounds the list
    // to [MAX_PENDING_REFERRAL_RELAY_EVENTS], dropping the OLDEST on overflow
    // (same eviction direction as the commonMain buffer it mirrors).
    private val _referralRelayEvents = MutableStateFlow<List<ReferralRelayEvent>>(emptyList())
    val referralRelayEvents: StateFlow<List<ReferralRelayEvent>> = _referralRelayEvents.asStateFlow()

    /** Pops the head of [referralRelayEvents] once its dialog is acknowledged. */
    fun dismissReferralRelayEvent() {
        _referralRelayEvents.update { if (it.isEmpty()) it else it.drop(1) }
    }

    /**
     * Appends [event] to [referralRelayEvents], deduping on [ReferralRelayEvent.introId]
     * (a re-delivered accept for an intro already queued replaces the stale entry in
     * place rather than adding a second one) and bounding the list to
     * [MAX_PENDING_REFERRAL_RELAY_EVENTS] by dropping the OLDEST entry on overflow.
     * See the kdoc on [_referralRelayEvents].
     */
    private fun appendReferralRelayEvent(event: ReferralRelayEvent) {
        _referralRelayEvents.update { current ->
            val deduped = current.filterNot { it.introId == event.introId }
            val withNew = deduped + event
            if (withNew.size > MAX_PENDING_REFERRAL_RELAY_EVENTS) {
                withNew.drop(withNew.size - MAX_PENDING_REFERRAL_RELAY_EVENTS)
            } else {
                withNew
            }
        }
    }

    // VaultSelector CLOSED the live vault handle mid-session
    // because a DB-key re-key did not verifiably commit (rolled-back
    // sqlite3_rekey_v2 — the handle's codec write context is poisoned; see
    // VaultSelector.retireRekeyedVaultHandle). MainActivity collects this and
    // tears the whole session down (finishAndRemoveTask → onCleared), the same
    // path as the Lever-C auto-lock; the next unlock's rotation reconcile then
    // reopens under whichever key really holds the file. STATE, not an event:
    // once true it stays true for this ViewModel's lifetime, so however late the
    // collector attaches (activity recreation) the teardown still happens.
    private val _vaultSessionRetired = MutableStateFlow(false)
    val vaultSessionRetired: StateFlow<Boolean> = _vaultSessionRetired.asStateFlow()

    // Periodic random re-auth at MAXIMUM (docs/periodic-reauth-design.md): set
    // by [lockForReauth] when the watchdog's re-auth deadline fires.
    // MainActivity collects this and navigates to "pin" (in-process, NOT
    // finishAndRemoveTask — see lockForReauth's kdoc for why Tor stays up),
    // then calls [consumeReauthLocked] so the flag doesn't re-fire the
    // navigation on the next recomposition/collector attach.
    private val _reauthLocked = MutableStateFlow(false)
    val reauthLocked: StateFlow<Boolean> = _reauthLocked.asStateFlow()

    /** MainActivity calls this immediately after dispatching the "pin"
     *  navigation for a fired [reauthLocked]. */
    fun consumeReauthLocked() {
        _reauthLocked.value = false
    }

    // iOS parity: LIVE (same-process, same-composition)
    // signal that a DENIABLE in-session emergency wipe just ran, so
    // MainActivity can render one process-lifetime black cover as a SIBLING of
    // (drawn on top of, and gating) the NavHost — rather than leaving the
    // decision to per-screen `remember { mutableStateOf(false) }` locals
    // (ChangePinScreen / RecoveryEntryScreen), which a NavHost `BackHandler`-
    // free BACK press could pop past to reveal a live screen underneath with a
    // null vault. Set ONLY when [performEmergencyWipe] runs with
    // `deniable = true` — exact same gate as [ProcessWipeCover.arm]; the two
    // are intentionally redundant (this one is a reactive Compose signal for
    // the CURRENT composition, [ProcessWipeCover] is the process-lifetime flag
    // `MainActivity.onCreate` reads on a config-change (re)create). Mirrors
    // iOS `AppState.wipedThisSession`, a `@Published` read as a top-level
    // `ContentView` branch (`ContentView.swift:230-236`) for the identical
    // reason. RAM-only, one-way for this ViewModel's lifetime — nothing clears
    // it (a relaunch/new ViewModel starts false, matching a fresh process).
    private val _wipedThisSession = MutableStateFlow(false)
    val wipedThisSession: StateFlow<Boolean> = _wipedThisSession.asStateFlow()

    // Contacts the relay has persistently 404'd (inbox lost server-side) → the
    // contact list flags them for re-pair. Refreshed by the control poll below.
    private val _relayLostContacts = MutableStateFlow<Set<String>>(emptySet())
    val relayLostContacts: StateFlow<Set<String>> = _relayLostContacts.asStateFlow()

    // contactId → count of text blobs waiting on the relay (the contact-list
    // unread badge count). Driven by a non-destructive /peek sweep on the
    // background poll loop; cleared optimistically when a conversation is
    // opened (the drain there empties the relay queue, so the next sweep
    // would clear it anyway — this just makes the badge feel instant).
    private val _unreadCounts = MutableStateFlow<Map<String, Int>>(emptyMap())
    val unreadCounts: StateFlow<Map<String, Int>> = _unreadCounts.asStateFlow()

    // groupId → unread group-message count. Group texts share members' 1:1
    // inboxes, so the /peek sweep can't attribute them; the GROUP dot is driven
    // by KIND_ACTIVITY control notices (GroupManager), cleared on group open.
    private val _groupUnreadCounts = MutableStateFlow<Map<String, Int>>(emptyMap())
    val groupUnreadCounts: StateFlow<Map<String, Int>> = _groupUnreadCounts.asStateFlow()

    // contactId → true once MessageManager.forwardSecrecyStalled
    // reports the per-contact legacy-fallback counter (dr-legacyfb) has crossed
    // RATCHET_FALLBACK_STALL_THRESHOLD — the responder's ratchet still has no sending
    // chain, so this device's outbound direction keeps falling through to the
    // no-forward-secrecy static envelope. A SIGNAL for the 1:1 conversation notice
    // row, never a send gate (see MessageManager's KDoc). Refreshed on conversation
    // open and after every completed send — see [refreshForwardSecrecyStalled] and
    // [sendMessageInBackground]; no polling loop.
    private val _forwardSecrecyStalled = MutableStateFlow<Map<String, Boolean>>(emptyMap())
    val forwardSecrecyStalled: StateFlow<Map<String, Boolean>> = _forwardSecrecyStalled.asStateFlow()

    /**
     * Re-evaluates [forwardSecrecyStalled] for one contact from the current
     * [messageManager]. Best-effort like the rest of this flag's read path: no
     * transport yet or a transient vault-read failure both read as "not stalled"
     * (never a false positive — see MessageManager.ratchetFallbackCount's KDoc).
     */
    fun refreshForwardSecrecyStalled(contactId: String) {
        val epoch = TransportFailedSends.shared.sessionEpoch
        val stalled = try { messageManager?.forwardSecrecyStalled(contactId) ?: false } catch (_: Exception) { false }
        // The read above may have straddled a lock / wipe: never re-key the map
        // with this contact's id after the teardown emptied it.
        if (!sessionStillCurrent(epoch)) return
        _forwardSecrecyStalled.value = _forwardSecrecyStalled.value + (contactId to stalled)
    }

    // contactId → true once
    // MessageManager.ratchetRefused reports the secure channel with this contact has
    // provably failed to establish and sends are being refused. Backs the
    // `ratchet_refused_notice` row, which takes precedence over the
    // `fs_stalled_notice` row when both would show. Refreshed on conversation open,
    // after every completed send, and on every poll tick — the last one because,
    // unlike [forwardSecrecyStalled], this signal is cleared by an INBOUND ratchet
    // blob, not only by our own send landing. See [refreshRatchetRefused] and
    // [sendMessageInBackground]. iOS sibling: AppState.ratchetRefused.
    private val _ratchetRefused = MutableStateFlow<Map<String, Boolean>>(emptyMap())
    val ratchetRefused: StateFlow<Map<String, Boolean>> = _ratchetRefused.asStateFlow()

    /**
     * Re-evaluates [ratchetRefused] for one contact from the current
     * [messageManager]. Best-effort like [refreshForwardSecrecyStalled]: no
     * transport yet or a transient vault-read failure both read as "not refused" —
     * never a false positive that would tell a user to re-pair a healthy contact.
     */
    fun refreshRatchetRefused(contactId: String) {
        val epoch = TransportFailedSends.shared.sessionEpoch
        val refused = try { messageManager?.ratchetRefused(contactId) ?: false } catch (_: Exception) { false }
        // Same straddle guard as [refreshForwardSecrecyStalled].
        if (!sessionStillCurrent(epoch)) return
        _ratchetRefused.value = _ratchetRefused.value + (contactId to refused)
    }

    /** Clears [groupId]'s unread dot immediately when its conversation opens
     *  (pollGroup also clears it shared-side; this removes the poll-cycle lag). */
    fun markGroupRead(groupId: String) {
        if (groupId in _groupUnreadCounts.value) {
            _groupUnreadCounts.value = _groupUnreadCounts.value - groupId
        }
        groupManager?.markGroupRead(groupId)
    }

    /**
     * NO-PARK: a screen just took a GROUP_ECHO item, i.e. a group text was shown in
     * a 1:1 (or another group). The shared count already gave that unit back
     * (GroupUnreadTally.shownElsewhere), but the published map only refreshed
     * on the control loop's next cycle (60–90 s idle), so the group row kept a dot
     * with nothing behind it. Republish now. Off-main: groupUnreadCounts can read
     * the vault.
     */
    fun refreshGroupUnreadCounts() {
        val gm = groupManager ?: return
        viewModelScope.launch(Dispatchers.IO) {
            val counts = try { gm.groupUnreadCounts() } catch (_: Exception) { return@launch }
            if (_groupUnreadCounts.value != counts) _groupUnreadCounts.value = counts
        }
    }

    /**
     * Clears [contactId]'s unread badge immediately. Called when its
     * conversation opens: the conversation poll drains the relay queue, so
     * the next /peek sweep would clear it regardless — this just makes the
     * badge vanish the instant the user taps in, not a poll cycle later.
     */
    fun markContactRead(contactId: String) {
        if (contactId in _unreadCounts.value) {
            _unreadCounts.value = _unreadCounts.value - contactId
        }
    }

    // -----------------------------------------------------------------------
    // Contact list + consent prompts (read by ContactListScreen)
    // -----------------------------------------------------------------------

    /**
     * The contact list for this session, loaded on IO by [startContactListLoader].
     * `null` = not loaded yet: the screen keeps the list hidden until it lands, so a
     * revealed list never flashes "no contacts yet" during the first load.
     *
     * A MutableStateFlow plus a session job, NOT `stateIn`: a `stateIn` flow keeps
     * its last value after its subscribers leave and cannot be reset, so the aliases
     * would outlive the session with no clear point. This one is nulled by
     * [clearInMemoryIdentifierMaps] on every lock and wipe.
     */
    private val _contactList = MutableStateFlow<ContactListSnapshot?>(null)
    val contactList: StateFlow<ContactListSnapshot?> = _contactList.asStateFlow()
    private val _contactListRefresh = MutableStateFlow(0)
    private var contactListJob: Job? by sessionJobs.slot()

    /** Re-reads the contact list (an in-place edit, delete, or re-entering the screen). */
    fun refreshContactList() {
        _contactListRefresh.update { it + 1 }
    }

    /**
     * Started by [onVaultOpened] once the session managers exist. Reloads on every
     * vault event (a control batch landed), relay-lost change, or explicit refresh;
     * `collectLatest` drops a stale in-flight load when a newer trigger arrives. The
     * session-epoch check keeps a load that straddles a lock from re-publishing the
     * old session's aliases after the teardown cleared them.
     */
    private fun startContactListLoader() {
        val epoch = TransportFailedSends.shared.sessionEpoch
        contactListJob?.cancel()
        contactListJob = viewModelScope.launch {
            combine(_vaultEvents, _relayLostContacts, _contactListRefresh) { _, _, _ -> }
                .conflate()
                .collectLatest {
                    val snap = withContext(Dispatchers.IO) {
                        val v = vault ?: return@withContext null
                        try {
                            loadContactListSnapshot(v, maximumShield)
                        } catch (e: CancellationException) {
                            throw e
                        } catch (e: Exception) {
                            LogBuffer.append("W", "ViewModel", "contact list load failed: ${e::class.simpleName}")
                            null
                        }
                    }
                    if (snap != null && sessionStillCurrent(epoch)) _contactList.value = snap
                }
        }
    }

    /**
     * The next referral offer and group invite waiting for consent. RAM reads only
     * (both managers hold them under a lock), so [refreshPendingConsent] is cheap
     * and callable from any thread. Refreshed right after every control-poll cycle,
     * at the end of the unread prime's control pre-drain (it parks invites without
     * bumping [vaultEvents]), at unlock (restored offers and invites), after every
     * accept/decline, and by the [CONSENT_TICK_MS] backstop [consentTickJob]. The
     * tick keeps the e2e bound: `dismissGroupInviteIfPresent` polls for up to 6 s.
     * Cleared on every lock and wipe, because an offer carries aliases.
     */
    private val _pendingConsent = MutableStateFlow(PendingConsent(null, null))
    val pendingConsent: StateFlow<PendingConsent> = _pendingConsent.asStateFlow()
    private var consentTickJob: Job? by sessionJobs.slot()

    fun refreshPendingConsent() {
        // Read the managers once: a teardown nulls them on Main while this may run
        // on IO, and a null manager simply reads as "nothing pending".
        val rm = referralManager
        val gm = groupManager
        var invites: List<GroupInvite>? = null
        try { invites = gm?.pendingInvites() } catch (_: Exception) { }
        if (invites != null) {
            // Only after a SUCCESSFUL read: a withdrawn / declined invite's "Later"
            // must not outlive it (a re-invite of the same group presents afresh).
            val pruned = GroupInvitePresentation.pruneDeferred(invites.map { it.groupId }, _deferredGroupInviteIds.value)
            if (pruned.size != _deferredGroupInviteIds.value.size) _deferredGroupInviteIds.value = pruned
        }
        var offers: List<ReferralOffer>? = null
        try { offers = rm?.pendingOffers() } catch (_: Exception) { }
        if (offers != null) {
            // Same rule as invites: a consumed / expired offer's "Later" must not outlive it.
            val prunedOffers = GroupInvitePresentation.pruneDeferred(offers.map { it.introId }, _deferredReferralOfferIds.value)
            if (prunedOffers.size != _deferredReferralOfferIds.value.size) _deferredReferralOfferIds.value = prunedOffers
        }
        _pendingConsent.value = PendingConsent(
            offer = offers?.firstOrNull(),
            offers = offers ?: emptyList(),
            invite = invites?.firstOrNull(),
            invites = invites ?: emptyList(),
        )
    }

    /**
     * Group invites the user closed with "Later" this session (RAM only; group ids,
     * no aliases). The consent surface does not auto-present them again — they show
     * as rows in the groups area instead ([GroupInvitePresentation]). Lives here, not
     * in the screen, because the contact list is a NavHost destination whose
     * composition (and `remember` state) dies on every conversation open. Cleared
     * on lock / wipe / teardown with the rest of the session state.
     */
    private val _deferredGroupInviteIds = MutableStateFlow<Set<String>>(emptySet())
    val deferredGroupInviteIds: StateFlow<Set<String>> = _deferredGroupInviteIds.asStateFlow()

    fun deferGroupInvite(groupId: String) {
        _deferredGroupInviteIds.value = _deferredGroupInviteIds.value + groupId
    }

    /**
     * Referral offers (introIds, base64url) the user closed with "Later" this
     * session — the same non-blocking rule as [deferredGroupInviteIds], RAM only,
     * cleared with it. Approve un-defers first so a failed accept re-presents as Retry.
     */
    private val _deferredReferralOfferIds = MutableStateFlow<Set<String>>(emptySet())
    val deferredReferralOfferIds: StateFlow<Set<String>> = _deferredReferralOfferIds.asStateFlow()

    fun deferReferralOffer(introId: String) {
        _deferredReferralOfferIds.value = _deferredReferralOfferIds.value + introId
    }

    fun undeferReferralOffer(introId: String) {
        _deferredReferralOfferIds.value = _deferredReferralOfferIds.value - introId
    }

    private fun startConsentTick() {
        val epoch = TransportFailedSends.shared.sessionEpoch
        consentTickJob?.cancel()
        consentTickJob = viewModelScope.launch {
            while (isActive && sessionStillCurrent(epoch)) {
                refreshPendingConsent()
                delay(CONSENT_TICK_MS)
            }
        }
    }

    /**
     * Declines a referral offer OFF the main thread: [ReferralManager.declineOffer]
     * drops vault records. [onDone] fires on Main after the drop landed and
     * [pendingConsent] was refreshed, so the consent dialog cannot re-present the
     * offer in between.
     */
    fun declineReferralOfferInBackground(introId: String, onDone: () -> Unit) {
        val rm = referralManager
        viewModelScope.launch(Dispatchers.IO) {
            try { rm?.declineOffer(introId) } catch (e: Exception) {
                LogBuffer.append("W", "Referral", "declineOffer failed: ${e::class.simpleName}")
            }
            refreshPendingConsent()
            withContext(Dispatchers.Main) { onDone() }
        }
    }

    /** Saves (or, with "", removes) a contact's private memory OFF the main thread. */
    fun saveContactMnemonicInBackground(contactId: String, mnemonic: String, onDone: () -> Unit) {
        val v = vault
        viewModelScope.launch(Dispatchers.IO) {
            try { saveContactMnemonic(v, contactId, mnemonic) } catch (e: Exception) {
                LogBuffer.append("W", "Contact", "saveMnemonic failed: ${e::class.simpleName}")
            }
            withContext(Dispatchers.Main) { onDone() }
        }
    }

    /**
     * Rolls a fresh alias for [contact] OFF the main thread. [onDone] gets the
     * updated secret-free projection on Main (the original on a write failure).
     */
    fun rollContactAliasInBackground(contact: ContactListItem, onDone: (ContactListItem) -> Unit) {
        val v = vault
        viewModelScope.launch(Dispatchers.IO) {
            val updated = try { rollContactAlias(v, contact) } catch (e: Exception) {
                LogBuffer.append("W", "Contact", "rollAlias failed: ${e::class.simpleName}")
                contact
            }
            withContext(Dispatchers.Main) { onDone(updated) }
        }
    }

    // -----------------------------------------------------------------------
    // Background operations (send / group / referral / contact)
    // -----------------------------------------------------------------------

    /**
     * Leaves [groupId] with the local delete surfacing IMMEDIATELY:
     * [onLocalDelete] runs on Main as soon as the group is gone from the
     * vault, while the best-effort leave notices fan out afterwards on
     * viewModelScope — NOT a screen scope, so navigating away the moment
     * the row disappears can't cancel the in-flight notices.
     */
    fun leaveGroupInBackground(groupId: String, onLocalDelete: () -> Unit) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val gm = groupManager
                if (gm == null) {
                    withContext(Dispatchers.Main) { onLocalDelete() }
                    return@launch
                }
                gm.leaveGroup(groupId) {
                    viewModelScope.launch(Dispatchers.Main) { onLocalDelete() }
                }
            } catch (e: Exception) {
                LogBuffer.append("W", "ViewModel", "leaveGroup failed: ${e::class.simpleName}")
                withContext(Dispatchers.Main) { onLocalDelete() }
            }
        }
    }

    /**
     * Admin handoff + leave: transfers the admin role to [newAdminMemberId]
     * FIRST (must persist while we're still admin and the group still exists),
     * then leaves. Same background/Main contract as [leaveGroupInBackground].
     *
     * [GroupManager.transferAdmin] returns `false`
     * (no throw) when the chosen successor row is already gone — e.g. it left
     * between the sheet opening and the tap. Leaving anyway would strand every
     * remaining member pointed at a dead `adminMemberId` forever (`handleRoster`
     * drops every future roster once the admin contact can't be resolved) — a
     * PERMANENT membership freeze. So the leave is now gated on the transfer's
     * boolean result: on `false` (or a thrown exception) we do NOT leave, we
     * stay admin locally, and [onTransferFailed] runs on Main so the UI can
     * surface a retry. Mirrors the iOS gate at
     * `GroupViews.swift:1194-1207` (`chooseAdminAndLeave`'s `guard transferred`).
     */
    fun transferAdminThenLeaveInBackground(
        groupId: String,
        newAdminMemberId: String,
        onLocalDelete: () -> Unit,
        onTransferFailed: () -> Unit,
    ) {
        viewModelScope.launch(Dispatchers.IO) {
            val gm = groupManager
            if (gm == null) {
                withContext(Dispatchers.Main) { onLocalDelete() }
                return@launch
            }
            val transferred = try {
                gm.transferAdmin(groupId, newAdminMemberId)
            } catch (e: Exception) {
                LogBuffer.append("W", "ViewModel", "transferAdmin (pre-leave) failed: ${e::class.simpleName}")
                false
            }
            if (!transferred) {
                LogBuffer.append("W", "ViewModel", "transferAdmin (pre-leave) returned false; NOT leaving")
                withContext(Dispatchers.Main) { onTransferFailed() }
                return@launch
            }
            try {
                gm.leaveGroup(groupId) {
                    viewModelScope.launch(Dispatchers.Main) { onLocalDelete() }
                }
            } catch (e: Exception) {
                LogBuffer.append("W", "ViewModel", "leaveGroup (post-transfer) failed: ${e::class.simpleName}")
                withContext(Dispatchers.Main) { onLocalDelete() }
            }
        }
    }

    /**
     * Sends [text] to [contactId] on viewModelScope so an in-flight POST SURVIVES
     * the user leaving the conversation. The old send launched on the screen's
     * rememberCoroutineScope, so backing out the moment after tapping send cancelled
     * the POST mid-flight — under a slow/contended Tor circuit the message was
     * silently LOST (never reached the relay, so the peer never received it; the
     * runestone was still lit, so nothing looked wrong). Idempotent transient-retry
     * (the monotonic counter is sealed on the first attempt, so re-POSTing the same
     * bytes is safe). [onDelivered] fires on Main when the relay accepts — best-effort
     * UI ✓; a no-op if the conversation has since closed.
     */
    fun sendMessageInBackground(contactId: String, text: String, redriveToken: String? = null, onDelivered: () -> Unit) {
        // The session this send belongs to, captured at ENQUEUE time — see
        // [sessionStillCurrent] and [TransportFailedSends]'s session-epoch kdoc.
        val sendEpoch = TransportFailedSends.shared.sessionEpoch
        // LAZY so the job is in [inFlightSendJobs] before it can run (and finish):
        // an eager launch could complete before the add and leave a stale entry.
        val job = viewModelScope.launch(Dispatchers.IO, start = CoroutineStart.LAZY) {
            var sent = false
            // resilience:tor-death: a TRANSPORT-class failure is PARKED in
            // the RAM-only TransportFailedSends ledger under the bubble's id and
            // re-driven by [armTransportRedrive] when the transport comes back — the
            // same sendMessage path a manual Retry takes. The token is per MESSAGE
            // (both the send and the Retry long-press pass the bubble id), so three
            // failed attempts and any number of manual retries are ONE entry.
            val token = redriveToken ?: java.util.UUID.randomUUID().toString()
            val onRedriven: () -> Unit = {
                viewModelScope.launch(Dispatchers.Main) { onDelivered() }
            }
            var parked = false
            // A durable ratchet-role-collision refusal short-circuits
            // the retry loop entirely — zero HTTP, matching MessageManager's own
            // no-throw refusal contract. Counts only, never an identifier.
            val refused = try { messageManager?.ratchetRefused(contactId) ?: false } catch (_: Exception) { false }
            if (!refused) {
                for (attempt in 1..3) {
                    val mm = messageManager
                    if (mm == null) {
                        // No transport at all (Tor died between the tap and this
                        // attempt): known down by definition — park it, burn nothing.
                        TransportFailedSends.shared.record(token, contactId, text, false, onRedriven, sendEpoch)
                        parked = true
                        break
                    }
                    val outcome = try {
                        mm.sendMessageWithOutcome(contactId, text, noPush = false, redriveToken = token, onRedriven = onRedriven)
                    } catch (_: Exception) { SendOutcome.FAILED }
                    if (outcome == SendOutcome.SENT) { sent = true; break }
                    LogBuffer.append("W", "Chat", "send attempt $attempt/3 failed")
                    // Known-down transport: the outer loop must not spend its 1-5 s
                    // backoffs on it either; the re-drive owns recovery from here. A
                    // transport that is merely believed up keeps today's three attempts.
                    if (outcome == SendOutcome.TRANSPORT_FAILED && mm.isTransportLost()) { parked = true; break }
                    if (attempt < 3) {
                        delay(1000L + com.vg.run.secureRandomInt(4000).toLong())
                    }
                }
            } else {
                LogBuffer.append("W", "Chat", "send refused — secure channel not established, 0 attempts made")
            }
            if (sent) {
                LogBuffer.append("D", "Chat", "sent message delivered")
                withContext(Dispatchers.Main) { onDelivered() }
            } else if (parked) {
                LogBuffer.append("W", "Chat", "message parked — transport down, re-driven when it is back")
            } else {
                LogBuffer.append("E", "Chat", "message failed after 3 attempts")
            }
            // A send that outlived its session (lock / wipe while the POST was
            // blocked) must not write this contact's id back into the per-contact
            // maps the teardown just emptied.
            if (sessionStillCurrent(sendEpoch)) {
                // Re-check the forward-secrecy-stalled signal once the whole
                // retry sequence has concluded — success or exhausted — never per
                // attempt. Already on IO here, so this costs one more vault read.
                refreshForwardSecrecyStalled(contactId)
                // Re-check the refusal signal too — cleared by an inbound
                // ratchet blob, independent of anything this send did.
                refreshRatchetRefused(contactId)
            }
        }
        inFlightSendJobs.add(job)
        job.invokeOnCompletion { inFlightSendJobs.remove(job) }
        job.start()
    }

    /**
     * Every [sendMessageInBackground] job not yet finished, so [lockSession] and
     * [performEmergencyWipe] can cancel them ([cancelInFlightSends]).
     *
     * WHY cancelling is not enough on its own: the POST inside
     * `MessageManager.sendMessageWithOutcome` is a BLOCKING call, so a cancel only
     * lands at the job's next suspension point (the retry backoff, the hop to
     * Main) — the attempt already on the wire runs to its end and can still try to
     * park its plaintext. What actually keeps a late completion out of the ledger
     * is the session epoch passed to `TransportFailedSends.record`; the cancel just
     * stops the remaining retries from starting.
     */
    private val inFlightSendJobs: MutableSet<Job> =
        Collections.newSetFromMap(ConcurrentHashMap<Job, Boolean>())

    private fun cancelInFlightSends() {
        for (job in inFlightSendJobs.toList()) job.cancel()
    }

    /**
     * True while the session that captured [epoch] is still the open one: the
     * vault is open and no lock / wipe / new unlock has bumped the epoch since.
     * Async work that writes contact or group ids into this ViewModel's state
     * checks this right before the write, so a completion that lands after a
     * teardown is dropped instead of re-populating what the teardown cleared.
     * Not atomic with the teardown (writers run on IO, the teardown on Main); the
     * window left is the few instructions between the check and the write.
     */
    private fun sessionStillCurrent(epoch: Long): Boolean =
        vault != null && TransportFailedSends.shared.sessionEpoch == epoch

    /**
     * The user DELETED a failed bubble: a parked copy must not be re-driven behind
     * their back. RAM-only ledger, no transport needed. No-op if nothing is parked.
     */
    fun cancelParkedSend(redriveToken: String) {
        TransportFailedSends.shared.remove(redriveToken)
    }

    private var transportRedriveJob: Job? by sessionJobs.slot()

    /**
     * ONE transport-back re-drive per transport transition: armed beside every NEW
     * MessageManager (the Tor `Connected` branch of [startTorMonitor] and the
     * debug/direct path — i.e. the exact edge GroupManager logs as "transport back
     * — draining resumed" and the conversation screen as "transport back —
     * conversation draining again"), so it fires whether or not a conversation is
     * open. Waits for THIS transport's first relay answer so the re-sends ride a
     * warm budget instead of the cold rendezvous; a transition whose relay never
     * answers re-drives nothing (the entries wait, bounded by the 15-minute window,
     * for the next transition). Runs on IO; the count-only log line is
     * MessageManager's. Re-arming cancels a previous transition's pending wait.
     */
    private fun armTransportRedrive() {
        transportRedriveJob?.cancel()
        transportRedriveJob = viewModelScope.launch {
            isRelayReachable.first { it }
            val mm = messageManager ?: return@launch
            withContext(Dispatchers.IO) {
                try { mm.redriveTransportFailures() } catch (e: Exception) {
                    LogBuffer.append("W", "Chat", "transport-back re-drive failed: ${e::class.simpleName}")
                }
            }
        }
    }

    /**
     * Group send on viewModelScope so the fan-out POST survives the user leaving the
     * group conversation — the SAME silent-loss bug as [sendMessageInBackground] (a
     * screen-scoped send was cancelled mid-POST on a quick back-out). [onResult] fires
     * on Main with the delivered/total counts (GroupSendResult(0,0) if unavailable).
     */
    fun sendGroupMessageInBackground(groupId: String, text: String, onResult: (GroupSendResult) -> Unit) {
        viewModelScope.launch(Dispatchers.IO) {
            val result = try {
                groupManager?.sendGroupMessage(groupId, text)
            } catch (_: Exception) { null }
            withContext(Dispatchers.Main) {
                onResult(result ?: GroupSendResult(0, 0))
            }
        }
    }

    /**
     * Runs a blocking group MEMBERSHIP op (create / add /
     * remove / transfer-admin) on viewModelScope so it SURVIVES the user backing out
     * of the screen mid-op — the SAME silent-loss class as [sendMessageInBackground].
     * A screen-scoped (rememberCoroutineScope) launch was cancelled on dispose, leaving
     * a group that persisted locally but whose invites/roster were never fanned out.
     * [op] runs on IO; [onDone] fires on Main with its result (null on failure/throw),
     * best-effort — a no-op if the screen has since closed.
     */
    fun <T> runGroupOpInBackground(op: () -> T, onDone: (T?) -> Unit) {
        viewModelScope.launch(Dispatchers.IO) {
            val result = try { op() } catch (e: Exception) {
                LogBuffer.append("W", "Group", "group membership op failed: ${e::class.simpleName}")
                null
            }
            // A membership op may have consumed a parked invite (accept/decline):
            // refresh the consent state before the screen re-evaluates it.
            refreshPendingConsent()
            withContext(Dispatchers.Main) { onDone(result) }
        }
    }

    /**
     * Fan out referral introductions on viewModelScope, OFF the
     * main thread. startReferral does 2 blocking Tor sends per contact; the dialog's
     * onClick ran them synchronously on the UI thread → ANR on a slow circuit for N
     * contacts. Runs on IO and survives the dialog/screen going away mid-fan-out.
     *
     * [onDone] reports whether EVERY contact's [ReferralManager.startReferral]
     * returned non-null. A null result means no transport (no `messageManager`,
     * i.e. Tor/relay not actually ready despite the UI gate having let the user
     * this far — a race, not the common case) or an invalid pairing (self-introduce,
     * a contact vanishing mid-fan-out) — never a delivery failure: an offer that
     * fails to SEND is still a durable, redriven obligation core-side (see
     * ReferralManager's offer-redrive kdoc), so only the "nothing was even
     * attempted" case is worth surfacing here. Defaults to a no-op so this stays
     * source-compatible with any other caller.
     */
    fun startReferralsInBackground(
        fromContactId: String,
        toContactIds: List<String>,
        onDone: (allStarted: Boolean) -> Unit = {},
    ) {
        viewModelScope.launch(Dispatchers.IO) {
            var allStarted = true
            for (toId in toContactIds) {
                val introId = try {
                    referralManager?.startReferral(fromContactId, toId)
                } catch (e: Exception) {
                    LogBuffer.append("W", "Referral", "startReferral failed: ${e::class.simpleName}")
                    null
                }
                if (introId == null) allStarted = false
            }
            withContext(Dispatchers.Main) { onDone(allStarted) }
        }
    }

    /**
     * Delete a contact off the main thread — deleteContact is a
     * multi-row SQLCipher cascade (contact + inbox rows + ratchet meta + group-member
     * unresolve). [onDone] fires on Main so the list refreshes.
     */
    fun deleteContactInBackground(contactId: String, onDone: () -> Unit) {
        viewModelScope.launch(Dispatchers.IO) {
            // The local delete FIRST (it is the gate), then a best-effort relay
            // DELETE of the two inbound inboxes using caps snapshotted before the
            // rows go — otherwise a deleted contact leaves live, drainable inboxes on
            // the relay. Never gated on Tor: the local delete always happens, and
            // onLocalDeleted fires the list refresh the instant it lands so the row
            // disappears immediately rather than waiting on the relay round-trips
            // (parity with iOS, which drops the row at the tap).
            var refreshed = false
            fun refreshOnce() {
                if (refreshed) return
                refreshed = true
                viewModelScope.launch(Dispatchers.Main) { onDone() }
            }
            try {
                vault?.let {
                    deleteContactAndPurgeRelay(it, messageManager, contactId) { refreshOnce() }
                }
            } catch (e: Exception) {
                LogBuffer.append("W", "Contact", "deleteContact failed: ${e::class.simpleName}")
            }
            refreshOnce()
        }
    }

    /**
     * "Reset relay access": rotates the READ capability on both of this
     * contact's inbound inboxes, so a copy of the vault taken while the phone was
     * unlocked stops granting remote drain / delete / rotate / push-register rights.
     * Non-destructive — messages, history and the contact are untouched and the peer
     * does nothing. Runs on IO (two relay round-trips per inbox); [onResult] fires
     * on Main. A false result is "not proven done", never data loss: the durable
     * marker survives and the control-poll reconcile finishes it.
     */
    fun resetRelayAccessInBackground(contactId: String, onResult: (Boolean) -> Unit) {
        viewModelScope.launch(Dispatchers.IO) {
            val ok = try {
                messageManager?.resetRelayAccess(contactId) ?: false
            } catch (e: Exception) {
                LogBuffer.append("W", "Contact", "resetRelayAccess failed: ${e::class.simpleName}")
                false
            }
            withContext(Dispatchers.Main) { onResult(ok) }
        }
    }

    /**
     * Anonymous "Report bug" — sends [text] once over the SAME live relay
     * transport [messageManager] is currently using (Tor SOCKS in release,
     * direct HTTP only in debug/emulator — see [MessageManager.relayTransport]).
     * No vault access, no capability, no auth; nothing about the report is
     * persisted on this device. [onResult] fires on Main; false covers "no
     * relay connected yet" (Tor still bootstrapping) exactly like any other
     * transport failure — the caller shows one generic error copy either way.
     */
    fun sendBugReportInBackground(text: String, onResult: (Boolean) -> Unit) {
        val mm = messageManager
        viewModelScope.launch(Dispatchers.IO) {
            val ok = try {
                if (mm == null) false
                else BugReportSender.send(mm.relayTransport(), RelayConfig.BASE_URL, text, BuildConfig.VERSION_NAME, "android")
            } catch (e: Exception) {
                LogBuffer.append("W", "BugReport", "send failed: ${e::class.simpleName}")
                false
            }
            withContext(Dispatchers.Main) { onResult(ok) }
        }
    }

    /**
     * Accept a referral offer on viewModelScope so the accept
     * SURVIVES the user leaving the contact list mid-flight. The old screen-scoped launch
     * was cancelled on dispose — and a cancel between registerAccepted and the final
     * send dead-ended the referral silently (offer already removed from the poller).
     * [onResult] fires on Main with the delivered flag (false on failure/throw).
     */
    fun acceptReferralOfferInBackground(introId: String, onResult: (Boolean) -> Unit) {
        viewModelScope.launch(Dispatchers.IO) {
            val ok = try { referralManager?.acceptOffer(introId) ?: false } catch (e: Exception) {
                LogBuffer.append("W", "Referral", "acceptOffer failed: ${e::class.simpleName}"); false
            }
            refreshPendingConsent()
            withContext(Dispatchers.Main) { onResult(ok) }
        }
    }

    // -----------------------------------------------------------------------
    // Vault unlock
    // -----------------------------------------------------------------------

    fun onVaultOpened(openedVault: VaultDatabase) {
        // A new session epoch on EVERY vault open — this is the single callback
        // every unlock path reaches (PIN, re-auth re-unlock, first-run provision,
        // recovery code; see NotificationHelper.cancelAll below), and it runs
        // before any MessageManager of this session exists. Work captured under
        // the previous epoch can no longer park plaintext or publish ids into
        // this session (see [sessionStillCurrent]).
        TransportFailedSends.shared.beginSession()
        vault = openedVault
        // An unlock is an interaction (a Lever-B BiometricPrompt does not dispatch
        // Activity.onUserInteraction), so the idle clock starts fresh with the
        // session and a stale pre-unlock stamp can never fire Lever C at once.
        noteUserInteraction()
        applySessionPolicy()
        recordUnlockBookkeeping(openedVault)
        // Build + cross-wire both session managers in one shared place so the
        // referral-control bridge can't be forgotten on one platform.
        val managers = createSessionManagers(
            openedVault,
            // Eager group-inbox establishment, OFF the critical path: a membership
            // event converges the pair's group inbox ahead of the first group text
            // (so its dot is the durable, peek-derivable presence bump). Cancelled
            // with the session (viewModelScope dies in onCleared); blocking PoW +
            // network, so Dispatchers.IO. Fail-soft — a drop just leaves the lazy
            // control-sweep backfill.
            groupBackfillLauncher = { work -> viewModelScope.launch(Dispatchers.IO) { work() } },
            // The shield's "am I at MAXIMUM" read — authenticated-only (VaultSelector.maximumShieldLevel).
            maximumLevelProbe = { vaultSelector.maximumShieldLevel() },
        ) { messageManager }
        groupManager = managers.groupManager
        referralManager = managers.referralManager
        maximumShield = managers.maximumShield
        // Assigned PROMPTLY, right after construction — the setter flushes a
        // latched rehydrate-time finalize (a peer's accept that landed while we
        // were dead), so a late assignment here would silently miss it. Bumping
        // the SAME signal the control-poll's contact-refresh path already uses
        // (see the `_vaultEvents.value += 1` a few hundred lines below) means the
        // contact list picks up a newly-committed referred contact without a
        // dedicated observer. Best-effort/never-throwing by construction — see
        // ReferralManager.onIntroFinalized's kdoc.
        referralManager?.onIntroFinalized = { _vaultEvents.value += 1 }
        // Introducer side of the same handshake: surfaces a "your intro was
        // relayed" info modal (ContactListScreen) as a FIFO queue — see
        // [referralRelayEvents]. Mirrors onIntroFinalized's wiring exactly
        // (assigned promptly right after construction, same rehydrate-safety
        // rationale in ReferralManager's kdoc).
        referralManager?.onIntroRelayed = { event -> appendReferralRelayEvent(event) }
        // The contact list and the consent prompts now that the managers exist: a
        // first load, the restored offers/invites, and the 4 s consent backstop.
        startContactListLoader()
        refreshPendingConsent()
        startConsentTick()
        // Background notifications (the WorkManager background poll has been
        // removed entirely, matching iOS, which never had an on-device poll):
        // (re)register whichever push transport the user opted into. This is now
        // the ONLY registration path — the device-key (inboxId,
        // readCap) manifest that let a locked-device token rotation register
        // without a vault is gone, so an FCM token (or a UnifiedPush endpoint) that
        // rotated while the app was closed is picked up HERE (and on the
        // control-poll cycle) and nowhere else. Registration is unconditional
        // per session: both transports' registered-id sets and cached addresses
        // are session-scoped RAM, so every unlock re-registers with whatever
        // address the transport currently holds.
        // A no-op while the feature is off (the default) — see
        // [PushRegistrationCoordinator.refreshPushRegistration], which dispatches on the persisted level.
        // `!moveQuiesced`: a frozen (old-phone-of-a-move) session must not
        // re-register the push rows the export just deleted — the relay would go
        // back to waking a phone whose identity now lives elsewhere.
        if (isBackgroundNotificationsEnabled() && !moveQuiesced) {
            viewModelScope.launch(Dispatchers.IO) {
                push.refreshPushRegistration()
            }
        }
        // Log a boolean, NOT the .onion prefix — the address is
        // deliberately kept out of git, and even a prefix in the (DEBUG) log
        // buffer is copyable into a bug report.
        LogBuffer.append("D", "ViewModel", "vault opened, relayConfigured=${RelayConfig.BASE_URL.isNotEmpty()}, torRequired=${RelayConfig.isTorRequired}, extProxy=$externalProxyMode")
        connectRelayForSession(openedVault)
    }

    /**
     * The per-session policy decisions of an unlock, re-read on EVERY vault open:
     * the move freeze, Debug mode's persisted consent, the periodic re-auth
     * deadline, the composer keyboard tier and the keep-alive tier. Main thread.
     */
    private fun applySessionPolicy() {
        // "Move to new device" (docs/device-move.md D2): if this vault carries
        // `mig_frozen`, this device is the OLD phone of a move and must come up
        // QUIESCED — transport only, no polls, no push registration — however it
        // was unlocked. MainActivity routes the same condition to the frozen
        // screen, but the session decision is made here so it holds even if a
        // future caller reaches an unlock without that routing.
        // refreshFrozenState() is what moves a manager built BEFORE this unlock
        // (in-process re-auth lock/unlock) from Idle to FrozenNoCode; on the
        // ordinary path the lazy construction on the line above has just done it.
        moveManagerImpl.refreshFrozenState()
        val frozenForMove = moveManagerImpl.isFrozen()
        // Assigned, not conditionally set: an in-process re-auth lock keeps this
        // ViewModel alive, so an unlock of a vault that is NO LONGER frozen (the
        // user cancelled the move) must clear the flag rather than inherit it.
        moveQuiesced = frozenForMove
        if (frozenForMove) {
            LogBuffer.append("W", "Move", "vault is frozen for a device move — session stays quiesced")
        }
        // Periodic random re-auth at MAXIMUM (docs/periodic-reauth-design.md):
        // draw a fresh deadline on EVERY vault open — a re-auth's own
        // re-unlock is itself an unlock, so "after every successful auth" and
        // "on every unlock" coincide. Tier gate is re-read here (not cached),
        // so a mid-session tier change takes effect on the next unlock.
        // Debug mode: re-read the persisted consent now that the vault is open
        // (parity with iOS AppState.startRelayCheck, a prod bug — the
        // iOS launch-time Keychain read can fail on a cold start). Android's
        // store is plain app storage with no unlock dependency, so this is
        // expected to be a no-op here; kept so the two platforms share the
        // same recovery point. Only ever flips OFF → ON.
        if (!_debugMode.value && DebugMode.reapplyPersisted(debugModeStore, cryptoProvider)) _debugMode.value = true
        reauthDeadlineElapsedMs =
            if (ReauthPolicy.isEnabled(vaultSelector.protectionLevelForEnforcement())) {
                SystemClock.elapsedRealtime() + ReauthPolicy.nextIntervalMs()
            } else {
                null
            }
        // Keyboard privacy scales with the tier (option 3): re-read on every
        // unlock alongside the re-auth gate above, same rationale — a mid-session
        // tier change (Protection screen) only takes effect through a re-unlock.
        strictComposerKeyboard =
            ComposerKeyboardPolicy.isStrict(vaultSelector.protectionLevelForEnforcement())
        // Bounded Tor keep-alive: the tier decision from this AUTHENTICATED read,
        // the fallback when the live read at backgrounding races the keyguard
        // (see armTorKeepAliveOnBackground / TorKeepAlive.shouldKeepAlive).
        sessionTierAllowsKeepAlive =
            TorKeepAlive.tierAllowsKeepAlive(vaultSelector.protectionLevelForEnforcement())
    }

    /**
     * The bookkeeping of a real unlock: notification hygiene, the push prompt and
     * telemetry arms, the review-prompt unlock count (vault I/O, off Main), the
     * inactivity stamp and the PIN-attempt counters. Main thread.
     */
    private fun recordUnlockBookkeeping(openedVault: VaultDatabase) {
        // Launcher-badge hygiene: once the vault is open, the in-app unread
        // dots take over as the "something is waiting" signal — the system
        // notification (and the boolean launcher badge it drives, see
        // NotificationHelper) must not linger for a user who unlocked by
        // tapping the launcher icon rather than the notification itself.
        // Idempotent + cheap when nothing was posted. This is the single
        // vault-open callback (PIN unlock, first-run provision auto-open,
        // recovery-code unlock all route through here — see the callers of
        // this function), so one call covers every unlock path.
        NotificationHelper.cancelAll(getApplication())
        // No longer evaluated here. The prompt is
        // raised on the FIRST relay answer of this session instead — the
        // moment the contact list is revealed and the switch it leads to can
        // actually register (a toggle-ON without a live transport reverts with
        // "check your connection"). See armPushPromptForFirstRelayContact.
        armPushPromptForFirstRelayContact()
        // Anonymous connect-time report (ConnectTelemetry.kt) — armed on the same
        // signal, sent once per process after the first relay answer (it survives
        // lockForReauth by design: same ViewModel, same user wait, no second
        // report). Plus the reveal mark and the Debug-mode first flush.
        telemetry.armOnUnlock()
        // In-app store-review nudge (ReviewPromptPolicy.kt, commonMain):
        // record this unlock in the vault's `_meta` singleton
        // (REVIEW_PROMPT_META_KEY) on EVERY unlock, unconditionally — the
        // actual ask-or-not decision is made once per session in
        // [startRelayCheck], alongside the update nudge. This used to write plaintext SecurePrefs, which
        // an AFU extraction could read without the vault credential. An
        // existing pre-fix install's legacy counters are folded in here
        // exactly once (SecurePrefs.readLegacyReviewCounters), and the legacy
        // keys are deleted ONLY after the vault write is confirmed to have
        // landed (recordReviewPromptUnlock's Boolean return) — never delete
        // unread-back state. Vault I/O, so this hops off Main; onVaultOpened
        // itself runs on Main (see its callers in
        // PinEntryScreen/PinSetupScreen/RecoveryEntryScreen).
        viewModelScope.launch(Dispatchers.IO) {
            val context = getApplication<Application>()
            val legacy = SecurePrefs.readLegacyReviewCounters(context)
            val legacyFallback = if (legacy.firstUnlockAt != null || legacy.unlockCount != 0 || legacy.alreadyPrompted) {
                ReviewPromptVaultState(legacy.firstUnlockAt, legacy.unlockCount, legacy.alreadyPrompted)
            } else {
                null
            }
            val wrote = recordReviewPromptUnlock(openedVault, System.currentTimeMillis(), legacyFallback)
            if (wrote) SecurePrefs.clearLegacyReviewCounters(context)
        }
        // Refresh the inactivity dead-man's-switch on a REAL
        // unlock only — never on a bare launch, so a seized-but-not-vault-unlocked
        // phone can't keep the vault alive by tapping the icon. This is the single
        // vault-open callback (PIN unlock, first-run provision auto-open, recovery),
        // mirroring iOS InactivityWipe.touch() on the .opened branch. Reuses the warm
        // cryptoProvider (unlock just used it) → one in-RAM AEAD encrypt.
        InactivityWipe.recordUnlock(getApplication(), cryptoProvider)
        // Establish the wrong-PIN and change-PIN counters now that the
        // vault is confirmed provisioned+open. This is an OPTIMISATION only — the
        // pre-unlock read establishes-on-read anyway (marker absent + configured →
        // write 0 + arm, never wipe), so an interrupted provision that never reaches
        // here self-heals on the next launch. Both are idempotent no-ops once established.
        pinAttempts.establishVerified()
        changePinAttempts.establish()
    }

    /**
     * Wires this session's relay transport: external SOCKS proxy mode first
     * (fail closed, never the embedded Tor or direct), then the embedded Tor,
     * else the debug-only direct client (refused in release). Main thread.
     */
    private fun connectRelayForSession(openedVault: VaultDatabase) {
        if (externalProxyMode) {
            // External SOCKS proxy mode — checked FIRST, before the onion/clearnet
            // split, so neither the embedded Tor nor the debug direct client can
            // ever be reached while it is on. A clearnet dev relay in this mode
            // fails closed (connectViaExternalProxy refuses it, never direct).
            _torBootstrapStalled.value = false
            connectViaExternalProxy(openedVault)
            startRelayStallWatch()
        } else if (RelayConfig.isTorRequired) {
            // New session (first unlock, or a re-unlock after a Lever-C auto-lock):
            // the connect wait starts over, so no stale hint may carry into it.
            _torBootstrapStalled.value = false
            connectViaTor(openedVault)
            startRelayStallWatch()   // self-heal + manual-reconnect escalation
        } else {
            // Clearnet relay = NO Tor: messages stay E2E-encrypted but IP and
            // metadata are exposed. This is intended ONLY for the emulator/dev
            // override. A non-.onion relay in a RELEASE build means a
            // misconfigured relay.properties shipped — refuse to route traffic
            // without Tor (fail-CLOSED) rather than silently exposing the user.
            // A correctly configured release uses an
            // .onion relay (isTorRequired==true) and never reaches this branch.
            if (!BuildConfig.DEBUG) {
                LogBuffer.append("E", "ViewModel", "clearnet relay refused in release build — Tor unavailable, messaging disabled")
                return
            }
            LogBuffer.append("D", "ViewModel", "using direct HTTP (no Tor) — dev/emulator")
            // Same anchor the Tor branch sets inside connectViaTor — the connect
            // wait starts here on the direct/emulator path.
            telemetry.markConnectStart()
            // The same wiring the Tor and external-proxy paths use: manager,
            // relay check, debug-log upload, control poll, re-drive, unread prime.
            wireRelayTransport(openedVault, PlatformHttpClient.direct())
        }
    }

    // -----------------------------------------------------------------------
    // Tor lifecycle (speculative start, adoption, keep-alive, watchdogs)
    // -----------------------------------------------------------------------

    /**
     * Starts Tor BEFORE the vault is open, so its ~10-40 s bootstrap overlaps the
     * user's credential entry instead of starting after it. Called exactly once,
     * from [init].
     *
     * Deliberately minimal: it constructs and starts a [TorManager] and NOTHING
     * else.
     *  - No MessageManager, no relay reachability check, no control poll, no
     *    unread prime, no push registration — every one of those needs an OPEN
     *    vault, and none of them may exist before there is one.
     *  - No [armTorBootstrapWatchdog] and no [startRelayStallWatch] either. Their
     *    hint ("this network may be blocking it") is meaningless on the PIN
     *    screen, which never renders it, and the stall watch's self-heal
     *    ([restartTor]) needs the vault and would no-op. Pre-unlock the ONLY
     *    governors are TorManager's own 90 s bootstrap timeout and its one-shot
     *    corrupt-state retry — the right amount of autonomy for a window with no
     *    user-visible surface. The watchdogs arm at unlock, re-anchored onto the
     *    bootstrap they inherit (see [reanchoredDelayMs]).
     *  - No [_torState] publication either: nothing rendered pre-unlock reads it
     *    (torState's consumers are ContactList / AddContact / Conversation /
     *    GroupConversation, all post-unlock), and the adoption's monitor is
     *    replayed the current value the instant it attaches.
     *
     * Gated on [RelayConfig.isTorRequired] — a `Build.*`/`BuildConfig`-only
     * predicate that needs no vault — so a clearnet dev/emulator relay starts
     * nothing here, exactly as [onVaultOpened]'s else-branch starts nothing.
     *
     * Writes the SAME [torManager] and [torStartJob] fields the unlock path uses.
     * That is the entire safety argument for the new pre-unlock window: see
     * [init] for the teardown paths it inherits unchanged.
     */
    private fun startSpeculativeTor() {
        // Belt. The primary stop is
        // MainActivity.onResume, which now returns before this ViewModel can
        // even be looked up while [ProcessWipeCover] is armed. This is the
        // second line of defense for any OTHER construction path that reaches
        // RunViewModel.init in the same process (a new ViewModelProvider owner,
        // a future service/receiver, …) — ProcessWipeCover is one-way and false
        // in every honest process, so this can never false-positive a normal
        // launch. Do NOT gate this on ProcessWipeLatch instead: that flag is
        // armed by every launch-time wipe too (InactivityWipe, the
        // orphaned-credential self-heal, the debug test-wipe hook), all of
        // which are designed to fall through to setup and DO need Tor to start
        // normally in this same process.
        if (ProcessWipeCover.armed) return
        // External SOCKS proxy mode: the embedded Tor is never started — not
        // speculatively, not adopted from a keep-alive. A Tor a previous
        // (non-external) session kept warm is STOPPED here rather than left to
        // its 2-min timer: external proxy mode means it must never run in this session.
        if (externalProxyMode) {
            speculativeTorStarted = true
            retireKeptTorForExternalProxyMode()
            return
        }
        if (!RelayConfig.isTorRequired) return
        // Two guards, one per direction: the latch stops a second speculative
        // start, and the null check stops this from ever running once an unlock
        // has already taken ownership of the field.
        if (speculativeTorStarted || torManager != null) return
        speculativeTorStarted = true
        // Bounded keep-alive: a Tor kept warm from the previous session is
        // adopted INSTEAD of starting a new child (writes the same torManager
        // field, so every teardown below covers it unchanged).
        if (adoptWarmTorFromPreviousSession()) return
        LogBuffer.append("D", "ViewModel", "starting Tor speculatively (pre-unlock) — bootstrap overlaps credential entry")
        // boot anchor (ConnectTelemetry.kt): this is this session's Tor PROCESS
        // start. Set-once — see ConnectTelemetryRecorder.markTorProcessStart.
        telemetry.markTorProcessStart()
        val tor = newTorManager()
        torManager = tor
        torStartJob = viewModelScope.launch(Dispatchers.IO) {
            val port = tor.start()
            if (port <= 0) {
                // Not an error the user can act on and not a dead end: the
                // instance publishes Failed, so [connectViaTor] declines to adopt
                // it and takes the ordinary fresh-instance path at unlock.
                LogBuffer.append("W", "ViewModel", "speculative Tor start failed, port=$port — unlock will start a fresh instance")
            }
        }
        // Measure THIS bootstrap, not the unlock that follows it.
        telemetry.armBootStamp(tor)
        armPreUnlockRelayWarmup(tor)
    }

    /**
     * Every TorManager this ViewModel builds. Its session callbacks go through
     * the REBINDABLE [TorKeepAliveHolder.hooks] (bound to this ViewModel in
     * [init]) rather than straight to [descriptorHedge] etc., because
     * the bounded keep-alive can hand the instance to the NEXT session's
     * ViewModel — see [TorSessionHooks].
     */
    private fun newTorManager(): TorManager {
        // External SOCKS proxy mode: THE single construction site refuses. Every
        // caller is already diverted ([startSpeculativeTor], [connectViaTor]);
        // this is the invariant that makes "the embedded Tor is never used"
        // hold even for a future caller that forgets — a crash is the
        // fail-closed outcome, a silently started Tor is not.
        check(!externalProxyMode) { "embedded Tor requested while external proxy mode is on" }
        val hooks = TorKeepAliveHolder.hooks
        return TorManager(
            getApplication(),
            // The hedge is resolved through the hooks at EVERY use, so a Tor
            // kept warm into the next session drives THAT session's hedge (fresh
            // per-session budget) — never the cleared ViewModel's. Its gate is
            // the hung-circuit gate's "relay answered" (inert = true unbound).
            descriptorHedge = hooks::descriptorHedge,
            descriptorHedgeAnswered = hooks::hsCircuitAnswered,
            onDescriptorStageStalled = hooks::onDescriptorStageStalled,
            onNewCircuitAccepted = hooks::onNewCircuitAccepted,
            hsCircuitAnswered = hooks::hsCircuitAnswered,
            bootstrapStallKick = true,
        )
    }

    /**
     * BOUNDED TOR KEEP-ALIVE — the reattach half (TorKeepAlive.kt). Called once,
     * from [startSpeculativeTor], before any Tor is started for this session.
     *
     * Warm: the previous session's Tor child is still Connected (it was kept
     * < [TorKeepAlive.KEEP_ALIVE_MS] after backgrounding). It becomes THIS
     * session's [torManager] — no bootstrap, and Tor's in-RAM onion descriptor
     * survives, so the pre-unlock warm-up's `GET /` goes straight to
     * intro/rendezvous. The unlock then ADOPTS it through [connectViaTor]'s
     * existing adopt branch (Connected ⇒ live), which builds the MessageManager
     * on `PlatformHttpClient.torProxy(port)` exactly as for a speculative start.
     * Per-SESSION budgets (NEWNYM 2/session, the relay-answered latch, the
     * connect anchor, the telemetry latch) are fields of this new ViewModel and
     * start fresh — and so does the descriptor hedge ([descriptorHedge], resolved
     * through the hooks: the adopted Tor drives THIS session's instance, whose
     * budget is fresh; adopt starts no Tor process, so nothing calls its
     * resetForNewTorProcess); the per-PROCESS Tor ledgers (HsCircuitWatchdog,
     * HsDirLedger, SocksPortRedirect) deliberately carry over with the daemon
     * they describe.
     *
     * NOT done for a warm instance: [ConnectTelemetryRecorder.armBootStamp] and the `boot` anchor —
     * this session started no Tor process, so `boot` is honestly omitted from
     * the telemetry rather than reported as a near-zero bootstrap; and the
     * warm-up's `HSFETCH` — the descriptor is already cached, and a forced
     * refetch would only add HSDir load.
     *
     * The connection-log ring is CLEARED first: what it holds at this point is
     * the previous session's lock marker plus the lines the parked daemon
     * narrated while no session existed — and with no `TOR_START` in the ring
     * the telemetry timeline would otherwise anchor on that stale lock marker.
     *
     * Returns true when a warm instance was adopted (the caller starts nothing).
     */
    /**
     * External SOCKS proxy mode's half of the keep-alive reclaim: a Tor the
     * PREVIOUS session kept warm (it ran without external mode, and the user
     * enabled it for this launch) is stopped at once instead of adopted.
     * Reclaim always ends the keep-alive (timer + foreground service), so after
     * this no embedded Tor of ours is alive in the process.
     */
    private fun retireKeptTorForExternalProxyMode() {
        when (val reclaim = TorKeepAliveHolder.reclaimForNewSession()) {
            is TorKeepAlive.Reclaim.Warm -> {
                reclaim.tor.stop()
                ConnectionLog.clear()
                LogBuffer.append("D", "ViewModel", "external proxy mode — stopped the Tor kept warm by the previous session")
            }
            is TorKeepAlive.Reclaim.Expired, is TorKeepAlive.Reclaim.Cold -> Unit
        }
    }

    private fun adoptWarmTorFromPreviousSession(): Boolean {
        return when (val reclaim = TorKeepAliveHolder.reclaimForNewSession()) {
            is TorKeepAlive.Reclaim.Warm -> {
                val tor = reclaim.tor
                torManager = tor
                ConnectionLog.clear()
                // Coded so the connect telemetry can split WARM
                // connects from cold ones: with the ring just cleared and no
                // TOR_START to follow, this line is also the timeline's anchor —
                // the same pre-unlock moment a cold session's TOR_START marks.
                ConnectionLog.append(ConnectionLog.Kind.TOR, TorKeepAlive.PHRASE_REUSED, ConnectionLog.Code.TOR_REUSED)
                LogBuffer.append("D", "ViewModel", "adopted the Tor kept warm from the previous session — no bootstrap")
                armPreUnlockRelayWarmup(tor, fetchDescriptor = false)
                true
            }
            is TorKeepAlive.Reclaim.Expired -> {
                ConnectionLog.append(ConnectionLog.Kind.TOR, TorKeepAlive.PHRASE_EXPIRED)
                false
            }
            is TorKeepAlive.Reclaim.Cold -> false
        }
    }

    /**
     * The tier half of the keep-alive gate, taken from an AUTHENTICATED read at
     * this session's unlock ([onVaultOpened]). Only consulted when the live read
     * at backgrounding is `Unreadable` (see [TorKeepAlive.shouldKeepAlive]);
     * null = no unlock this session ⇒ refuse.
     */
    private var sessionTierAllowsKeepAlive: Boolean? = null

    /**
     * BOUNDED TOR KEEP-ALIVE — the arm half, called by `MainActivity.onStop`
     * immediately BEFORE `finishAndRemoveTask()` (a foreground service can only
     * be started while the app is still leaving the foreground; [onCleared]
     * would be too late). Evaluates the gate and, if it passes, starts the
     * foreground service + the 2-min clock. It changes NOTHING about the
     * teardown itself: [lockSession] still closes the vault, wipes the keyset
     * and scrubs every manager; only its final `stop()` becomes a hand-over.
     *
     * Refuses (Tor stops with the session exactly as before) when: no Tor /
     * not Connected / mid corrupt-state retry; the unlocked session never got a
     * relay answer (a possibly wedged daemon); a wipe ran this session or the
     * deniable cover is armed; the tier is MAXIMUM (or unprovable).
     */
    fun armTorKeepAliveOnBackground() {
        val tor = torManager ?: return
        val connected = tor.state.value is TorManager.ConnectionState.Connected && !tor.isMidInternalRetry
        val isWipe = _wipedThisSession.value || ProcessWipeCover.armed
        // An unlocked session whose transport never reached the relay over this
        // Tor must not hand it on: background + return is the user's restart
        // remedy for a stuck connect. Pre-unlock there is no evidence either way.
        val notKnownWedged = vault == null || relayAnsweredThisSession ||
            messageManager?.hasCompletedRelayRoundTrip() == true
        // Short-circuit before the device-key read when the answer is already no.
        if (isWipe || !connected || !notKnownWedged) return
        val allowed = TorKeepAlive.shouldKeepAlive(
            isWipe = isWipe,
            torConnected = connected,
            notKnownWedged = notKnownWedged,
            liveTier = vaultSelector.protectionLevelForEnforcement(),
            sessionTierAllowed = sessionTierAllowsKeepAlive,
        )
        if (!allowed) {
            LogBuffer.append("D", "ViewModel", "Tor keep-alive refused by the tier gate — Tor stops with the session")
            return
        }
        TorKeepAliveHolder.armOnBackground(getApplication())
    }

    /**
     * PRE-UNLOCK RENDEZVOUS WARM-UP: the moment the
     * speculative [tor] reports `Connected` and no vault is open yet, issue ONE
     * bare `GET {relayBaseUrl}/` over its SOCKS proxy so the onion descriptor
     * fetch + rendezvous happen WHILE the user is still typing, instead of after
     * unlock. Preceded by a control-socket `HSFETCH` when that channel is up,
     * which starts the descriptor fetch even before a stream exists.
     *
     * Why this is safe to do before the vault opens — the request needs no
     * secret. It carries no capability, no auth header, no body and names no
     * inbox; on the wire it is the same `GET /` the health probe issues, which
     * is already the first request of every session. The reason it did not happen earlier
     * was the OBJECT GRAPH (the probe lives on a MessageManager, which needs an
     * open vault), not the crypto. See [RelayWarmup] for the full rule list.
     *
     * Bounds, all of them:
     *  - At most TWO attempts per Tor instance, and the second one only after a
     *    `SIGNAL NEWNYM` (see [fireWarmupNewnym] and
     *    [RelayWarmup.shouldRotateAndRetry]). It is armed only here, alongside
     *    the one-shot [startSpeculativeTor], and `first {}` completes on the
     *    first `Connected` — a later reachability flap or self-heal restart
     *    re-arms nothing.
     *  - `vault == null` re-checked AT FIRE TIME: if the user unlocked while Tor
     *    was still bootstrapping, the session's own transport exists and does
     *    this work itself, so the warm-up stands down rather than opening a
     *    second stream onto the same pending rendezvous.
     *  - [RelayWarmup.HTTP_TIMEOUT_SECONDS] budget PER ATTEMPT (25 s,
     *    down from 60), fire-and-forget, nothing persisted, and a failure is
     *    never surfaced to the user.
     *  - Cancelled by lock and by wipe. Known limitation: cancellation
     *    cannot interrupt a socket read already in flight (the same property
     *    every other blocking relay call here has), which is why the request is
     *    built to carry nothing that could leak if it completes late.
     *
     * It deliberately does NOT touch [_isRelayReachable], [_relayHandshakeComplete]
     * or [MessageManager.hasCompletedRelayRoundTrip]: the contact list stays
     * hidden until the SESSION's own transport answers. The post-unlock health
     * probe is unchanged — the warm-up only makes its circuit exist earlier.
     *
     * Launch-time wipes are already ordered strictly BEFORE this ViewModel
     * exists (see [init]), so no wipe can be pending when this arms.
     */
    private fun armPreUnlockRelayWarmup(tor: TorManager, fetchDescriptor: Boolean = true) {
        if (RelayConfig.BASE_URL.isEmpty()) return
        // Unreachable in external proxy mode (no TorManager exists to pass in);
        // belt for a future caller — the warm-up is an embedded-Tor feature.
        if (externalProxyMode) return
        relayWarmupJob?.cancel()
        relayWarmupJob = viewModelScope.launch {
            val connected = tor.state.first {
                it is TorManager.ConnectionState.Connected
            } as? TorManager.ConnectionState.Connected ?: run {
                // Defensive branch (the predicate above already guarantees the
                // cast): logged rather than silent so the panel never shows a
                // warm-up that simply stops existing.
                ConnectionLog.append(
                    ConnectionLog.Kind.RELAY,
                    "warm-up skipped: tor not ready",
                    ConnectionLog.Code.WARMUP_SKIPPED,
                )
                return@launch
            }
            if (vault != null) {
                // The user unlocked while Tor was still bootstrapping — the
                // session's own transport does this work itself. A skip here is
                // the GOOD outcome, but it has to be visible: otherwise the
                // panel shows a warm-up "started" with no ending.
                ConnectionLog.append(
                    ConnectionLog.Kind.RELAY,
                    "warm-up skipped: unlocked first",
                    ConnectionLog.Code.WARMUP_SKIPPED,
                )
                return@launch
            }
            // Best-effort and never logged with the address: a v3 descriptor is
            // never cached on disk, so this starts the HSDir fetch the GET below
            // would otherwise have to wait for. `false` (no control channel yet,
            // or Tor refused) simply means the GET does all of the work.
            // Skipped for a Tor kept warm from the previous session
            // ([adoptWarmTorFromPreviousSession]): its descriptor is still cached.
            // Several onion addresses: the descriptor RACE across
            // them instead (normally already begun at Connected — then a no-op);
            // the GET below waits for its winner. One address: the old HSFETCH.
            if (fetchDescriptor) tor.requestRelayDescriptorFetch()
            val http = PlatformHttpClient.torProxy(connected.socksPort).asRelayHttp()
            val attempt = RelayWarmup.warmAttempt(http = http, relayBaseUrl = RelayConfig.BASE_URL)
            // ACT ON WARMUP_FAILED. A warm-up that burns its whole budget is
            // the same wedged introduction point the post-unlock cold rung
            // recovers from — measured in every slow connect timeline — and
            // until now nothing consumed that signal: the failure was logged and
            // the user then paid for the identical wedge after unlocking. The
            // decision is shared with iOS ([RelayWarmup.shouldRotateAndRetry]:
            // failed AND full-budget AND at most one retry); the NEWNYM budget is
            // this ViewModel's, shared with [maybeFireEarlyNewnym].
            if (!RelayWarmup.shouldRotateAndRetry(attempt.answered, attempt.elapsedMs, retriesUsed = 0)) return@launch
            // Unlocking during those 25 s no longer cancels the rotation:
            // the session's first probe is stuck on the SAME wedged
            // HS circuits, and refusing here only deferred the rescue to the cold
            // rung at ~t45. What still refuses is a session that has ALREADY
            // reached the relay — the shared gate inside [fireWarmupNewnym].
            // Descriptor-stage early recovery (DescriptorHedge): when
            // the 10 s descriptor-stage NEWNYM already fired for this stall it
            // REPLACES this one — retry the GET on its fresh circuits, never a
            // second NEWNYM for the same stall.
            if (!descriptorHedge.stageNewnymFiredThisSession && !fireWarmupNewnym(tor)) return@launch
            RelayWarmup.warmAttempt(http = http, relayBaseUrl = RelayConfig.BASE_URL)
        }
    }

    /**
     * DESCRIPTOR-STAGE EARLY RECOVERY (iOS sibling
     * `AppState.fireDescriptorStageNewnym`). Called by the TorManager (IO thread,
     * via [TorKeepAliveHolder.hooks]) when the shared [DescriptorHedge] decided the
     * descriptor episode is still open 10 s after its first request with the hedge
     * budget spent or ≥ 2 requests outcome-less. Hops to Main (the NEWNYM counters
     * are touched there by the warm-up rotation too) and spends ONE NEWNYM through
     * the SAME shared gate and budget as the warm-up rotation
     * ([MessageManager.shouldFireWarmupNewnym]: no relay answer yet this session,
     * [earlyNewnymsFired] < [MessageManager.EARLY_NEWNYM_MAX_FIRES]) — so it can
     * never be a third NEWNYM, and the warm-up then retries without its own.
     */
    private fun onDescriptorStageStalled() {
        viewModelScope.launch { fireDescriptorStageNewnym() }
    }

    private suspend fun fireDescriptorStageNewnym() {
        val tor = torManager ?: return
        if (tor.isMidInternalRetry) return
        if (!MessageManager.shouldFireWarmupNewnym(
                transportRoundTripCompleted = messageManager?.hasCompletedRelayRoundTrip() == true,
                relayAnsweredThisSession = relayAnsweredThisSession,
                newnymsFiredThisSession = earlyNewnymsFired,
            )
        ) {
            LogBuffer.append("D", "Relay", "descriptor stage stalled — NEWNYM refused by the session gate")
            return
        }
        DescriptorHedge.logStageStalled()
        if (!tor.requestNewCircuit()) {
            LogBuffer.append("W", "Relay",
                "NEWNYM unavailable (control channel down) — descriptor-stage rotation skipped")
            return
        }
        earlyNewnymsFired++
        descriptorHedge.noteStageNewnymFired()
        messageManager?.noteEarlyNewnymFired()
        LogBuffer.append("W", "Relay",
            "descriptor stage stalled — requested fresh Tor circuits " +
                "(NEWNYM $earlyNewnymsFired/${MessageManager.EARLY_NEWNYM_MAX_FIRES})")
        // The EXISTING coded NEWNYM line, verbatim, same shared counter (iOS
        // emits the identical string) — the uncoded stage line above says why.
        ConnectionLog.append(
            ConnectionLog.Kind.STALL,
            "relay unreachable - requesting fresh circuits (NEWNYM $earlyNewnymsFired/${MessageManager.EARLY_NEWNYM_MAX_FIRES})",
            ConnectionLog.Code.NEWNYM,
        )
    }

    /**
     * Handed to every [TorManager] this ViewModel builds: called (IO thread) right
     * after ANY app-fired `SIGNAL NEWNYM` was accepted — warm-up rotation, cold
     * rung, warm rung, stall watch — so the current transport aborts its
     * in-flight health probe / batch peek and re-probes at once instead of
     * sitting out a 20 s budget on a retired circuit
     * ([MessageManager.noteNewCircuitRequested], shared with iOS via
     * `IosAppController.noteNewCircuitRequested`). No transport yet (pre-unlock)
     * = nothing in flight to abort.
     */
    private fun onNewCircuitAccepted() {
        messageManager?.noteNewCircuitRequested()
    }

    // -----------------------------------------------------------------------
    // Network-restore kick: the action. The hook (callback, debounce timer,
    // rate-limit latch) is [networkRestore]; the shared decision is
    // [NetworkRestoreKick]. On a restore:
    //   1. TorManager.kickForNetworkRestore (DisableNetwork 1 -> 0; it aborts the
    //      in-flight probe/peek through the new-circuit hook when Connected),
    //   2. the stall watch re-armed with a FULL first window,
    //   3. the opt-out ladder's backoff woken ([networkRestoreEpoch]).
    // -----------------------------------------------------------------------

    /**
     * The action. Embedded Tor only: an external proxy or the debug direct path
     * has no Tor of ours to tell. The ladder wake and the stall-watch re-arm run
     * whether or not the toggle reached Tor — a Tor that is down or restarting
     * still benefits from a fresh watch, and the ladder waits for its transport.
     */
    private suspend fun performNetworkRestoreKick() {
        if (externalProxyMode || !RelayConfig.isTorRequired) {
            NetworkRestoreKick.logSkip(NetworkRestoreKick.SkipReason.NOT_EMBEDDED_TOR)
            return
        }
        val tor = torManager
        val skip = if (tor == null) NetworkRestoreKick.SkipReason.TOR_NOT_RUNNING
                   else tor.kickForNetworkRestore()
        if (skip != null) NetworkRestoreKick.logSkip(skip)
        // Only for an open session: pre-unlock there is no watch and no ladder.
        if (vault != null && !moveQuiesced) {
            if (_relayConnectPhase.value == RelayConnectPhase.Stalled) {
                _relayConnectPhase.value = RelayConnectPhase.Connecting
            }
            relayStallWatchFullFirstWindow = true
            startRelayStallWatch()
            LogBuffer.append("D", "NetRestore", "network restore: stall watch re-armed")
        }
        networkRestoreEpoch.update { it + 1 }
    }

    // -----------------------------------------------------------------------
    // Relay connect (Tor / external proxy / direct) and its watchdogs
    // -----------------------------------------------------------------------

    /**
     * Hung onion-circuit rung gate ([HsCircuitWatchdog], shared with iOS via
     * `IosAppController.relayAnsweredForCircuitWatchdog`): the rung closes a hung
     * intro / rendezvous circuit only BEFORE the session's first relay answer —
     * the set-once latch OR the current transport's round-trip latch. Read on an
     * IO coroutine; set-once latches only.
     */
    private fun relayAnsweredForCircuitWatchdog(): Boolean =
        relayAnsweredThisSession || messageManager?.hasCompletedRelayRoundTrip() == true

    /**
     * The warm-up rotation: ONE `SIGNAL NEWNYM` on a warm-up (started pre-unlock)
     * that burned its budget, spent out of the SAME per-session budget as
     * [maybeFireEarlyNewnym]'s cold rung ([earlyNewnymsFired], capped at
     * [MessageManager.EARLY_NEWNYM_MAX_FIRES]) — so the two rungs together can
     * never exceed the cap, whichever fires first. Since 2026-10-06 it may also
     * fire AFTER unlock, as long as the session has had no relay round trip yet
     * ([MessageManager.shouldFireWarmupNewnym], shared with iOS).
     *
     * Needs no vault: the control socket has been up since Tor started, and
     * NEWNYM carries nothing. It cannot use [MessageManager.earlyNewnymDue],
     * whose evidence is full-budget PROBE_TIMEOUTs on a transport that does not
     * exist yet — the equivalent evidence here is the warm-up's own burnt
     * budget, classified by the shared [RelayWarmup.shouldRotateAndRetry].
     * [MessageManager.noteEarlyNewnymFired] is still called when a transport
     * happens to exist, so the post-unlock rung never counts pre-unlock evidence.
     *
     * Returns whether NEWNYM was actually handed to the control channel; false
     * retires the rung for this session exactly like the post-unlock sibling.
     */
    private suspend fun fireWarmupNewnym(tor: TorManager): Boolean {
        // Same guard as the cold rung: never NEWNYM into a daemon that is
        // rebuilding its whole circuit set anyway.
        if (tor.isMidInternalRetry) return false
        // THE shared gate (commonMain, identical on iOS): no relay round trip
        // yet this session — locked or not — and the per-session NEWNYM budget
        // shared with [maybeFireEarlyNewnym] not spent.
        if (!MessageManager.shouldFireWarmupNewnym(
                transportRoundTripCompleted = messageManager?.hasCompletedRelayRoundTrip() == true,
                relayAnsweredThisSession = relayAnsweredThisSession,
                newnymsFiredThisSession = earlyNewnymsFired,
            )
        ) return false
        if (!tor.requestNewCircuit()) {
            // Deliberately does NOT retire the session budget the way the
            // post-unlock sibling does: this runs seconds after Tor first
            // reported Connected, when the control channel can still be coming
            // up, and spending the whole ladder on that timing would be wrong.
            // The post-unlock rung retries and retires it if it is really gone.
            LogBuffer.append("W", "Relay",
                "NEWNYM unavailable (control channel down) — warm-up circuit rotation skipped")
            return false
        }
        earlyNewnymsFired++
        messageManager?.noteEarlyNewnymFired()
        LogBuffer.append("W", "Relay",
            "rendezvous warm-up burned its budget — requested fresh Tor circuits " +
                "(NEWNYM $earlyNewnymsFired/${MessageManager.EARLY_NEWNYM_MAX_FIRES})")
        // The EXISTING cold-rung phrase, verbatim and with the same shared
        // counter, because this IS that rung fired on pre-unlock evidence — the
        // WARMUP_FAILED line immediately above it in the panel is what says which
        // evidence. iOS emits the identical string.
        ConnectionLog.append(
            ConnectionLog.Kind.STALL,
            "relay unreachable - requesting fresh circuits (NEWNYM $earlyNewnymsFired/${MessageManager.EARLY_NEWNYM_MAX_FIRES})",
            ConnectionLog.Code.NEWNYM,
        )
        return true
    }

    /**
     * Is [tor] a session worth ADOPTING rather than replacing?
     *
     * `Bootstrapping` / `Connected` are live by definition. `Idle` is the
     * ambiguous one — TorManager publishes it both BEFORE its start() coroutine
     * has written `Bootstrapping(0)` and AFTER a stop() — and is resolved by
     * whether the start coroutine is still running: every path that stops an
     * instance ([connectViaTor]'s fresh branch, [onCleared],
     * [performEmergencyWipe]) cancels [torStartJob] first, so "Idle with a live
     * start job" can only be the pre-start window. `Failed` is not adopted:
     * TorManager destroyed its child and gave up.
     *
     * …except while its own corrupt-state retry is in flight, which is checked
     * FIRST because that path publishes `Failed` (attempt 1 timed out) and then
     * `Idle` (the discard's stop()) on its way into attempt 2 — both of which
     * would read as dead here. Adopting there keeps the recovery running; the
     * fresh path would cancel it mid-discard. Same reasoning as the corrupt-state-retry defer in
     * [restartTor].
     */
    private fun torInstanceIsLive(tor: TorManager): Boolean {
        if (tor.isMidInternalRetry) return true
        return when (tor.state.value) {
            is TorManager.ConnectionState.Bootstrapping,
            is TorManager.ConnectionState.Connected -> true
            is TorManager.ConnectionState.Failed -> false
            is TorManager.ConnectionState.Idle -> torStartJob?.isActive == true
        }
    }

    /**
     * Wires the just-opened vault to a Tor session, ADOPTING the one
     * [startSpeculativeTor] already has in flight whenever it is still alive.
     *
     * **ADOPT** (the common path now): the live instance is KEPT and only the
     * monitor is attached to it, against the now-open vault. [TorManager.state]
     * is a `StateFlow`, so the fresh collector is replayed the CURRENT value
     * immediately — a Tor that reached Connected while the user was typing builds
     * the MessageManager on that first emission, race-free, with no "wait for the
     * next transition" gap. Nothing calls `stop()` here, and nothing calls
     * `start()` again: [TorManager.start] is not re-entrant (a second call spawns
     * a second Tor child against the same DataDirectory), so the in-flight
     * [torStartJob] is left exactly as it is.
     *
     * **FRESH** (no instance, a dead/Failed/stopped one, or [forceFresh]):
     * today's path unchanged — cancel the monitor, cancel the old start, stop(),
     * construct a new TorManager, launch its start.
     *
     * @param forceFresh set by [restartTor]. The ~100 s self-heal and the manual
     *   Reconnect exist precisely to THROW THE CURRENT SESSION AWAY, so they must
     *   never adopt it however healthy its state flow looks — without this they
     *   would silently become no-ops the moment adoption landed.
     */
    private fun connectViaTor(openedVault: VaultDatabase, forceFresh: Boolean = false) {
        // External SOCKS proxy mode: every path that would (re)build the embedded
        // Tor — first unlock, the manual Reconnect via [restartTor], a move
        // resume — lands on the external proxy instead. Never a TorManager.
        if (externalProxyMode) {
            connectViaExternalProxy(openedVault)
            return
        }
        // Connect-time telemetry anchor (ConnectTelemetry.kt). Set-once, so the
        // self-heal restart / manual Reconnect / move resume that also land here
        // keep measuring the user's ONE wait rather than restarting the clock.
        telemetry.markConnectStart()
        val existing = torManager
        if (!forceFresh && existing != null && torInstanceIsLive(existing)) {
            LogBuffer.append("D", "ViewModel", "adopting the in-flight pre-unlock Tor session")
            startTorMonitor(openedVault, existing)
            // Re-anchored inside, onto this bootstrap's real elapsed time.
            armTorBootstrapWatchdog()
            return
        }
        torMonitorJob?.cancel()
        // The old instance's start() coroutine must not outlive its replacement —
        // cancel it before stop() so it can't keep racing the next TorManager's
        // construction. A plain cancel() (no join): this runs on the Main thread
        // and TorManager's stopped/purgedForRetry guards already bound the
        // in-flight worst case to one spurious bootstrap retry.
        torStartJob?.cancel()
        // The pre-unlock warm-up was waiting on (or riding) the instance this
        // branch is about to stop — it must not outlive it. The replacement gets
        // no warm-up: from here on the session has its own transport and the
        // health probe does the same work.
        relayWarmupJob?.cancel()
        // Same reasoning for the boot observer: it is watching the state flow
        // of the instance being stopped. The replacement is monitored from its
        // own start ([startTorMonitor] is attached below, before start()), so
        // that path measures its bootstrap honestly without it.
        telemetry.cancelBootStamp()
        torManager?.stop()

        // boot anchor (ConnectTelemetry.kt): covers the case where this is the
        // FIRST Tor process of the session (no speculative start ran ahead of
        // it, e.g. the app was backgrounded before it fired). Set-once, so a
        // later self-heal/Reconnect replacing the instance here never moves it.
        telemetry.markTorProcessStart()
        val tor = newTorManager()
        torManager = tor
        startTorMonitor(openedVault, tor)
        torStartJob = viewModelScope.launch(Dispatchers.IO) {
            val port = tor.start()
            if (port <= 0) {
                LogBuffer.append("E", "ViewModel", "Tor failed to start, port=$port")
            }
        }
        armTorBootstrapWatchdog()
    }

    /**
     * EXTERNAL SOCKS PROXY MODE — the [connectViaTor] sibling. Checks the user's
     * proxy is listening (a bare TCP connect, nothing sent — see
     * [PlatformHttpClient.socksProxyReachable]), then wires the session's
     * MessageManager to a SOCKS5h client pointed at it
     * ([PlatformHttpClient.socksProxy]). [_torState] is reused as "the relay
     * transport" so every existing consumer (send gates, Add Contact's mint gate,
     * the move transport, the push seam) behaves exactly as with the embedded Tor:
     * `Connected` = proxy listening, `Failed` = it is not.
     *
     * FAIL CLOSED: an invalid stored setting or an unreachable proxy publishes
     * `Failed`, builds no transport and offers the manual Reconnect (which lands
     * back here via [restartTor] → [connectViaTor]). Nothing falls back.
     *
     * Logs only the shared address-free phrases ([ExternalTorProxy.inUseLogLine],
     * [ExternalTorProxy.statusLogLine], PHRASE_*) — word for word with iOS. No connect telemetry in this mode (`ConnectTelemetryRecorder.armConnectTelemetry`).
     */
    private fun connectViaExternalProxy(openedVault: VaultDatabase) {
        telemetry.markConnectStart()
        extProxyConnectJob?.cancel()
        torStallJob?.cancel()
        val cfg = externalProxy
        if (cfg == null) {
            // Stored value present but unusable: fail closed, say which.
            val unreadable = _externalProxyStatus.value == ExternalProxyStatus.UNREADABLE
            val phrase = if (unreadable) ExternalTorProxy.PHRASE_UNREADABLE_CONFIG else ExternalTorProxy.PHRASE_INVALID_CONFIG
            LogBuffer.append("E", "ViewModel", phrase)
            ConnectionLog.append(ConnectionLog.Kind.TOR, phrase)
            if (!unreadable) _externalProxyStatus.value = ExternalProxyStatus.INVALID
            _torState.value = TorManager.ConnectionState.Failed("external proxy setting unusable")
            return
        }
        val hostClass = ExternalTorProxy.classify(cfg.host)
        if (!RelayConfig.isTorRequired) {
            // The SOCKS path carries onions only (onionTransportGuard); a clearnet
            // dev relay in this mode is refused outright, never sent direct.
            LogBuffer.append("E", "ViewModel", ExternalTorProxy.PHRASE_RELAY_NOT_ONION)
            ConnectionLog.append(ConnectionLog.Kind.TOR, ExternalTorProxy.PHRASE_RELAY_NOT_ONION)
            _externalProxyStatus.value = ExternalProxyStatus.UNREACHABLE
            _torState.value = TorManager.ConnectionState.Failed("relay is not an onion")
            return
        }
        ConnectionLog.append(ConnectionLog.Kind.TOR, ExternalTorProxy.inUseLogLine(hostClass))
        _externalProxyStatus.value = ExternalProxyStatus.CHECKING
        _torState.value = TorManager.ConnectionState.Bootstrapping(0)
        extProxyConnectJob = viewModelScope.launch {
            val reachable = withContext(Dispatchers.IO) {
                PlatformHttpClient.socksProxyReachable(cfg.host, cfg.port, EXT_PROXY_REACHABILITY_TIMEOUT_MS)
            }
            // The session this check was for may have locked meanwhile.
            if (vault !== openedVault) return@launch
            val line = ExternalTorProxy.statusLogLine(hostClass, reachable)
            LogBuffer.append(if (reachable) "D" else "W", "ViewModel", line)
            ConnectionLog.append(ConnectionLog.Kind.TOR, line)
            if (!reachable) {
                _externalProxyStatus.value = ExternalProxyStatus.UNREACHABLE
                _torState.value = TorManager.ConnectionState.Failed("external proxy unreachable")
                _relayConnectPhase.value = RelayConnectPhase.Stalled
                return@launch
            }
            _externalProxyStatus.value = ExternalProxyStatus.REACHABLE
            _torState.value = TorManager.ConnectionState.Connected(cfg.port)
            if (messageManager == null) {
                wireRelayTransport(openedVault, PlatformHttpClient.socksProxy(cfg.host, cfg.port))
            }
        }
    }

    /**
     * External proxy mode's replacement for [startRelayStallWatch]'s ladder: no
     * NEWNYM (we have no control port — the circuits are the proxy's), no Tor
     * restart (there is no Tor of ours). While the relay stays unreachable for
     * the same window the embedded-Tor ladder waits before its first rung, it
     * re-checks the proxy ONCE (to tell "proxy gone" from "proxy up, relay not
     * answering through it"), narrates which, and offers the manual Reconnect.
     * collectLatest cancels it the moment the relay answers, exactly like the
     * embedded-Tor watch. No new timer: this is that watch's own window.
     */
    private fun startExternalProxyStallWatch() {
        relayStallJob?.cancel()
        val cfg = externalProxy ?: return
        relayStallJob = viewModelScope.launch {
            isRelayReachable.collectLatest { reachable ->
                if (reachable) {
                    _relayConnectPhase.value = RelayConnectPhase.Connecting
                    return@collectLatest
                }
                delay(RELAY_SELF_HEAL_RESTART_MS)
                val proxyUp = withContext(Dispatchers.IO) {
                    PlatformHttpClient.socksProxyReachable(cfg.host, cfg.port, EXT_PROXY_REACHABILITY_TIMEOUT_MS)
                }
                if (!proxyUp) {
                    // The shared phrase, no Code (iOS emits the identical line).
                    val line = ExternalTorProxy.statusLogLine(ExternalTorProxy.classify(cfg.host), false)
                    LogBuffer.append("W", "Relay", line)
                    ConnectionLog.append(ConnectionLog.Kind.STALL, line)
                    _externalProxyStatus.value = ExternalProxyStatus.UNREACHABLE
                } else {
                    // Proxy up, relay silent through it: debug-log only — the
                    // panel vocabulary for this mode is the shared phrase set.
                    LogBuffer.append("W", "Relay", "ext proxy: proxy reachable but the relay is not answering - offering manual reconnect")
                }
                _relayConnectPhase.value = RelayConnectPhase.Stalled
            }
        }
    }

    /**
     * Builds THE session transport on [client] and starts every loop that rides
     * it. Shared by the embedded-Tor monitor's Connected branch and the external
     * proxy path, so the two can never wire a session differently.
     */
    private fun wireRelayTransport(openedVault: VaultDatabase, client: PlatformHttpClient) {
        messageManager = MessageManager(openedVault, httpClient = client, localAppVersion = BuildConfig.VERSION_NAME, maximumShield = maximumShield)
        startRelayCheck()
        startDebugLogPeriodicUpload()
        startControlPoll()
        // Transport back (a self-heal restart lands here too):
        // re-drive the sends that died on the previous transport.
        armTransportRedrive()
        // Races the unread dot ahead of the control poll's first
        // jittered cycle; merge-only per-contact emission,
        // steady-state loop above is unchanged. It now opens with a
        // control PRE-DRAIN of the group members' control inboxes
        // (see GroupManager.primeUnreadCounts), so a pending GROUP
        // text is attributed to the group instead of the sender's
        // 1:1 row — the two are indistinguishable in a /peek count.
        startUnreadPrime()
    }

    /**
     * How long the CURRENT Tor instance has already been bootstrapping, for the
     * two unlock-time watchdogs to subtract off (see [reanchoredDelayMs]).
     *
     * **Zero unless Tor is genuinely still pre-Connected, and that condition is
     * the load-bearing half.** The only thing worth compensating for is a
     * bootstrap that began before the vault opened and has not landed. Once Tor
     * IS Connected the head start has already paid off and the remaining wait is
     * about the RELAY handshake, which only begins when the transport is wired at
     * unlock — subtracting a long, *successful* bootstrap there would restart a
     * perfectly healthy Tor seconds after unlock, which is the exact failure the
     * "arm the watchdog at PIN-mount instead" alternative was rejected for. The
     * same clause is what keeps a much later reachability FLAP on the same
     * instance at its full window.
     *
     * Zero on the fresh-instance path too — [TorManager.startedAtElapsedMs] is 0
     * until that instance's own `start()` runs — so that path's behaviour is
     * unchanged.
     */
    private fun torBootstrapElapsedMs(): Long {
        val tor = torManager ?: return 0L
        if (tor.state.value is TorManager.ConnectionState.Connected) return 0L
        val startedAt = tor.startedAtElapsedMs
        if (startedAt <= 0L) return 0L
        return (SystemClock.elapsedRealtime() - startedAt).coerceAtLeast(0L)
    }

    /**
     * [fullMs] minus [torBootstrapElapsedMs], floored at
     * [MIN_REANCHORED_WATCHDOG_MS].
     *
     * Without this, a slow credential typer gets one of two wrong answers: arm
     * the watchdogs at unlock and a Tor 60 s into a stuck bootstrap waits another
     * full window before anything self-heals (a 160 s stuck window); arm them
     * when the PIN screen mounts instead and a *healthy* bootstrap gets restarted
     * under the user mid-typing. Re-anchoring gives the stuck one its self-heal
     * ~40 s after unlock while leaving the healthy one alone.
     */
    private fun reanchoredDelayMs(fullMs: Long): Long =
        (fullMs - torBootstrapElapsedMs()).coerceAtLeast(MIN_REANCHORED_WATCHDOG_MS)

    /**
     * Arms the PRE-CONNECT bootstrap watchdog (see [torBootstrapStalled]).
     *
     * Idempotent: cancels any previous watchdog before launching a new one, so the
     * restart paths (self-heal at ~100s, manual Reconnect) can never stack them.
     * Readiness is read as CURRENT-VALUE state at wake time, never captured at arm
     * time.
     *
     * Deliberately does NOT clear [_torBootstrapStalled]: [startRelayStallWatch]
     * auto-restarts Tor at ~100s, i.e. ~10s after this first fires, and clearing
     * here would flash the honest hint off again for the fresh bootstrap's 90s —
     * a message that blinks is worse than none. From the user's side that restart
     * is one continuous unattended wait, so the hint stays until Tor actually
     * connects. The three places that DO clear it are the ones where the wait
     * genuinely restarts: a new session ([onVaultOpened]), an explicit user
     * Reconnect ([reconnectRelay]), and success (the monitor's Connected branch).
     *
     * Deliberately does NOT touch Tor either: the one auto-restart lives in
     * [startRelayStallWatch]. iOS sibling: `TransportStatus.armTorBootstrapWatchdog()`.
     *
     * RE-ANCHORED (speculative-start package): the delay is
     * [TOR_BOOTSTRAP_STALL_MS] measured from when the BOOTSTRAP began, not from
     * when this was armed — see [reanchoredDelayMs]. On the fresh-instance path
     * that is the full window as before; on the adopt path a Tor already 60 s
     * into a stuck bootstrap surfaces the hint 30 s after unlock, which is when
     * it becomes true, rather than 90 s after.
     */
    private fun armTorBootstrapWatchdog() {
        torStallJob?.cancel()
        // Computed at ARM time (the elapsed bootstrap is a property of now, not
        // of wake time); the readiness check below stays a current-value read.
        val waitMs = reanchoredDelayMs(TOR_BOOTSTRAP_STALL_MS)
        torStallJob = viewModelScope.launch {
            delay(waitMs)
            if (_torState.value !is TorManager.ConnectionState.Connected) {
                LogBuffer.append("W", "ViewModel",
                    "Tor not connected ${TOR_BOOTSTRAP_STALL_MS}ms into its bootstrap (waited ${waitMs}ms from arming) — surfacing the network-may-be-blocking hint (bootstrap continues)")
                ConnectionLog.append(
                    ConnectionLog.Kind.STALL,
                    "Tor still bootstrapping after ${TOR_BOOTSTRAP_STALL_MS / 1000} s - this network may be blocking it",
                )
                _torBootstrapStalled.value = true
            }
        }
    }

    /**
     * Relay-connect self-heal + stall escalation. While the relay stays
     * unreachable, wait past Tor's own ~90s bootstrap timeout (so an in-progress bootstrap
     * is never interrupted — only a stuck/failed one) then, as a CHEAP first rung, ask Tor
     * for fresh circuits (SIGNAL NEWNYM over the authenticated control socket — in-process,
     * no re-bootstrap) and probe a reachability cycle; only if STILL unreachable escalate
     * to the expensive full-process [restartTor] — the in-app equivalent of "restart the
     * app to rebuild Tor". If it's STILL unreachable after a further window, flip to Stalled
     * so the contact list can offer a manual Reconnect. collectLatest resets the whole
     * escalation the instant the relay becomes reachable, so a brief reachability flap never
     * trips it and a recovery cancels a pending stall (including mid-NEWNYM-probe).
     *
     * Two changes from the speculative-start package, both inside the wait:
     *  - the FIRST restart wait is RE-ANCHORED onto the elapsed bootstrap
     *    ([reanchoredDelayMs]), so a Tor adopted 60 s into a stuck bootstrap
     *    self-heals ~40 s after unlock instead of ~100 s. Recomputed on every
     *    collectLatest pass and self-limiting: [torBootstrapElapsedMs] returns 0
     *    once Tor is Connected, so a later reachability flap on a healthy session
     *    gets the full window exactly as before.
     *  - The restart DEFERS while TorManager is inside its own one-shot
     *    corrupt-state retry — see [restartTor].
     */
    private fun startRelayStallWatch() {
        // Move freeze (docs/device-move.md D2): while this device is the OLD phone
        // of a move, nothing polls. A single received message advances the Double
        // Ratchet and orphans the new phone's chain, so this gate is not cosmetic.
        // It also has to be HERE and not only at the cancel site: a Tor restart
        // re-enters startTorMonitor's Connected branch, which recreates the
        // MessageManager (the move still needs the transport) and would otherwise
        // restart every loop with it.
        if (moveQuiesced) return
        // External SOCKS proxy mode: no NEWNYM, no Tor restart — see the sibling.
        if (externalProxyMode) {
            startExternalProxyStallWatch()
            return
        }
        relayStallJob?.cancel()
        // [relayStallWatchFullFirstWindow] (the network-restore re-arm): the watch
        // starts over FROM THE RESTORE with the full
        // window — re-anchoring onto a bootstrap that stood still only because the
        // network was gone would restart Tor seconds after the kick reviving it.
        var firstPassFull = relayStallWatchFullFirstWindow
        relayStallWatchFullFirstWindow = false
        relayStallJob = viewModelScope.launch {
            isRelayReachable.collectLatest { reachable ->
                if (reachable) {
                    _relayConnectPhase.value = RelayConnectPhase.Connecting
                    return@collectLatest
                }
                // Just past Tor's ~90s bootstrap timeout, minus whatever of that
                // bootstrap already elapsed before the vault opened.
                var waitMs = if (firstPassFull) RELAY_SELF_HEAL_RESTART_MS else reanchoredDelayMs(RELAY_SELF_HEAL_RESTART_MS)
                firstPassFull = false
                while (true) {
                    delay(waitMs)
                    // RESCHEDULE, never drop. Tearing Tor down here would
                    // cancel the very recovery this restart is trying to cause,
                    // and would do it at the worst moment — over freshly
                    // discarded working dirs, with the previous child possibly
                    // still releasing the DataDirectory lock. The restart intent
                    // survives: we wait another FULL window and re-check.
                    // Bounded by TorManager's own timeout on that second attempt
                    // (~90s), so this loop turns at most a couple of times.
                    if (torManager?.isMidInternalRetry != true) break
                    LogBuffer.append("W", "Relay",
                        "relay unreachable, but Tor is inside its own corrupt-state retry — rescheduling the auto-restart one full window")
                    ConnectionLog.append(
                        ConnectionLog.Kind.STALL,
                        "auto-restart rescheduled - Tor is inside its own retry",
                    )
                    waitMs = RELAY_SELF_HEAL_RESTART_MS
                }
                // CHEAP RUNG FIRST: ask Tor for fresh circuits (SIGNAL NEWNYM,
                // in-process, no re-bootstrap) and probe one reachability cycle
                // before the expensive full restart. If NEWNYM clears the stall,
                // isRelayReachable flips true and collectLatest cancels this whole
                // block at the delay below — restartTor() is never reached and the
                // ~90 s cold re-bootstrap is avoided. This can only help: the full
                // restart still follows if it doesn't.
                //
                // Composition with the existing self-heal machinery:
                //  - We only reach here AFTER the isMidInternalRetry defer loop
                //    above, so NEWNYM never fires while TorManager's own
                //    corrupt-state retry (a fresh bootstrap) is in flight; the
                //    re-check inside the loop guards a retry that STARTS mid-probe.
                //  - forceFresh semantics are untouched: NEWNYM does not tear the
                //    session down, so it never counts as the restart — restartTor()
                //    below still forces a fresh instance exactly as before.
                //  - Bounded by RELAY_NEWNYM_MAX_TRIES so it can't loop forever, and
                //    a control channel that never came up (requestNewCircuit()==false)
                //    short-circuits straight to the restart with zero added delay.
                //
                // CAVEAT: NEWNYM's benefit for the reachability-flake class is
                // UNVALIDATED on-device — see RELAY_NEWNYM_MAX_TRIES. Do not
                // oversell it; the full restart is the real fix.
                var newnymTries = 0
                while (newnymTries < RELAY_NEWNYM_MAX_TRIES) {
                    // Never NEWNYM into a daemon that is already re-bootstrapping
                    // (an internal corrupt-state retry that started during our
                    // probe) — that circuit set is being rebuilt from scratch.
                    if (torManager?.isMidInternalRetry == true) break
                    val fired = torManager?.requestNewCircuit() == true
                    if (!fired) {
                        LogBuffer.append("W", "Relay",
                            "NEWNYM unavailable (control channel down) — escalating straight to Tor restart")
                        ConnectionLog.append(
                            ConnectionLog.Kind.STALL,
                            "NEWNYM unavailable (control channel down) - escalating to Tor restart",
                            ConnectionLog.Code.NEWNYM,
                        )
                        break
                    }
                    newnymTries++
                    LogBuffer.append("W", "Relay",
                        "relay unreachable — requested fresh Tor circuits (NEWNYM $newnymTries/$RELAY_NEWNYM_MAX_TRIES), probing before restart")
                    // NAMES ITS RUNG. The cold rung
                    // ([maybeFireEarlyNewnym]) renders `(NEWNYM n/2)` and this one
                    // `(NEWNYM n, stall watch)`: both carry the same
                    // ConnectionLog.Code.NEWNYM — the wire vocabulary is unchanged and
                    // gains no token — but the two lines used to be BYTE-IDENTICAL
                    // (RELAY_NEWNYM_MAX_TRIES is also 2), so a panel or a debug log
                    // could not tell the cheap connect-time rung from this stall-watch
                    // escalation. `n` is this outage's own fire count. iOS emits the
                    // identical phrase.
                    ConnectionLog.append(
                        ConnectionLog.Kind.STALL,
                        "relay unreachable - requesting fresh circuits (NEWNYM $newnymTries, stall watch)",
                        ConnectionLog.Code.NEWNYM,
                    )
                    // collectLatest cancels HERE if NEWNYM restored reachability.
                    delay(RELAY_NEWNYM_PROBE_MS)
                }
                LogBuffer.append("W", "Relay", "relay still unreachable after NEWNYM — auto-restarting Tor (self-heal)")
                // TOR_RESTART marks an actual restart. The two "deferred" /
                // "rescheduled" lines above are deliberately left uncoded: they
                // are restarts that did NOT happen, and a consumer counting
                // TOR_RESTART must not see them.
                ConnectionLog.append(
                    ConnectionLog.Kind.STALL,
                    "still unreachable after NEWNYM - restarting Tor",
                    ConnectionLog.Code.TOR_RESTART,
                )
                restartTor()
                delay(RELAY_SELF_HEAL_STALL_MS)  // let the fresh session bootstrap
                LogBuffer.append("W", "Relay", "relay still unreachable after auto-restart — offering manual reconnect")
                ConnectionLog.append(
                    ConnectionLog.Kind.STALL,
                    "still unreachable after the restart - offering manual reconnect",
                    ConnectionLog.Code.RELAY_STALLED,
                )
                _relayConnectPhase.value = RelayConnectPhase.Stalled
            }
        }
    }

    /**
     * Tears down the current Tor + MessageManager and bootstraps a fresh Tor session on
     * the open vault. Nulls messageManager FIRST so startTorMonitor rebuilds it on the
     * NEW SOCKS port (its guard only recreates when messageManager == null). Shared by
     * the auto self-heal and the manual Reconnect.
     *
     * `forceFresh = true`: this function EXISTS to throw the current Tor session
     * away, so it must never take [connectViaTor]'s adopt path — which would
     * silently turn both the self-heal and the manual Reconnect into no-ops.
     */
    private fun restartTor() {
        val v = vault ?: return
        // Never cancel TorManager's OWN one-shot corrupt-state retry. That
        // retry is already a fresh bootstrap on freshly discarded working dirs —
        // precisely what this function would do — so tearing it down mid-flight
        // wastes the discard and risks a second Tor child contending for a
        // DataDirectory lock the dying one has not released yet.
        //
        // DEFER, never drop the intent. The automatic caller
        // ([startRelayStallWatch]) checks the same flag before it gets here and
        // re-arms itself for another full window; the manual caller
        // ([reconnectRelay]) calls startRelayStallWatch() immediately after this
        // returns, so the user's tap is honoured by that watch once the retry
        // resolves — and the "Connecting…" it already reset the UI to is honest,
        // because a genuine fresh bootstrap attempt really is in flight. This
        // guard is the backstop for that manual path; the loop above is the
        // primary.
        if (torManager?.isMidInternalRetry == true) {
            LogBuffer.append("W", "ViewModel",
                "Tor restart deferred — the instance is inside its own corrupt-state retry (rescheduled by the stall watch, not dropped)")
            ConnectionLog.append(ConnectionLog.Kind.STALL, "Tor restart deferred - an internal retry is in flight")
            return
        }
        relayCheckJob?.cancel()
        debugLogPeriodicJob?.cancel()
        controlPollJob?.cancel()
        // The old transport is being torn down on purpose — same signal as a Tor
        // death, so an in-flight send parks instead of spending its retries on it.
        messageManager?.noteTransportLost()
        messageManager = null
        _isRelayReachable.value = false
        // The latch is per-transport: the new Tor session has proven nothing yet.
        _relayHandshakeComplete.value = false
        _unreadPrimeSettled.value = false
        _relayFirstAnswer.value = false
        unreadPrimeCapJob?.cancel()
        connectViaTor(v, forceFresh = true)
    }

    /** Manual "Reconnect" from the relay-stalled contact-list UI: restart Tor and reset
     *  the self-heal escalation for a fresh cycle. */
    fun reconnectRelay() {
        LogBuffer.append("I", "ViewModel", "manual relay reconnect requested")
        ConnectionLog.append(
            ConnectionLog.Kind.STALL,
            "manual reconnect requested",
            ConnectionLog.Code.MANUAL_RECONNECT,
        )
        _relayConnectPhase.value = RelayConnectPhase.Connecting
        // The user just asked for a fresh attempt — show it fresh progress, not the
        // previous attempt's stall hint (the watchdog re-arms in connectViaTor).
        _torBootstrapStalled.value = false
        restartTor()
        startRelayStallWatch()
    }

    /**
     * Monitors the Tor state flow. Once connected, creates the MessageManager.
     */
    private fun startTorMonitor(openedVault: VaultDatabase, tor: TorManager) {
        torMonitorJob?.cancel()
        torMonitorJob = viewModelScope.launch {
            tor.state.collect { state ->
                val stateDesc = when (state) {
                    is TorManager.ConnectionState.Idle -> "Idle"
                    is TorManager.ConnectionState.Bootstrapping -> "Bootstrapping(${state.progress}%)"
                    is TorManager.ConnectionState.Connected -> "Connected(port=${state.socksPort})"
                    is TorManager.ConnectionState.Failed -> "Failed(${state.error})"
                }
                LogBuffer.append("D", "ViewModel", "Tor state → $stateDesc")
                _torState.value = state
                when (state) {
                    is TorManager.ConnectionState.Connected -> {
                        // Connect-telemetry phase split: the FIRST Connected of
                        // this session, set-once (see
                        // ConnectTelemetryRecorder.markTorConnected).
                        telemetry.markTorConnected()
                        // boot (ConnectTelemetry.kt): same FIRST-Connected,
                        // set-once capture, off the Tor-PROCESS anchor instead of
                        // the connect anchor.
                        // The pre-unlock armBootStamp observer has
                        // normally stamped this already, at the instant the
                        // bootstrap actually finished rather than at unlock; this
                        // call still covers the fresh-instance path (no
                        // speculative start) and is a no-op otherwise — FIRST
                        // STAMP WINS, see [firstBootStamp].
                        telemetry.markBootConnected()
                        // Bootstrap landed (possibly long after the watchdog fired) —
                        // retract the stall hint and disarm. AddContactScreen's
                        // LaunchedEffect(torState) re-fires the mint off this same
                        // transition, so a late connect fully self-recovers.
                        torStallJob?.cancel()
                        _torBootstrapStalled.value = false
                        if (messageManager == null) {
                            LogBuffer.append("D", "ViewModel", "creating MessageManager with SOCKS port ${state.socksPort}")
                            wireRelayTransport(openedVault, PlatformHttpClient.torProxy(state.socksPort))
                        }
                    }
                    is TorManager.ConnectionState.Failed -> {
                        LogBuffer.append("E", "ViewModel", "Tor failed: ${state.error}")
                        // Positive evidence the transport is gone: a send still in
                        // flight on this instance stops after its current attempt
                        // and parks for the re-drive instead of burning its budget.
                        messageManager?.noteTransportLost()
                        messageManager = null
                    }
                    is TorManager.ConnectionState.Idle -> {
                        messageManager?.noteTransportLost()
                        messageManager = null
                    }
                    is TorManager.ConnectionState.Bootstrapping -> {
                        // Still bootstrapping — wait.
                    }
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Session loops (control poll, unread prime, relay health, debug log)
    // -----------------------------------------------------------------------

    /**
     * Periodically checks whether the relay server is reachable.
     * Runs on a JITTERED ~8-12s cadence (not a fixed 10s) while a messageManager exists.
     */
    /**
     * Background CONTROL-channel poll: drains every contact's control inbox
     * (group invites/rosters/joins/leaves + inbox announces) on a jittered
     * loop while the vault is unlocked. This is what makes a group appear on
     * EVERY member's device — no conversation needs to be open. Texts are
     * untouched: they live on separate inboxes that are only drained in
     * their conversation (relay-retention of unread messages).
     */
    /**
     * A group conversation surface (the conversation itself, and the group-info
     * screen reached from it — on iOS that is a sheet over the conversation, so it
     * is covered there by construction) entered / left the screen. Feeds the fourth
     * FAST control-cadence condition read by [startControlPoll]; see
     * GroupManager.setGroupConversationForeground. RAM-only, per screen key,
     * cleared with the GroupManager on lock / wipe / teardown. 1:1 conversations
     * never call this.
     */
    fun setGroupConversationForeground(screenKey: String, open: Boolean) {
        groupManager?.setGroupConversationForeground(screenKey, open)
    }

    private fun startControlPoll() {
        // Move freeze (docs/device-move.md D2): while this device is the OLD phone
        // of a move, nothing polls. A single received message advances the Double
        // Ratchet and orphans the new phone's chain, so this gate is not cosmetic.
        // It also has to be HERE and not only at the cancel site: a Tor restart
        // re-enters startTorMonitor's Connected branch, which recreates the
        // MessageManager (the move still needs the transport) and would otherwise
        // restart every loop with it.
        if (moveQuiesced) return
        controlPollJob?.cancel()
        LogBuffer.append("D", "ViewModel", "starting background control-channel polling")
        // Every write of contact / group ids below is gated on this session still
        // being the open one ([sessionStillCurrent]): the sweeps are blocking
        // peeks, so a cancel at lock does not stop one already in flight.
        val pollEpoch = TransportFailedSends.shared.sessionEpoch
        controlPollJob = viewModelScope.launch(Dispatchers.IO) {
            // First sweep soon after unlock (Tor is already up by the time the
            // messageManager exists), then a jittered slow loop.
            delay(3_000L + secureRandomInt(4_000).toLong())
            while (true) {
                var received = false
                // Late-FCM-wake suppression (PushWakeFreshness): the wall clock BEFORE
                // this cycle's first request — the conservative end of the sweep —
                // and whether the control pass returned without throwing.
                val cycleStartedAtMs = System.currentTimeMillis()
                var controlPassOk = false
                try {
                    received = groupManager?.pollAllControls() == true
                    controlPassOk = groupManager != null
                    if (received) _vaultEvents.value += 1
                    // Relay-loss flags are accumulated inside pollControlMessages
                    // above; publish the current set (read on this poll thread) so
                    // the contact list can flag lost contacts for re-pair.
                    messageManager?.let {
                        val lost = it.relayLostContacts()
                        if (sessionStillCurrent(pollEpoch)) _relayLostContacts.value = lost
                    }
                } catch (e: Exception) {
                    LogBuffer.append("W", "ViewModel", "control poll cycle failed: ${e::class.simpleName}")
                }
                // Every cycle, whatever it received: the sweep may have parked a
                // referral offer or group invite for consent.
                if (sessionStillCurrent(pollEpoch)) refreshPendingConsent()
                // Push re-sync: registers any inbound-text inbox minted since
                // the last cycle (pairing, re-pair, referral accept, cap
                // rotation) — this cycle sits downstream of every cap-mutation
                // site, which is why one hook here covers them all (mirrors iOS
                // refreshPushRegistrationIfNeeded). It is also what actually
                // lands the registration after an unlock: the unlock-time call
                // usually returns early because Tor has not finished
                // bootstrapping yet and there is no transport. This is
                // additionally the ONLY thing that re-registers a UnifiedPush
                // endpoint the distributor rotated while the app was closed.
                // [PushRegistrationCoordinator.refreshPushRegistration] dispatches on the persisted level
                // and is a cheap no-op (one prefs read) when notifications are
                // off, which is the default.
                push.refreshPushRegistration()
                // Same cadence, same scope: a non-destructive /peek sweep driving
                // the per-contact unread badge — which since the third (group)
                // inbox pair counts ONLY 1:1 texts, with the legacy subtraction
                // retained solely for peers that still ride the text inbox —
                // plus the per-group unread counts.
                try {
                    groupManager?.let {
                        var peekComplete = false
                        val sweptContactCounts = it.contactUnreadCounts(onSweepFinished = { c -> peekComplete = c })
                        val sweptGroupCounts = it.groupUnreadCounts()
                        if (sessionStillCurrent(pollEpoch)) {
                            _unreadCounts.value = sweptContactCounts
                            _groupUnreadCounts.value = sweptGroupCounts
                        }
                        // Every text + group inbox answered its peek and the control
                        // pass ran: anything the relay pushed a wake for before this
                        // cycle began is now visible in-app, so a late-delivered FCM
                        // wake sent earlier is stale (RunFcmService drops its banner).
                        // Writes only under VENDOR_PUSH, only on a complete sweep;
                        // refused after a wipe (PushWakeFreshness.sweepStampAction).
                        PushWakeFreshness.recordInboxSweep(
                            notificationLevelStore,
                            cycleStartedAtMs,
                            sweepComplete = peekComplete,
                            controlPassRan = controlPassOk,
                        )
                    }
                } catch (e: Exception) {
                    // A lock that lands mid-sweep cancels this job and closes the vault
                    // under the still-running (blocking) sweep — an expected cut, not a
                    // failure, so it is not reported as one.
                    if (!isActive || vault == null) {
                        LogBuffer.append("D", "ViewModel", "unread peek sweep cut short by session teardown")
                    } else {
                        LogBuffer.append("W", "ViewModel", "unread peek sweep failed: ${e::class.simpleName}")
                    }
                }
                // Event-driven cadence (MessageManager.controlPollDelayMs): a fast
                // jittered follow-up while a group-membership convergence round-trip
                // is in flight (recent control send/receive), else the jittered
                // 60–90 s idle (was 25–45 s; a sweep on a
                // 16-contact phone costs 14–16 s, and the control channel's
                // payloads are durable on the relay and redriven on this sweep).
                // Prompt enough for invites to feel live, no fixed beacon for a
                // traffic observer.
                // Converging = we just received control traffic OR resolution is
                // still pending (unresolved group members) — keep polling FAST
                // until the roster lands, not just after our own sends.
                // …OR a group conversation is on screen (the fourth arming condition,
                // GroupManager.setGroupConversationForeground): THIS cycle
                // only, never the persistent window, so the peek-before-drain stays on.
                val converging = received || (groupManager?.hasUnresolvedMembers() == true) ||
                    (groupManager?.isGroupConversationForeground() == true)
                // No-transport fallback: the SAME 60–90 s idle window
                // controlPollDelayMs would return, kept in lockstep with
                // MessageManager.CONTROL_POLL_IDLE_* and with iOS's sibling.
                val delayMs = messageManager?.controlPollDelayMs(converging)
                    ?: (60_000L + secureRandomInt(30_000).toLong())
                // Sleep in 1 s slices and let MessageManager.controlPollIdleWaitShouldEnd
                // cut an IDLE wait short the moment the convergence window opens
                // (the Add-contact scan-back screen arming it, or our own control
                // send from the UI). A FAST wait is never cut, and a quiet idle
                // wait runs its full jittered course. Without this a loop already
                // asleep would ignore the arm for up to 90 s (the two-scan pairing
                // "Almost there" wait). iOS sibling: startControlPoll
                // in AppState.swift.
                var remaining = delayMs
                while (remaining > 0) {
                    val slice = minOf(1_000L, remaining)
                    delay(slice)
                    remaining -= slice
                    // fastWantedNow: opening a group conversation mid-sleep ends an
                    // IDLE wait within one slice (same mechanism as the scan-back arm).
                    if (messageManager?.controlPollIdleWaitShouldEnd(
                            delayMs,
                            fastWantedNow = groupManager?.isGroupConversationForeground() == true,
                        ) == true) break
                }
            }
        }
    }

    /**
     * One-shot parallel /peek sweep fired the instant the transport is wired
     * (Tor Connected, or the dev/no-Tor branch at unlock): races the
     * contact-list "message waiting" dot ahead of [startControlPoll]'s first
     * jittered cycle instead of waiting 3-7s+ for a full sequential sweep.
     * Merge-only per-contact emission (a failed peek gets no callback) — the
     * steady-state whole-map replace above is untouched and still wins once
     * its first cycle lands.
     *
     * It DRAINS the group members' CONTROL inboxes before those peeks (never a text
     * inbox), because a group text rides the sender's 1:1 text inbox and a /peek
     * returns only a count: without the KIND_ACTIVITY notice that drain delivers, a
     * group message lights the SENDER's contact row. The two sweeps can therefore
     * overlap, and GroupManager serialises them — whichever gets there second skips
     * that pass, and a batch the prime took is still reported to [startControlPoll]'s
     * next cycle so the "an applied invite surfaces a group row" nudge is never lost.
     */
    private fun startUnreadPrime() {
        // Move freeze (docs/device-move.md D2): while this device is the OLD phone
        // of a move, nothing polls. A single received message advances the Double
        // Ratchet and orphans the new phone's chain, so this gate is not cosmetic.
        // It also has to be HERE and not only at the cancel site: a Tor restart
        // re-enters startTorMonitor's Connected branch, which recreates the
        // MessageManager (the move still needs the transport) and would otherwise
        // restart every loop with it.
        if (moveQuiesced) {
            // No sweep is coming while a move is frozen — never hold the reveal on it.
            settleUnreadPrime(ConnectReveal.PrimeEvent.SKIPPED)
            return
        }
        unreadPrimeJob?.cancel()
        // No blocked-contact source exists on Android today (contact
        // blocking is iOS-only — see startControlPoll's contactUnreadCounts()
        // call, which also passes none): emptySet() mirrors that exactly.
        // Same session gate as [startControlPoll]: the per-contact callback fires
        // from blocking peeks that a cancel at lock does not interrupt.
        val primeEpoch = TransportFailedSends.shared.sessionEpoch
        unreadPrimeJob = viewModelScope.launch(Dispatchers.IO) {
            try {
                groupManager?.let { gm ->
                    gm.primeUnreadCounts(blockedContactIds = emptySet()) { id, n ->
                        if (!sessionStillCurrent(primeEpoch)) return@primeUnreadCounts
                        _unreadCounts.update { m -> if (n > 0) m + (id to n) else m - id }
                        // The FIRST per-contact result releases the reveal —
                        // the visible list is already correct, and the peeks still
                        // in flight update their own rows in place (merge-only),
                        // exactly as the steady-state sweep does seconds later.
                        // Measured: in 39 of 48 Android timelines the whole pass
                        // had NOT finished when the relay answered, so waiting for
                        // it cost up to the full cap on top of the network wait.
                        // Runs on the prime's I/O worker; [settleUnreadPrime] is
                        // compare-and-set for exactly that reason.
                        settleUnreadPrime(ConnectReveal.PrimeEvent.FIRST_DOT)
                    }
                    // The prime pre-drains group members' CONTROL inboxes (activity
                    // notices) before it peeks, so the per-group counts are already
                    // current here — publish them now instead of waiting for the
                    // control loop's first cycle (3–7 s), so the GROUP dot lights in
                    // the same beat the contact dot is (correctly) withheld.
                    val primedGroupCounts = gm.groupUnreadCounts()
                    if (sessionStillCurrent(primeEpoch)) _groupUnreadCounts.value = primedGroupCounts
                    // The same control pre-drain may have parked an invite or offer
                    // without bumping [vaultEvents]: surface it now, not at the tick.
                    if (sessionStillCurrent(primeEpoch)) refreshPendingConsent()
                }
            } catch (e: Exception) {
                LogBuffer.append("W", "ViewModel", "unread prime sweep failed: ${e::class.simpleName}")
            } finally {
                // Settled on EVERY exit — done, failed or cancelled — so the
                // contact-list reveal ([contactsReady]) never waits on a dead
                // sweep. This is normally already settled by the first
                // dot above; it still carries the passes that emit NOTHING: a
                // vault with no contacts, a pass where every peek failed, a
                // cancelled one. A no-op when the first dot got here first.
                settleUnreadPrime(ConnectReveal.PrimeEvent.PASS_ENDED)
            }
        }
    }

    /**
     * COLD-TRANSPORT NEWNYM RUNG — the CHEAPEST and EARLIEST rung of the self-heal ladder, ahead
     * of [startRelayStallWatch]'s 100 s NEWNYM-then-[restartTor] escalation
     * (which is untouched and still owns every stall AFTER the first relay
     * answer).
     *
     * The phase it targets is INTRODUCTION, not bootstrap: the descriptor lands
     * in ~5 s and an intro/rendezvous circuit is built in 5–15 s, then the
     * introduction point never completes and the session burns 20 s probes on
     * fresh STREAMS over the same wedged circuit until Tor abandons the intro
     * point itself 60–75 s later. `SIGNAL NEWNYM` purges the HS client state and
     * recovered it in < 5 s where it was observed — and it leaves the entry
     * guards alone.
     *
     * EVERY gate lives in commonMain ([MessageManager.earlyNewnymDue] →
     * [MessageManager.shouldFireEarlyNewnym]), so iOS's `AppState` rung fires on
     * exactly the same evidence at exactly the same wall-clock: cold transport
     * only (never after the first round trip), ≥ 35 s from
     * [ConnectTelemetryRecorder.connectStartElapsedMs], ≥ 2 consecutive full-budget PROBE_TIMEOUTs, at
     * most [MessageManager.EARLY_NEWNYM_MAX_FIRES] per session with the second
     * not before ~80 s.
     *
     * Does NOT touch [ConnectTelemetryRecorder.connectStartElapsedMs] / `ConnectTelemetryRecorder.torConnectedElapsedMs`: the
     * connect report must keep measuring launch → first answer, so a self-heal
     * inside that wait stays inside the number it improves. Skipped entirely on
     * the debug/direct path (no [torManager]) and while TorManager is inside its
     * own corrupt-state retry — that circuit set is being rebuilt from scratch,
     * the same guard [startRelayStallWatch]'s rung applies.
     */
    private suspend fun maybeFireEarlyNewnym(mgr: MessageManager) {
        val anchorMs = telemetry.connectStartElapsedMs ?: return
        val tor = torManager ?: return
        if (tor.isMidInternalRetry) return
        val sinceAnchorMs = SystemClock.elapsedRealtime() - anchorMs
        if (!mgr.earlyNewnymDue(sinceAnchorMs, earlyNewnymsFired, coldRungNewnymsFired)) return
        if (!tor.requestNewCircuit()) {
            // Control channel down — nothing to escalate to from here (the
            // stall watch owns the restart); stop trying this session.
            LogBuffer.append("W", "Relay",
                "NEWNYM unavailable (control channel down) — cold-start circuit rotation skipped")
            earlyNewnymsFired = MessageManager.EARLY_NEWNYM_MAX_FIRES
            return
        }
        earlyNewnymsFired++
        coldRungNewnymsFired++
        mgr.noteEarlyNewnymFired()
        LogBuffer.append("W", "Relay",
            "no relay answer yet after ${sinceAnchorMs / 1000}s — requested fresh Tor circuits " +
                "(NEWNYM $earlyNewnymsFired/${MessageManager.EARLY_NEWNYM_MAX_FIRES})")
        // Panel line: the EXISTING NEWNYM phrase, verbatim, numbers only — the
        // iOS sibling emits the identical string so the panel reads the same on
        // both platforms.
        ConnectionLog.append(
            ConnectionLog.Kind.STALL,
            "relay unreachable - requesting fresh circuits (NEWNYM $earlyNewnymsFired/${MessageManager.EARLY_NEWNYM_MAX_FIRES})",
            ConnectionLog.Code.NEWNYM,
        )
    }

    /**
     * WARM-TRANSPORT NEWNYM RUNG — the cheap rung for a session
     * that HAS had a relay answer on this transport and then went dark (the
     * onion half wedged mid-session, Tor still at 100 %). The cold rung
     * ([maybeFireEarlyNewnym]) retires at the first answer, and
     * [startRelayStallWatch] only starts its 100 s clock once the 3-miss
     * hysteresis has flipped `isRelayReachable` (~60–90 s into a warm outage),
     * so the first NEWNYM used to land ~140 s in (A13, 2026-10-07: first probe
     * timeout 14:38:5x, stall-watch NEWNYM 14:41:16 / 14:41:28).
     *
     * EVERY gate lives in commonMain ([MessageManager.warmNewnymDue] →
     * [MessageManager.shouldFireWarmNewnym], budgets in [WarmNewnymLedger]), so
     * iOS's `AppState.maybeFireWarmNewnym` fires on the same evidence: warm
     * transport only (the exact complement of the cold rung), ≥ 3 consecutive
     * full-budget PROBE_TIMEOUTs spanning ≥ 28 s for the first fire; ≥ 2 fresh
     * ones and ≥ 40 s after it for the second; ≤ 2 per dark run, ≤ 6 per hour.
     * On the 8–12 s heartbeat that is the end of the 2nd failed cycle (~50 s into
     * the outage) and ~60 s later. [startRelayStallWatch] (NEWNYM ×2 → Tor
     * restart → Stalled) is untouched and stays the backstop. Skipped while
     * TorManager is inside its own corrupt-state retry, like the other rungs.
     */
    private suspend fun maybeFireWarmNewnym(mgr: MessageManager) {
        val tor = torManager ?: return
        if (tor.isMidInternalRetry) return
        if (!mgr.warmNewnymDue(warmNewnymLedger)) return
        if (!tor.requestNewCircuit()) {
            // Control channel down — the stall watch escalates to a restart;
            // stop asking for the rest of this dark run.
            LogBuffer.append("W", "Relay",
                "NEWNYM unavailable (control channel down) — warm circuit rotation skipped")
            warmNewnymLedger.retireRun()
            return
        }
        mgr.noteWarmNewnymFired(warmNewnymLedger)
        val n = warmNewnymLedger.firesThisRun
        LogBuffer.append("W", "Relay",
            "relay dark for ${mgr.warmDarkForSeconds()}s after answering — requested fresh Tor circuits " +
                "(NEWNYM $n/${MessageManager.WARM_NEWNYM_MAX_PER_RUN}, warm)")
        // Panel line: the shared NEWNYM phrase + the fixed word `warm`, numbers
        // only — iOS emits the identical string. Same Code as the other two
        // NEWNYM rungs; the phrase is what tells them apart.
        ConnectionLog.append(
            ConnectionLog.Kind.STALL,
            "relay unreachable - requesting fresh circuits (NEWNYM $n/${MessageManager.WARM_NEWNYM_MAX_PER_RUN}, warm)",
            ConnectionLog.Code.NEWNYM,
        )
    }

    private fun startRelayCheck() {
        // Move freeze (docs/device-move.md D2): while this device is the OLD phone
        // of a move, nothing polls. A single received message advances the Double
        // Ratchet and orphans the new phone's chain, so this gate is not cosmetic.
        // It also has to be HERE and not only at the cancel site: a Tor restart
        // re-enters startTorMonitor's Connected branch, which recreates the
        // MessageManager (the move still needs the transport) and would otherwise
        // restart every loop with it.
        if (moveQuiesced) return
        relayCheckJob?.cancel()
        LogBuffer.append("D", "ViewModel", "starting periodic relay reachability checks")
        relayCheckJob = viewModelScope.launch {
            // Consecutive failed health checks. isRelayReachable only drops to false
            // after RELAY_UNREACHABLE_STREAK_LIMIT of them (recovers to true on the
            // first success), so a single transient onion-stream failure — common
            // when several devices hammer fresh Tor streams concurrently — no longer
            // instantly flags the relay unreachable. Pure UX-gating hysteresis
            // (nothing security-critical reads isRelayReachable). Parity with iOS.
            var unreachableStreak = 0
            // Wall-clock of the last COUNTED miss. The streak is a TIME-based
            // hysteresis dressed up as a counter: 3 misses was only ever "~24-36 s"
            // because the loop slept 8-12 s between cycles. Now that a COLD
            // transport re-probes every 1-2 s (MessageManager.relayHealthDelayMs),
            // an attempt-counted streak would grey the relay out — and march toward
            // Stalled — in a few SECONDS. Counting at most one miss per
            // MIN_STREAK_BUMP_INTERVAL_MS of real time keeps every downstream
            // threshold at exactly the wall-clock it had before. Identical rule and
            // identical floor to iOS AppState.lastStreakBumpAtMs.
            // 0 = fresh outage, so its first miss counts immediately.
            var lastStreakBumpAtMs = 0L
            while (true) {
                val mgr = messageManager
                val probe = if (mgr != null) {
                    withContext(Dispatchers.IO) {
                        try { mgr.isRelayReachable() } catch (e: Exception) {
                            LogBuffer.append("W", "Relay", "reachability check exception: ${e::class.simpleName}")
                            false
                        }
                    }
                } else false
                // COLD-TRANSPORT NEWNYM RUNG — evaluated BEFORE the
                // hysteresis below, because it is anchored on wall time from
                // [ConnectTelemetryRecorder.connectStartElapsedMs], not on counted misses: a cold cycle
                // costs 2 × 20 s, so a miss-counted rung cannot fire inside the
                // user's first wait at all. Every gate is in commonMain and the
                // whole call is a cheap no-op once the relay has answered once
                // (and on the debug/direct path). Bounded at
                // [MessageManager.EARLY_NEWNYM_MAX_FIRES] per session; the
                // heavier [startRelayStallWatch] ladder is unchanged.
                if (!probe && mgr != null) maybeFireEarlyNewnym(mgr)
                // WARM-TRANSPORT NEWNYM RUNG: the complement of the
                // line above — only a transport that HAS answered — and likewise
                // ahead of the hysteresis, so it never waits for the 3-miss flip
                // that the stall watch's 100 s clock starts from.
                if (!probe && mgr != null) maybeFireWarmNewnym(mgr)
                val effective = if (probe) {
                    unreachableStreak = 0
                    lastStreakBumpAtMs = 0L   // next outage's first miss counts immediately
                    true
                } else {
                    val nowMs = System.currentTimeMillis()
                    if (nowMs - lastStreakBumpAtMs >= MIN_STREAK_BUMP_INTERVAL_MS) {
                        lastStreakBumpAtMs = nowMs
                        unreachableStreak++
                    }
                    // Hold the last value until the streak crosses the threshold.
                    if (unreachableStreak >= RELAY_UNREACHABLE_STREAK_LIMIT) false else _isRelayReachable.value
                }
                if (effective != _isRelayReachable.value) {
                    LogBuffer.append("D", "Relay", "reachable: ${_isRelayReachable.value} → $effective (messageManager=${mgr != null}, missStreak=$unreachableStreak)")
                }
                _isRelayReachable.value = effective
                // The first-answer latch (`_relayFirstAnswer`, C7) only bridges the
                // gap between the prime's first /peek and this probe's verdict; once
                // the hysteresis has latched the relay UNREACHABLE it must not keep
                // `contactsReady` (lit runestone, relay-gated rows) alive through the
                // outage. iOS sibling: AppState.recomputeContactsReady.
                if (!effective) _relayFirstAnswer.value = false
                if (effective) relayAnsweredThisSession = true
                // Reveal backstop for [contactsReady]: the relay has answered but the
                // unread prime has not settled — a wedged peek must not hold the
                // contacts hostage. Counted from the first answer, not from the prime's
                // start (the prime is fired at Tor Connected, often long before).
                if (effective && !_unreadPrimeSettled.value && unreadPrimeCapJob?.isActive != true) {
                    unreadPrimeCapJob = viewModelScope.launch {
                        delay(UNREAD_PRIME_REVEAL_CAP_MS)
                        // The PRIME_CAP line and the flip both belong to
                        // [settleUnreadPrime]: it re-reads the flag, so a cap that
                        // expires after the prime already settled narrates nothing.
                        settleUnreadPrime(ConnectReveal.PrimeEvent.CAP)
                    }
                }
                // Honest "connected" signal for the UI: the first COMPLETED onion
                // round-trip on this transport, not Tor's bootstrap (see
                // relayHandshakeComplete). Read from the manager rather than from
                // `probe` so the pre-mint warm-gate's successful probe also counts.
                val handshook = mgr?.hasCompletedRelayRoundTrip() == true
                if (handshook && !_relayHandshakeComplete.value) {
                    LogBuffer.append("I", "Relay", "first onion round-trip completed — relay handshake done")
                    ConnectionLog.append(
                        ConnectionLog.Kind.RELAY,
                        "first onion round-trip completed",
                        ConnectionLog.Code.FIRST_ROUNDTRIP,
                    )
                    // Start the push re-registration pass NOW instead of waiting for the
                    // first control-poll cycle (~30 s later): the unlock-time call returned
                    // early (no Tor transport yet), and in a short session the pass would
                    // otherwise run after the user backgrounded. Same gate as the
                    // vault-open call; a concurrent pass is skipped by
                    // withPushRefreshTurn(awaitTurn = false).
                    if (isBackgroundNotificationsEnabled() && !moveQuiesced) {
                        viewModelScope.launch(Dispatchers.IO) {
                            push.refreshPushRegistration()
                        }
                    }
                }
                _relayHandshakeComplete.value = handshook
                if (handshook) relayAnsweredThisSession = true
                // In-app update nudge.
                // newerRelayVersion() is a RAM latch MessageManager sets from the
                // FIRST successful (code > 0) relay response of the session — it
                // stays null until one lands, so this is a no-op every tick until
                // then. updateNudgeEvaluated bounds the vault read/write to once
                // per ViewModel instance even though this loop polls every 8-12s.
                if (!updateNudgeEvaluated) {
                    val advertised = mgr?.newerRelayVersion()?.let { parseAppVersion(it) }
                    val openVault = vault
                    if (advertised != null && openVault != null) {
                        // Vault I/O — never on Main, same offload as the
                        // reachability probe above.
                        val shouldShow = withContext(Dispatchers.IO) {
                            val show = shouldShowUpdateNudge(openVault, advertised)
                            // WRITE ON SHOW, before the dialog renders: a
                            // force-quit or onStop teardown between now and the
                            // user's tap must not re-nag on the next foreground.
                            if (show) markUpdateNudgeShown(openVault, advertised)
                            show
                        }
                        // Latch only AFTER the suspension point: a relayCheckJob
                        // cancellation mid-withContext (restartTor's self-heal)
                        // must leave the evaluation re-runnable on the next loop,
                        // not silently disable the nudge for the whole session.
                        updateNudgeEvaluated = true
                        if (shouldShow) {
                            _showUpdateNudge.value = advertised.render()
                        }
                    }
                }
                // In-app store-review nudge (ReviewPromptPolicy.kt, commonMain
                // — the pure decision function; everything here is orchestration).
                // Same "at most once per session" shape as the update nudge
                // above, deliberately NOT nested inside its `if` — a session
                // that never sees an advertised update must still get its one
                // review check. Placed right AFTER it so the ordering check
                // below reads `_showUpdateNudge` in its fully settled state for
                // THIS tick (the update-nudge write above is an inline suspend,
                // not detached, so there is no race there — unlike iOS's
                // Task.detached sibling). Fires on the FIRST tick of this loop
                // (~8-12s post-unlock), not at unlock itself, so the relay-
                // driven, asynchronous update nudge has had a real chance to
                // decide before this checks it.
                if (!reviewPromptEvaluated) {
                    reviewPromptEvaluated = true
                    // Ordering rule: never in the same session as the push
                    // prompt or the update nudge — both are RuneDialogs the
                    // native OS review sheet would otherwise stack awkwardly on
                    // top of. If either is up right now, this whole session is
                    // skipped (the latch above means it is not retried later
                    // this session); the NEXT unlock is a fresh ViewModel and
                    // gets a fresh, unbiased check.
                    if (!_showPushPrompt.value && _showUpdateNudge.value == null) {
                        val openVault = vault
                        if (openVault != null) {
                            withContext(Dispatchers.IO) {
                                // Count-only read — never retain the decrypted
                                // shared secrets past this line, same 4D-1
                                // discipline ContactListScreen's own projection
                                // uses for the identical getAllContacts() call.
                                val records = openVault.getAllContacts()
                                val contactCount = records.size
                                records.forEach { it.sharedSecret.secureWipe() }
                                // The
                                // counters are read from the vault's `_meta`
                                // singleton now, not plaintext SecurePrefs —
                                // see ReviewPromptPolicy.kt's vault-store section.
                                val state = readReviewPromptState(openVault)
                                val shouldShow = ReviewPromptPolicy.shouldPrompt(
                                    now = System.currentTimeMillis(),
                                    firstUnlockAt = state.firstUnlockAt,
                                    unlockCount = state.unlockCount,
                                    contactCount = contactCount,
                                    alreadyPrompted = state.alreadyPrompted,
                                    isDebugBuild = isDebugBuildPublic(),
                                )
                                if (shouldShow) {
                                    // WRITE ON ASK, before the flow launches —
                                    // see markReviewPromptShown's kdoc.
                                    markReviewPromptShown(openVault)
                                    _requestReviewFlow.value = true
                                    reviewSheetRequestedThisSession = true
                                }
                            }
                        }
                    }
                }
                // Cadence decided in commonMain (MessageManager.relayHealthDelayMs)
                // so both platforms schedule identically: the jittered 8-12 s
                // heartbeat once this transport has completed an onion round-trip
                // (a fixed 10.000 s period would be a traffic-analysis beacon
                // for the relay / guard node), and a bounded 1-2 s retry until then,
                // so a cold start spends its first minute rotating onto fresh Tor
                // streams instead of sleeping between them. No transport to probe
                // (mgr == null, re-wiring) ⇒ nothing was retried, so it keeps the
                // steady-state heartbeat.
                val nextDelayMs = mgr?.relayHealthDelayMs()
                    ?: (8_000L + secureRandomInt(4_000).toLong())
                delay(nextDelayMs)
            }
        }
    }

    /**
     * Debug mode (Settings → Debug mode): the periodic [DebugLogUploader]
     * cursor tick, roughly once a second per [DebugLogUploader]'s own design
     * (cursor-based + incremental, so an idle tick with nothing new is a
     * cheap no-op) — called from the SAME sites as [startRelayCheck] (see its
     * callers), so it shares that job's session lifetime exactly
     * (paused/resumed with a move freeze, restarted on a Tor reconnect).
     * Checks [debugMode] on every tick rather than being started/stopped by
     * the toggle itself, so flipping it mid-session takes effect on the very
     * next tick with no extra wiring at the toggle site; likewise a
     * live-but-unset [messageManager] (mid Tor-reconnect) just skips a tick
     * rather than failing. No try/catch — [DebugLogUploader.flush] is
     * documented never to throw, and this loop's own cancellation (every
     * cancel site pairs with [relayCheckJob]'s) must propagate normally.
     */
    private fun startDebugLogPeriodicUpload() {
        debugLogPeriodicJob?.cancel()
        debugLogPeriodicJob = viewModelScope.launch(Dispatchers.IO) {
            while (true) {
                delay(DEBUG_LOG_PERIODIC_INTERVAL_MS)
                if (!_debugMode.value) continue
                val mm = messageManager ?: continue
                DebugLogUploader.flush(
                    mm.relayTransport(),
                    ConnectTelemetry.PLATFORM_ANDROID,
                    BuildConfig.VERSION_NAME,
                    DebugLogUploader.REASON_PERIODIC,
                )
            }
        }
    }

    // -----------------------------------------------------------------------
    // In-band inbox announce (instant-QR pairing)
    // -----------------------------------------------------------------------

    /**
     * Delivers our own (inboxId, writeCap) to a freshly paired contact whose
     * QR we scanned in full while they only saw our secret-only code. Runs on
     * the ViewModel scope so it survives leaving the AddContact screen, with
     * jittered retries. Receiver-side application is idempotent.
     */
    fun announceInbox(
        contactId: String,
        myInboxId: String,
        peerWriteCap: String,
        myCtlInboxId: String? = null,
        peerCtlWriteCap: String? = null,
        myGrpInboxId: String? = null,
        peerGrpWriteCap: String? = null,
    ) {
        viewModelScope.launch(Dispatchers.IO) {
            for (attempt in 1..3) {
                val ok = try {
                    messageManager?.sendInboxAnnounce(
                        contactId, myInboxId, peerWriteCap, myCtlInboxId, peerCtlWriteCap,
                        myGrpInboxId, peerGrpWriteCap,
                    ) ?: false
                } catch (_: Exception) { false }
                if (ok) {
                    LogBuffer.append("D", "ViewModel", "inbox announce delivered")
                    return@launch
                }
                if (attempt < 3) {
                    delay(2_000L + secureRandomInt(3_000).toLong())
                }
            }
            // The peer stays in "awaiting inbox" — honest UI state; the user
            // can re-pair if this persists.
            LogBuffer.append("W", "ViewModel", "inbox announce failed after 3 attempts")
        }
    }

    // -----------------------------------------------------------------------
    // Background notification level
    // -----------------------------------------------------------------------

    // The persisted NotificationLevel (vendor-push tier) is the single source of
    // truth for "is background notification on": read via
    // [isBackgroundNotificationsEnabled], written at toggle time by
    // [setBackgroundNotificationsEnabledAwaiting]. It lives in its own plaintext
    // prefs file, NOT vault_selector_prefs (credential verifiers / wrapped DB
    // keys), because it is non-secret and must be readable pre-unlock:
    // RunFcmService (no ViewModel or vault) reads the same file through its own
    // KeyValueStore(app, NOTIFICATION_LEVEL_PREFS_NAME). Push registration reads
    // its inbox refs straight from the open vault ([allPushableInboxes], text AND
    // inbound control); no inbox id or read capability is kept outside the vault.
    private val notificationLevelStore = KeyValueStore(application, NOTIFICATION_LEVEL_PREFS_NAME)

    /**
     * Push registration (toggle, per-session bookkeeping, registration passes,
     * opt-out ladder, dereg sweep). Declared DIRECTLY BELOW
     * [notificationLevelStore] on purpose: Kotlin runs property initializers in
     * text order, so a declaration above it would capture a null store and NPE at
     * the first prefs read. [cryptoProvider] and [networkRestoreEpoch] are
     * declared further up, and `init {}` calls no push member.
     */
    private val push = PushRegistrationCoordinator(
        app = application,
        scope = viewModelScope,
        notificationLevelStore = notificationLevelStore,
        cryptoProvider = cryptoProvider,
        vaultProvider = { vault },
        messageManagerProvider = { messageManager },
        relayHttp = { currentRelayHttp() },
        networkRestoreEpoch = networkRestoreEpoch,
    )

    /** Facade over [PushRegistrationCoordinator.currentNotificationLevel], the
     *  PROVEN level (device-key-authenticated consent), not the plaintext selector. */
    fun currentNotificationLevel(): NotificationLevel = push.currentNotificationLevel()

    /** Facade over [PushRegistrationCoordinator.isBackgroundNotificationsEnabled]. */
    fun isBackgroundNotificationsEnabled(): Boolean = push.isBackgroundNotificationsEnabled()

    fun setBackgroundNotificationsEnabled(enabled: Boolean) {
        // Fire-and-forget wrapper kept for any caller that can't await (and as
        // the historical entry point) — routes through the awaitable variant
        // below so there's a single implementation of the enable/disable
        // logic. The Settings modal itself now calls
        // [setBackgroundNotificationsEnabledAwaiting] directly so it can show
        // a spinner and revert the switch on failure.
        //
        // Boolean-shaped by contract, so it has to pick a transport: whichever
        // one this device can actually deliver on. Same precedence as the
        // modal — vendor push first (it needs no extra app), UnifiedPush only
        // where there is no Play Services.
        val app = getApplication<Application>()
        val level = when {
            !enabled -> NotificationLevel.OFF
            VendorPush.isAvailable(app) -> NotificationLevel.VENDOR_PUSH
            else -> NotificationLevel.UNIFIED_PUSH
        }
        viewModelScope.launch(Dispatchers.IO) {
            setBackgroundNotificationsEnabledAwaiting(level)
        }
    }

    /** Why the last enable attempt failed; see
     *  [PushRegistrationCoordinator.lastPushEnableFailure]. */
    val lastPushEnableFailure: PushEnableFailure?
        get() = push.lastPushEnableFailure

    /** Facade over [PushRegistrationCoordinator.setBackgroundNotificationsEnabledAwaiting]
     *  (NotificationSettingsModal awaits it behind its spinner). */
    suspend fun setBackgroundNotificationsEnabledAwaiting(level: NotificationLevel): Boolean =
        push.setBackgroundNotificationsEnabledAwaiting(level)

    /**
     * The relay HTTP transport CURRENT to this session — mirrors the exact
     * client construction startTorMonitor/onVaultOpened use for
     * messageManager. Deliberately never reuses messageManager's own client
     * (private there): it may be null or mid-reconnect the instant this
     * runs — same reasoning as iOS registerRefs's fresh-client-per-call.
     * Null means "no live transport right now" (Tor still bootstrapping, or
     * a misconfigured release relay) — callers treat that as "try again next
     * cycle", never an error.
     */
    private fun currentRelayHttp(): RelayHttp? = when {
        RelayConfig.BASE_URL.isEmpty() -> null
        // External SOCKS proxy mode FIRST: `_torState.Connected` then carries the
        // PROXY's port, and `torProxy(port)` would dial 127.0.0.1 at it — the
        // wrong host for a LAN proxy, and the embedded-Tor redirect table for any.
        externalProxyMode -> {
            val cfg = externalProxy
            if (cfg != null && _torState.value is TorManager.ConnectionState.Connected) {
                PlatformHttpClient.socksProxy(cfg.host, cfg.port).asRelayHttp()
            } else null
        }
        RelayConfig.isTorRequired -> {
            val state = _torState.value
            if (state is TorManager.ConnectionState.Connected) {
                PlatformHttpClient.torProxy(state.socksPort).asRelayHttp()
            } else null
        }
        BuildConfig.DEBUG -> PlatformHttpClient.direct().asRelayHttp()
        else -> null
    }

    // -----------------------------------------------------------------------
    // Move to new device — the MoveSessionControl body (docs/device-move.md)
    //
    // Every function here is what AndroidMoveSessionControl delegates to. They
    // live in the ViewModel because they drive ITS jobs, ITS transport and ITS
    // push bookkeeping ([push]); the interface implementation is a separate file
    // only so the wipe path's NON-SUSPEND unregister stays unambiguous
    // (PushSessionBookkeepingRaceSourceTest — the wipe calls
    // PushRegistrationCoordinator.unregisterPushBestEffort synchronously).
    // -----------------------------------------------------------------------

    /**
     * Step (a) of the export: drop every relay push registration this device
     * holds. Push logic, so it lives in the coordinator
     * ([PushRegistrationCoordinator.unregisterForMoveAwaiting], which carries the
     * reasoning); this is the MoveSessionControl delegate's entry point.
     */
    internal suspend fun moveUnregisterPushAwaiting() = push.unregisterForMoveAwaiting()

    /**
     * Step (b)'s session half: stop everything that touches CONTACTS, keep the
     * transport.
     *
     * What stops: the control sweep, the unread prime, the relay health check and
     * both self-heal watchdogs. That is the fork-prevention part — a single
     * control poll RECEIVES, which advances the Double Ratchet and orphans the new
     * phone's chain (docs/device-move.md fact 5). The commonMain freeze gate
     * (`createSessionManagers`) already refuses the transport to GroupManager /
     * ReferralManager the moment `mig_frozen` is written, which is BEFORE this
     * runs; this is the loop-level half of the same decision, and it is what stops
     * the push re-registration the control poll would otherwise redo.
     *
     * What deliberately does NOT stop: Tor and the MessageManager. The transfer
     * inbox belongs to no contact and touches no ratchet, and the upload, the 10 s
     * peek, the cancel-DELETE and a later re-issue all need a live SOCKS client.
     * `MoveManager.takeTransport` documents the same contract from its side.
     */
    internal suspend fun moveQuiesceSession() {
        withContext(Dispatchers.Main.immediate) {
            if (moveQuiesced) return@withContext
            moveQuiesced = true
            LogBuffer.append("W", "Move", "quiescing session (move export) — Tor and the transport stay up")
            controlPollJob?.cancel()
            unreadPrimeJob?.cancel()
            relayCheckJob?.cancel()
            debugLogPeriodicJob?.cancel()
            relayStallJob?.cancel()
            pushPromptJob?.cancel()
            telemetry.cancelConnectJobs()
            torStallJob?.cancel()
        }
    }

    /**
     * The inverse, used only by a successful cancel (`MoveManager.unfreeze`) — by
     * then `mig_frozen` is already gone, so the commonMain gate hands the managers
     * their transport back and these loops have work to do again. Idempotent.
     */
    internal suspend fun moveResumeSession() {
        withContext(Dispatchers.Main.immediate) {
            if (!moveQuiesced) return@withContext
            moveQuiesced = false
            val db = vault ?: return@withContext
            LogBuffer.append("D", "Move", "resuming session after a cancelled move")
            if (messageManager != null) {
                startRelayCheck()
                startDebugLogPeriodicUpload()
                startControlPoll()
                startUnreadPrime()
                if (RelayConfig.isTorRequired || externalProxyMode) startRelayStallWatch()
            } else if (RelayConfig.isTorRequired || externalProxyMode) {
                // (External proxy mode: connectViaTor diverts to the proxy.)
                // Tor died while we were frozen: connectViaTor ADOPTS a live
                // instance and only bootstraps a fresh one if there is none.
                connectViaTor(db)
                startRelayStallWatch()
            }
        }
    }

    /**
     * The live [MoveTransport], or null when there is nothing to talk to. Null is
     * never an error to the caller — `MoveManager` treats it as
     * `RELAY_UNREACHABLE` (retryable) and, on the cancel path, as "I cannot prove
     * the bundle is undrained", which refuses rather than unfreezing.
     *
     * A fresh wrapper per call, deliberately: `RelayMoveTransport` is a thin
     * stateless facade over whichever MessageManager is current, so a Tor
     * self-heal that replaced the SOCKS port is picked up on the next call instead
     * of dialing a dead one (the same reasoning as [currentRelayHttp]).
     */
    internal fun moveTransport(): MoveTransport? {
        if (vault == null) return null
        val mm = messageManager ?: return null
        // Release + `.onion` relay ⇒ Tor or nothing (the clearnet fail-closed rule).
        if ((RelayConfig.isTorRequired || externalProxyMode) && _torState.value !is TorManager.ConnectionState.Connected) return null
        return RelayMoveTransport(mm)
    }

    // --- UI-facing move operations (all ViewModel-scoped: a rotation recreates
    // --- the Activity, and neither an upload nor an import may die with it).

    /**
     * Old phone: explain → Continue. Drives `moveManager.exportState`.
     *
     * The bounded transport wait happens HERE, before `beginExport`, and that is
     * the point: the freeze is persisted before the mint, so starting while Tor
     * is still bootstrapping would stop the phone and only then fail. Nothing is
     * written while we wait, so a user who backs out has lost nothing.
     */
    /**
     * The export needs a FRESH credential check (and, on a
     * Lever B vault, the strong biometric). Mirrors the change-PIN gate: the guess
     * counts against the daily change-PIN abuse budget first, the cap wipes
     * ([performEmergencyWipe] is the caller's job on [MoveExportAuth.Outcome.WIPE]).
     * OK grants the single-use token [MoveManager.beginExport] consumes. Heavy
     * (KDF + possible biometric prompt) — runs on IO, suspends the caller.
     */
    suspend fun verifyMoveExportAuth(credential: String): MoveExportAuth.Outcome =
        withContext(Dispatchers.IO) {
            MoveExportAuth.verifyAndGrant(credential, vaultSelector, changePinAttempts, moveExportAuthGate)
        }

    fun beginMoveExport() {
        if (moveOpJob?.isActive == true) return
        moveOpJob = viewModelScope.launch {
            awaitMoveTransport()
            moveManagerImpl.beginExport()
        }
    }

    /** Old phone, frozen or failed: a fresh bundle under a fresh code. */
    fun reissueMoveExport() {
        if (moveOpJob?.isActive == true) return
        moveOpJob = viewModelScope.launch {
            awaitMoveTransport()
            moveManagerImpl.reissueExport()
        }
    }

    /**
     * Waits (bounded) for a live transport. Returns either way — the manager's own
     * null-transport handling is the backstop, and a caller must never hang
     * forever on a network that is simply not coming back.
     */
    private suspend fun awaitMoveTransport() {
        val deadline = SystemClock.elapsedRealtime() + MOVE_IMPORT_TRANSPORT_WAIT_MS
        while (moveTransport() == null && SystemClock.elapsedRealtime() < deadline) {
            delay(1_000L)
        }
    }

    /** The 10 s `peek` while the code is on screen. Its own job — a slow peek must
     *  never make the cancel button look dead (MoveManager serialises internally). */
    fun refreshMoveTransferState() {
        if (movePollJob?.isActive == true) return
        movePollJob = viewModelScope.launch { moveManagerImpl.refreshTransferState() }
    }


    /** Old phone: cancel + unfreeze. `false` = refused (already drained, or the
     *  relay could not be asked) — the caller says so and hides the button. */
    fun cancelMoveExport(onResult: (Boolean) -> Unit) {
        if (moveOpJob?.isActive == true) {
            onResult(false)
            return
        }
        moveOpJob = viewModelScope.launch {
            val ok = moveManagerImpl.cancelExport()
            onResult(ok)
        }
    }

    /**
     * New phone: run the import for the handle scanned during setup, right after
     * the first unlock. Idempotent per state — a re-entry while one is running is
     * dropped, and `MoveManager` refuses a second import against `mig_imported`
     * anyway.
     *
     * The transport wait is the non-obvious part: this fires seconds after a fresh
     * provision, when Tor is typically still bootstrapping, and
     * `importFromHandle` (correctly) answers `RELAY_UNREACHABLE` the instant it is
     * handed a null transport. Waiting here — showing FETCHING, which is honest —
     * turns "failed before the network was up" into "took a moment".
     */
    fun startPendingMoveImport() {
        val handle = pendingMoveHandle ?: return
        if (_moveImportState.value is MoveImportUiState.Running) return
        if (moveOpJob?.isActive == true) return
        _moveImportState.value = MoveImportUiState.Running(MoveImportStep.FETCHING)
        moveOpJob = viewModelScope.launch {
            val result = try {
                awaitMoveTransport()
                moveManagerImpl.importFromHandle(handle) { step ->
                    _moveImportState.value = MoveImportUiState.Running(step)
                }
            } catch (e: CancellationException) {
                // Cancelled by a teardown (lock / wipe cancel moveOpJob) or by
                // MoveManager rethrowing one: never leave the screen on "Running",
                // or the `is Running` early return above refuses every later start
                // in a VM that lockForReauth keeps alive. Idle, not Failed: the same
                // teardown scrubbed pendingMoveHandle, and MoveFromDeviceScreen's
                // `Idle && pendingMoveHandle == null` branch then leaves to contacts
                // (a Retry would have nothing to retry with); a cancel that keeps the
                // handle restarts from Idle. RAM-only, no identifier, so this write
                // landing after the erase is harmless. Must come BEFORE the
                // Exception catch (CancellationException is an Exception) and must
                // rethrow.
                if (_moveImportState.value is MoveImportUiState.Running) {
                    _moveImportState.value = MoveImportUiState.Idle
                }
                throw e
            } catch (e: Exception) {
                // Any other throw out of the transport wait or the import maps to
                // the import's own failure, so the screen offers Retry instead of
                // spinning on "Running" forever.
                MoveImportResult.Failure(MoveError.IMPORT_FAILED)
            }
            _moveImportState.value = when (result) {
                is MoveImportResult.Success -> {
                    // Drop the read cap + one-time code the moment they are spent.
                    pendingMoveHandle = null
                    MoveImportUiState.Done(result.contacts, result.groups)
                }
                is MoveImportResult.Failure -> MoveImportUiState.Failed(result.error)
            }
        }
    }

    /** "Continue without it" on a failed import: keep the freshly provisioned
     *  vault, forget the transfer. The old phone is untouched and still frozen. */
    fun abandonPendingMoveImport() {
        pendingMoveHandle = null
        _moveImportState.value = MoveImportUiState.Idle
    }

    /**
     * Drops the RAM-only one-time code (Ready → FrozenNoCode, and Preparing →
     * Idle for an export the teardown just cancelled) when the move screen leaves
     * the foreground. Android tears the whole session down on background anyway
     * ([onCleared]), so this only matters for the ON_STOP that races it and for
     * the in-process [lockForReauth] — but it is the same discipline as
     * `messageManager.scrubInMemory()` and it mirrors the iOS `.background`
     * handler exactly. Both teardown paths cancel [moveOpJob]/[movePollJob]
     * BEFORE reaching this; the cancel is cooperative, so MoveManager
     * re-checks the vault before it ever publishes a code.
     */
    fun scrubMoveSecrets() {
        if (moveManagerDelegate.isInitialized()) moveManagerImpl.scrubInMemory()
    }

    // -----------------------------------------------------------------------
    // Emergency wipe
    // -----------------------------------------------------------------------

    /**
     * @param deniable arms [ProcessWipeCover] — the process-lifetime black cover
     *   that MainActivity.onCreate honours — so an Activity recreation (rotation:
     *   onStop skips finishAndRemoveTask on a config change) cannot reveal app
     *   content after a wipe the user triggered mid-session. Pass `false` for a
     *   wipe requested in order to START OVER (the orphaned-vault
     *   "Erase" on the unlock screen), which must land on setup, not on a black
     *   screen. Exact parity with iOS `AppState.emergencyWipe(deniable:)` /
     *   `eraseOrphanedVault()`.
     *
     *   NOT the same thing as [ProcessWipeLatch], which WipeRoutine arms on every
     *   wipe — including the launch-time ones that deliberately fall through to
     *   setup. Gating the cover on that latch was an earlier regression.
     */
    fun performEmergencyWipe(deniable: Boolean = true) {
        LogBuffer.append("W", "ViewModel", "EMERGENCY WIPE triggered (deniable=$deniable)")
        val app = getApplication<Application>()
        // Arm BEFORE the destruction, not after: this wipe tears down Tor, closes
        // the vault and does synchronous file I/O on the main thread, any of which
        // can be interrupted (process death, an OEM watchdog) — and an interrupted
        // wipe that left the cover un-armed would put the app back on an
        // interactive screen. Arming first is free (one in-RAM flag, no I/O) and
        // fails toward deniability. Same reasoning as ProcessWipeLatch.latch().
        if (deniable) ProcessWipeCover.arm()
        // See [wipedThisSession]'s kdoc: the reactive, same-composition twin
        // of ProcessWipeCover.arm() above — armed on the IDENTICAL gate, kept
        // as its own statement (not folded into one `if` block) so
        // ProcessWipeCoverTest's source-level pin of the exact
        // "if (deniable) ProcessWipeCover.arm()" line survives untouched.
        if (deniable) _wipedThisSession.value = true

        // Relay-side push unregister — best-effort, NON-BLOCKING, fired
        // while the vault + relay transport are STILL alive (mirrors iOS
        // AppState.unregisterCurrentInboxesBestEffort/emergencyWipe
        // ordering). MUST run before vault.close()/torManager.stop() below —
        // after those there is neither a vault to read refs from nor a
        // transport to send the DELETE over. A miss here is harmless: the
        // token stops mattering the moment the inbox itself is gone.
        //
        // Covers BOTH transports in the one pass — `DELETE /inbox/{id}/push` is
        // platform-agnostic (see [PushRegistrationCoordinator.unregisterPushBestEffort]). The LOCAL halves
        // of the teardown (Firebase identity; the UnifiedPush distributor
        // registration, connector database and Keystore alias) are not
        // duplicated here on purpose: [WipeRoutine.wipePersistentState], called
        // a few lines below, owns that list for every wipe entry point, and a
        // second copy here is exactly the drift class hand-maintained
        // purge lists have shown before.
        run {
            // GATED on "this device ever had push rows to drop", evaluated HERE,
            // while the vault is still open (the proven level needs it): opted in
            // now, or an opt-out whose relay DELETEs are still owed. WHY: on a
            // device that never enabled push, a `DELETE /inbox/{id}/push` can only
            // come from a wipe (or a move export), so an ungated burst tells the
            // relay "this device wiped at T" for no benefit — there are no rows to
            // remove. iOS parity: AppState.swift `if pushEnabled {
            // unregisterCurrentInboxesBestEffort() }`. An unreadable answer fails
            // toward NOT sending: a skipped row is inert (the local identities are
            // destroyed by WipeRoutine below either way). The call itself stays
            // unconditional so the session bookkeeping is still cleared.
            val hadPushRows = try {
                push.isBackgroundNotificationsEnabled() || SecurePrefs.isPushDeregPending(app)
            } catch (_: Exception) { false }
            val refs: List<InboundInboxRef> = if (!hadPushRows) emptyList() else try {
                // Same surface as registration (allPushableInboxes) — a wipe
                // must clean up every inbox the relay might still be push-registered
                // for, control included.
                vault?.let { allPushableInboxes(it) }
            } catch (_: Exception) { null } ?: emptyList()
            push.unregisterPushBestEffort(refs, currentRelayHttp())
        }

        // Stop every session job, then close the vault + drop the unwrapped Tink
        // keyset from RAM BEFORE unlinking the DB file, so we never delete a file
        // out from under an open SQLCipher handle (cleaner than delete-then-close; the
        // key is crypto-erased either way). This RAM teardown mirrors lockSession and
        // is required regardless of order: without it the SQLCipher page key and the
        // AES keyset survive the wipe in the live process's RAM, recoverable by a RAM
        // acquisition of a device seized right after a panic wipe.
        //
        // ONE cancel for every session job ([SessionJobs]): the pollers, the prime
        // and its reveal cap, the push prompt, the pre-unlock warm-up (a wipe may land
        // on the PIN screen while it is still parked, and the wrong-credential budget
        // wipe is exactly that case), the external-proxy check, the stall watchdog,
        // the transport re-drive, both move jobs, AND the Tor monitor + in-flight
        // start. All of it goes BEFORE vault.close(), as owner-approved after the
        // iteration-3 review (R5 section 2, items 1 and 2):
        //  - the Tor monitor and the prime cap are Main-confined, so they could not
        //    run inside this non-suspending body anyway (no observable change);
        //  - cancelling the in-flight `tor.start()` only runs
        //    TorManager.onAttemptCancelled (destroys a bootstrapping child, writes
        //    no state, file or network), so the child no longer tails/recreates the
        //    Tor dir while WipeRoutine deletes it. stopAndDiscardState() below
        //    stays the post-erase second pass;
        //  - the in-flight sends (IO) no longer start a backoff retry against a
        //    vault being erased; a cancel writes nothing (no finally; the
        //    completion handler only drops the job from the set).
        // An in-flight move export used to survive the wipe and publish
        // Ready(handle), the one-time code plus the read capability, after
        // scrubMoveSecrets() below had run. Cancellation is COOPERATIVE, which is
        // why MoveManager additionally re-checks the vault before publishing Ready.
        // iOS sibling: IosAppController.emergencyWipe's
        // `moveScope.coroutineContext.cancelChildren()`. The prime's late callback
        // is kept out of _unreadCounts by the session-epoch check in
        // startUnreadPrime ([sessionStillCurrent]), not by this cancel.
        // Cancellation itself performs no I/O, so it can neither delay the
        // crypto-erase below nor re-create residue after it.
        sessionJobs.cancelAll()
        telemetry.cancelConnectJobs()
        telemetry.cancelBootStamp()
        cancelInFlightSends()
        // The stall watchdog was cancelled above; retract its hint too, so nothing
        // shows on the post-wipe screen. A fresh unlock re-arms it.
        _torBootstrapStalled.value = false
        try { vault?.close() } catch (_: Exception) { /* best-effort */ }
        try { cryptoProvider.wipeKey() } catch (_: Exception) { /* best-effort */ }

        // Crypto-erase (persisted key material) + delete all persisted vault material.
        // WipeRoutine erases the key BEFORE the file, so a crash mid-wipe
        // still leaves the DB unrecoverable.
        WipeRoutine.wipePersistentState(app)

        vault = null
        // The ONE other function (besides lockSession) that
        // nulls `vault` MUST also clear this — a stale deadline left armed here
        // survives to the watchdog's next tick, which calls lockForReauth() on
        // an already-wiped session; lockForReauth's own vault==null guard is
        // belt-and-braces, this is the root-cause fix. Mirrors lockSession's
        // `reauthDeadlineElapsedMs = null` (its kdoc: "a locked/PIN-screen state
        // must never carry a stale one").
        reauthDeadlineElapsedMs = null
        messageManager?.scrubInMemory()   // scrub BEFORE dropping the ref (was dead: ran after null)
        messageManager = null
        // The parked-send ledger is process-wide and is written EXACTLY when
        // `messageManager` is null (sendMessageInBackground's no-transport branch),
        // so the `?.scrubInMemory()` above cannot be its only clear: a wipe taken
        // while Tor was down would leave plaintexts parked in RAM past the erase.
        // Unconditional, independent of the manager (iOS: IosAppController).
        // endSession() also bumps the epoch, so a send still blocked in its POST
        // cannot re-park when Tor's stop below fails it; repeated as the very
        // last step, after the Tor stop. (The in-flight sends were cancelled with
        // the session jobs, before the vault close.)
        TransportFailedSends.shared.endSession()
        // Scrub decrypted group-message/invite buffers + the ephemeral referral
        // X25519 private key from RAM BEFORE dropping the references — nulling alone
        // leaves them resident in the deliberately-kept-alive process.
        groupManager?.scrubInMemory()
        referralManager?.scrubInMemory()
        groupManager = null
        referralManager = null
        maximumShield = null
        _isRelayReachable.value = false
        _relayHandshakeComplete.value = false
        _unreadPrimeSettled.value = false
        _relayFirstAnswer.value = false
        // Debug mode's persisted flag is deleted by WipeRoutine above (its own
        // prefs file, DEBUG_MODE_PREFS_NAME); keep this kept-alive process's
        // RAM copy in lockstep so the Settings row never shows "on" against a
        // wiped, now-false persisted value.
        //
        // A wipe REVOKES CONSENT IN-PROCESS, not just on disk.
        // The deniable path keeps this process alive, so without
        // the three lines below LoggingState stayed true, LogBuffer kept
        // filling with post-wipe lines, and the cursor still pointed into the
        // pre-wipe stream — a wiped device that goes on uploading diagnostics
        // for a consent record that no longer exists. The upload LOOPS are
        // already cancelled further up (debugLogPeriodicJob / the debug-log connect job
        // in the teardown block), so this closes the producer side too.
        // BuildConfig.DEBUG, not `false`: a debug build enables logging for its
        // own reasons in RunApplication.onCreate and must keep it (iOS sibling:
        // `#if DEBUG true #else false`). Ordered before the remaining wipe
        // logging so nothing new is buffered after this point in release.
        _debugMode.value = false
        LoggingState.enabled = BuildConfig.DEBUG
        LogBuffer.clear()
        DebugLogUploader.resetCursor()
        // The panic path keeps the process ALIVE (black
        // screen), so these StateFlows would otherwise leave per-contact / per-group
        // identifiers resident in RAM for a post-wipe RAM acquisition — proof of prior
        // use plus the user's contact ids, exactly what the wipe is meant to erase.
        // Empty them explicitly (Kotlin sibling of the iOS AppState fix).
        clearInMemoryIdentifierMaps()
        // Same reasoning for the move's RAM-only secrets (the displayed transfer
        // code; a scanned handle's read cap + code) — this path deliberately keeps
        // the process alive behind the black cover.
        scrubMoveSecrets()
        pendingMoveHandle = null
        // stopAndDiscardState(), NOT stop(): Tor's working dirs are PRESERVED
        // across an ordinary stop since 2026-08-01 (guard/consensus reuse — see
        // TorManager.dataDir), so a plain stop() here would leave them behind.
        // WipeRoutine.wipePersistentState above already deleted both trees, but
        // it ran while this Tor child was still alive; this is the second pass,
        // after the child is confirmed dead.
        torManager?.stopAndDiscardState()
        torManager = null
        // Final step, AFTER the Tor stop: stopping Tor is what fails any POST still
        // in flight, and that failure is exactly when a send tries to park.
        TransportFailedSends.shared.endSession()
    }

    /**
     * Empties the in-RAM per-contact / per-group identifier StateFlows populated by
     * the background control poll (unread badges + relay-lost set), plus the
     * relay-derived update-nudge version. Called from both teardown paths so a
     * wipe or a background lock leaves no contact/group ids — or relay-chosen
     * state — resident in the (possibly
     * still-alive) process's heap.
     */
    private fun clearInMemoryIdentifierMaps() {
        // The contact list snapshot (aliases, ids) and the pending consent (an
        // offer carries introducer and peer aliases): nulled here, an explicit
        // point, rather than left to a composition's dispose.
        _contactList.value = null
        _pendingConsent.value = PendingConsent(null, null)
        _deferredGroupInviteIds.value = emptySet()
        _deferredReferralOfferIds.value = emptySet()
        _unreadCounts.value = emptyMap()
        _groupUnreadCounts.value = emptyMap()
        _relayLostContacts.value = emptySet()
        _showUpdateNudge.value = null
        // Contact aliases are identifying material too — drop any undismissed
        // relay-info modal the same way (same reasoning as above).
        _referralRelayEvents.value = emptyList()
        // These two are contactId-keyed maps like
        // the ones above — same heap, same acquisition target — and they were the
        // only per-contact StateFlows missing from this list. They are pure
        // SIGNALS re-derived from the vault by [refreshForwardSecrecyStalled] /
        // [refreshRatchetRefused] on the next conversation open, send and poll
        // tick, so dropping them here costs nothing and cannot suppress a notice.
        // iOS sibling: AppState.lock()/emergencyWipe() clear the same two.
        _forwardSecrecyStalled.value = emptyMap()
        _ratchetRefused.value = emptyMap()
    }

    /**
     * ONE teardown body (docs/periodic-reauth-design.md §3.4), extracted
     * VERBATIM from the old [onCleared] so the two lock paths that now share
     * it cannot drift:
     *  - [onCleared] (background/Lever-C `finishAndRemoveTask`, and process
     *    death): `stopTor = true` — Tor tears down with the whole session.
     *  - [lockForReauth] (in-process periodic re-auth lock): `stopTor = false`
     *    — parity with iOS `AppState.lock()`, which keeps Tor up for a
     *    foreground lock so the re-unlock can ADOPT the still-live instance
     *    (see [connectViaTor]'s adoption path) instead of re-bootstrapping.
     *
     * Closes/nulls the vault, scrubs the session managers, drops the in-RAM
     * identifier maps, wipes the Tink keyset, clears any delivered
     * notification, and clears the periodic re-auth deadline (a locked/
     * PIN-screen state must never carry a stale one — [onVaultOpened]
     * recomputes it fresh on the next unlock either way).
     *
     * NOT quite verbatim any more: three pieces
     * of session state that `onCleared` never had to clear — because dropping
     * the whole ViewModel cleared them — are now cleared EXPLICITLY, since
     * [lockForReauth] keeps this ViewModel (and the process) alive across the
     * lock: the relay-reachability/handshake latches and the push session
     * bookkeeping. Both are no-ops on the `onCleared` path. See the inline
     * comments for the per-item argument.
     */
    private fun lockSession(stopTor: Boolean) {
        // ONE cancel for every session job ([SessionJobs]), before the vault is
        // closed so nothing new goes on the wire for this session: the Tor monitor
        // and the in-flight start() (it may be the speculative one, and must not
        // outlive the torManager?.stop() below), the pollers, the prime and its
        // cap, the push prompt, the pre-unlock warm-up (a lock racing a still-parked
        // one takes it with the rest), the external-proxy check, the stall
        // watchdog, the transport re-drive and both move jobs.
        // Why every one of them matters: [lockForReauth] keeps Tor AND this
        // ViewModel (and viewModelScope) alive, so nothing else stops a pre-lock
        // job racing the next session. A still-pending re-drive would fire against
        // the next session's first relay answer and manager (nothing is lost by
        // dropping it: endSession() below clears the ledger it would re-drive). An
        // in-flight move export ran to completion across the lock and published
        // Ready(handle), the one-time code plus the inbox read cap, after
        // [scrubMoveSecrets] below had dropped it, while an import held the
        // scanned handle for the rest of its transport-wait budget. Cooperative,
        // hence MoveManager's own vault re-check before it publishes Ready and its
        // Preparing -> Idle collapse in scrubInMemory. iOS sibling:
        // IosAppController.lock()'s `moveScope.coroutineContext.cancelChildren()`.
        sessionJobs.cancelAll()
        telemetry.cancelConnectJobs()
        telemetry.cancelBootStamp()
        // Debug mode (Settings → Debug mode): snapshot BEFORE messageManager is
        // nulled below, for the bounded final flush placed just above
        // ConnectionLog.clear() further down. relayTransport() is only the Tor
        // SOCKS / direct HTTP client — no vault or key material — so holding
        // onto it past the crypto-erase-first block immediately below is safe
        // as long as Tor itself has not stopped yet, which it hasn't: that is
        // the LAST step this function takes (`if (stopTor) torManager?.stop()`).
        val debugLogWasOpen = vault != null
        val debugLogTransport = messageManager?.relayTransport()
        // Snapshot the last health-probe verdict HERE too: `_isRelayReachable`
        // is set to false further down, before the flush runs. A session whose
        // last probe did NOT succeed has a dead or half-open circuit, on which
        // this flush can only ever burn its whole budget — so it is skipped
        // outright rather than bounded (see the flush block below).
        val debugLogRelayWasUp = _isRelayReachable.value
        // Close + release the vault so SQLCipher frees the derived page key from
        // the backgrounded (cached, not killed) process's native RAM, and the
        // references become GC-eligible. Without this the open connection — and
        // its resident key — survived in the dormant process, recoverable by a
        // live-RAM acquisition of a seized locked device. Restores the documented
        // "vault cleared when the ViewModel is destroyed" invariant and mirrors
        // performEmergencyWipe's teardown.
        try { vault?.close() } catch (_: Exception) { /* best-effort */ }
        vault = null
        // Scrub RAM buffers + ephemeral referral key BEFORE dropping the references
        // (nulling alone does NOT clear the buffers, and a scrub AFTER the null is
        // dead).
        messageManager?.scrubInMemory()
        messageManager = null
        // Parked transport-failed sends (plaintext, RAM-only) must not outlive the
        // session either. Entries are recorded exactly when `messageManager` is
        // null — Tor Failed/Idle/restart null it WITHOUT scrubbing, on purpose: a
        // parked send must survive a transport outage inside the unlocked session
        // — so the clear must not depend on a manager existing here. endSession()
        // also bumps the epoch so an in-flight send cannot re-park after this;
        // repeated as the very last step, after the Tor stop.
        cancelInFlightSends()
        TransportFailedSends.shared.endSession()
        groupManager?.scrubInMemory()
        referralManager?.scrubInMemory()
        groupManager = null
        referralManager = null
        maximumShield = null
        // The transport is gone with the managers above, so neither claim may
        // survive the lock. [relayHandshakeComplete]'s own kdoc states the rule
        // ("reset only when the transport itself is torn down — Tor restart /
        // lock / wipe"); it held vacuously while a lock always destroyed this
        // ViewModel, and stops holding now that lockForReauth keeps it alive:
        // the next session would otherwise inherit a stale "we have talked to
        // the relay on this transport" latch and paint the contact list
        // CONNECTED for up to a full ~8-12 s probe cycle before its first
        // round-trip, which is the exact dishonest-UI claim that latch exists to
        // prevent. Mirrors performEmergencyWipe / restartTor.
        _isRelayReachable.value = false
        _relayHandshakeComplete.value = false
        _unreadPrimeSettled.value = false
        _relayFirstAnswer.value = false
        // Sibling of performEmergencyWipe: drop the per-contact/-group id maps so a
        // backgrounded (cached, not killed) process holds no contact ids in its heap.
        clearInMemoryIdentifierMaps()
        // Same reasoning, same RAM, one tier up: the push session bookkeeping
        // holds RAW INBOX IDS (the coordinator's two registered-id sets)
        // and the UnifiedPush ENDPOINT URL (which names the user's push server).
        // Those four fields are documented as SESSION-scoped RAM, and until
        // lockForReauth existed "session" and "ViewModel" were the same thing —
        // onCleared dropped the whole ViewModel, so the fields went with it.
        // An in-process lock breaks that identity: without this call the ids
        // stay strongly reachable in a locked-but-alive process (a live-RAM
        // acquisition target, exactly what clearInMemoryIdentifierMaps above
        // defends against) AND carry into the NEXT session's "already registered"
        // diff. Through the shared helper so the epoch bump comes first, which
        // is what makes a registration pass straddling this lock discard its own
        // bookkeeping instead of re-planting inbox ids behind us
        // (see [PushRegistrationCoordinator.clearPushSessionBookkeeping]). The
        // direction is the safe one — an over-cleared set merely re-registers,
        // an idempotent relay upsert. Parity with iOS AppState.lock(), which has
        // always done `pushTeardownEpoch += 1; pushRegisteredInboxIds = []`.
        push.clearPushSessionBookkeeping()
        // Drop the unwrapped Tink data keyset from RAM on lock (mirrors iOS
        // wipeKey) so the AES-256 keyset doesn't survive in the dormant process;
        // it lazily re-initializes on the next crypto use after unlock.
        try { cryptoProvider.wipeKey() } catch (_: Exception) { /* best-effort */ }
        // Clear any delivered "Notification" notification on the
        // SAME teardown that closes the vault. Before this fix, cancelAll's only
        // production callers were the wipe path and the push opt-OUT toggle —
        // a plain background/lock (this path, fired via MainActivity.onStop()'s
        // finishAndRemoveTask()) left the notification posted, so a seized AFU
        // device's shade still showed "Rún — New messages" after the app's own
        // teardown had already closed the vault and wiped the key. VISIBILITY_
        // SECRET only suppresses the LOCK-SCREEN display, not the record itself.
        // Mirrors iOS, which clears the equivalent local notification on every
        // lock(). Same acceptable UX cost iOS already documents: delivery
        // awareness is lost the moment the app backgrounds (the notification
        // content was already generic, so nothing sensitive is lost with it).
        try { NotificationHelper.cancelAll(getApplication()) } catch (_: Exception) { /* best-effort */ }
        // Periodic re-auth deadline is per-session — see reauthDeadlineElapsedMs's
        // kdoc; onVaultOpened recomputes it fresh on the next unlock regardless.
        reauthDeadlineElapsedMs = null
        // Move secrets are RAM-only and must not outlive the lock: the displayed
        // one-time transfer code (Ready -> FrozenNoCode) and, on the new phone, the
        // scanned handle (read capability + code). Both are re-obtainable — a
        // re-issue on the old phone, a rescan on the new one — so dropping them is
        // always the safe direction. Matters for lockForReauth, which keeps this
        // ViewModel (and the process) alive across the lock; a no-op on the
        // onCleared path, which drops the whole object anyway.
        scrubMoveSecrets()
        pendingMoveHandle = null
        // Debug mode (Settings → Debug mode): best-effort FINAL flush, here and
        // ONLY here (both onCleared's full teardown and lockForReauth's
        // in-process lock share this one body) — BEFORE ConnectionLog.clear()
        // below and Tor stop further down. debugLogPeriodicJob was just
        // cancelled a few lines above and gets no further ticks, so without
        // this call the last (at most ~1 s of) lines written during this very
        // teardown — often the most interesting ones, per DebugMode.kt's own
        // header note — would never ship; the cursor's sequence numbers stay
        // valid across ConnectionLog.clear() (it is not the buffer contents
        // that decide what is "new", it is [DebugLogSeq]), so nothing here
        // depends on racing the clear itself. Placed AFTER the
        // crypto-erase-first block above (vault close + Tink keyset wipe
        // already ran), so it can only delay this trailing, non-security-
        // critical cleanup — never the erase. Bounded to
        // [DEBUG_LOG_LOCK_FLUSH_TIMEOUT_MS] (withTimeoutOrNull): a dead or slow
        // relay must never hold up a lock or a teardown, so this proceeds
        // regardless of the outcome.
        // runBlocking is deliberate — this is a plain (non-suspend) function
        // reached from both a Handler callback (lockForReauth) and
        // ViewModel.clear() (onCleared, where viewModelScope is already
        // cancelled by the time onCleared runs), so there is no live scope
        // here to launch-and-forget on; a bounded synchronous wait is the
        // only way to honour "before ConnectionLog.clear() / Tor stop". No
        // try/catch — [DebugLogUploader.flush] is documented never to throw.
        // Skipped when there was no open session to report on, AND when this
        // session's last relay health probe did not succeed: an unreachable
        // relay cannot absorb a batch, so the only thing a flush could do there
        // is block this thread (the UI thread on the lockForReauth path) for
        // the full budget. Not "bound it tighter" — skip it entirely.
        if (debugLogWasOpen && debugLogRelayWasUp && _debugMode.value) {
            if (stopTor) {
                // Teardown (onCleared): the transport dies with this call, so the
                // bounded block is the only way the batch ever leaves the device.
                runBlocking(Dispatchers.IO) {
                    withTimeoutOrNull(DEBUG_LOG_LOCK_FLUSH_TIMEOUT_MS) {
                        DebugLogUploader.flush(
                            debugLogTransport,
                            ConnectTelemetry.PLATFORM_ANDROID,
                            BuildConfig.VERSION_NAME,
                            DebugLogUploader.REASON_LOCK,
                        )
                    }
                }
                LogBuffer.clear()
            } else {
                // In-process re-auth lock: this runs on the main thread from the
                // watchdog while the user may be mid-tap, and Tor + the captured
                // transport stay alive, so the flush is detached instead of
                // stalling the UI for up to the timeout. The
                // buffer is cleared by the SAME task once the batch is out (or
                // the timeout hit), so the detached collect cannot race an
                // immediate clear into an empty lock batch.
                viewModelScope.launch(Dispatchers.IO) {
                    try {
                        withTimeoutOrNull(DEBUG_LOG_LOCK_FLUSH_TIMEOUT_MS) {
                            DebugLogUploader.flush(
                                debugLogTransport,
                                ConnectTelemetry.PLATFORM_ANDROID,
                                BuildConfig.VERSION_NAME,
                                DebugLogUploader.REASON_LOCK,
                            )
                        }
                    } finally {
                        LogBuffer.clear()
                    }
                }
            }
        } else {
            // iOS parity (AppState.lock() clears LogBuffer): with Debug mode on
            // in a RELEASE build LogBuffer holds up to 2000 RAW lines (redaction
            // happens at upload), and LoggingState.kt promises they do not
            // survive a lock. Bounded above by the flush timeout when a lock
            // batch is in flight, immediate otherwise.
            LogBuffer.clear()
        }
        // Connection-log panel: drop every buffered line on lock — the same
        // RAM-residue rule that clears LogBuffer, and the sibling of iOS
        // AppState.lock(). CLEAR FIRST, then leave exactly one fixed-phrase
        // SYSTEM marker so the panel explains why it went empty instead of
        // looking broken; the marker names nothing.
        ConnectionLog.clear()
        ConnectionLog.append(
            ConnectionLog.Kind.SYSTEM,
            "session locked",
            ConnectionLog.Code.SESSION_LOCKED,
        )
        // Foreground-only: tear Tor down with the WHOLE session (Lever C /
        // background). A re-auth lock passes stopTor=false and keeps it running.
        //
        // Bounded Tor keep-alive (TorKeepAlive.kt): when MainActivity.onStop armed
        // it (tier < MAXIMUM, Tor Connected, no wipe), the live instance is HANDED
        // to TorKeepAliveHolder instead of stopped — everything above (vault,
        // keyset, managers, transport, identifier maps, ring) is already gone, so
        // only the Tor child outlives this session, for at most
        // TorKeepAlive.KEEP_ALIVE_MS. Not armed / not Connected ⇒ stop() exactly
        // as before. The hooks are unbound either way so the kept instance never
        // calls back into this cleared ViewModel.
        if (stopTor) {
            val tor = torManager
            if (tor != null) {
                val connected = tor.state.value is TorManager.ConnectionState.Connected && !tor.isMidInternalRetry
                if (!TorKeepAliveHolder.parkOnTeardown(tor, connected)) tor.stop()
            }
            torManager = null
            sessionTierAllowsKeepAlive = null
            TorKeepAliveHolder.hooks.unbind(this)
        }
        // Final step, AFTER the Tor stop (or hand-off): stopping Tor is what fails
        // any POST still in flight, and that failure is exactly when a send tries
        // to park. With stopTor=false (re-auth lock) Tor stays up and the epoch
        // bump above is what refuses a late park.
        TransportFailedSends.shared.endSession()
    }

    /**
     * Fires the periodic re-auth (docs/periodic-reauth-design.md): full lock via the SAME primitive Lever C uses
     * ([lockSession]); Tor stays up (`stopTor = false`) so the re-unlock's
     * [connectViaTor] adopts the live instance rather than re-bootstrapping.
     * MainActivity collects [reauthLocked] and navigates to "pin" in-process.
     *
     * Belt-and-braces: a lock with no open vault has
     * nothing to do — before this guard, a watchdog tick racing an in-session
     * [performEmergencyWipe] (whose own stale-deadline root cause is now fixed
     * there too) could reach here with `vault` already null. Returning here
     * before raising [_reauthLocked] keeps a wiped session's black cover in place instead of
     * MainActivity navigating to an interactive "pin" screen.
     */
    fun lockForReauth() {
        if (vault == null) return
        lockSession(stopTor = false)
        _reauthLocked.value = true
    }

    override fun onCleared() {
        super.onCleared()
        networkRestore.unregister()
        RelayEndpoints.race.unbindSwitchListener(this)
        lockSession(stopTor = true)
    }
}

/**
 * FIRST STAMP WINS — the `boot` field's one rule, extracted from
 * [ConnectTelemetryRecorder.markBootConnected] so it is unit-testable without a
 * [android.content.Context] or a live Tor.
 *
 * `boot` is "how long THIS session's Tor process took to reach `Connected`",
 * and two observers can report that transition: the pre-unlock
 * [ConnectTelemetryRecorder.armBootStamp] coroutine (the honest one — it is watching when
 * the bootstrap actually finishes) and the post-unlock Tor monitor, whose
 * `StateFlow` collector is replayed an already-`Connected` state at unlock and
 * would otherwise report `max(true bootstrap, time-to-unlock)`. Keeping the
 * FIRST value is what makes the relay's Android `boot` histogram a bootstrap
 * histogram again instead of an unlock-latency one, and it is the same
 * "one wait" rule the connect anchor and `tor` already follow: a self-heal
 * restart, a manual Reconnect or an activity recreation never re-stamps.
 *
 * @param existingMs the value already stamped, or null if none — returned
 *   unchanged whenever it exists.
 * @param anchorMs when this session's Tor PROCESS was started, or null on the
 *   debug/direct path (no Tor at all), which keeps `boot` OMITTED from the
 *   report rather than sent as a zero.
 * @param nowMs monotonic now ([android.os.SystemClock.elapsedRealtime]).
 */
internal fun firstBootStamp(existingMs: Long?, anchorMs: Long?, nowMs: Long): Long? =
    existingMs ?: anchorMs?.let { (nowMs - it).coerceAtLeast(0L) }

/**
 * The Play Store's installer-of-record package name. Compared against
 * [android.content.pm.InstallSourceInfo.installingPackageName] /
 * [android.content.pm.PackageManager.getInstallerPackageName] — never a
 * substring or prefix match (a look-alike package id proves nothing).
 */
internal const val PLAY_STORE_INSTALLER_PACKAGE = "com.android.vending"

/**
 * `market://` deep link for this app's own Play Store listing. Deliberately
 * has NO `https://play.google.com/...` counterpart: an unresolvable `market://` falls back to info-only, never a browser.
 */
internal const val PLAY_STORE_MARKET_URI = "market://details?id=com.vg.run"

/**
 * Pure decision extracted from [RunViewModel.isPlayInstall] so it is
 * unit-testable without an [android.content.Context]. `null` (no installer of
 * record — sideload, `adb install`, some OEM app stores) is `false`, the same
 * fail-closed-to-info-only answer as every other non-Play installer string.
 */
internal fun isPlayInstaller(installer: String?): Boolean = installer == PLAY_STORE_INSTALLER_PACKAGE

package com.vg.run

import android.content.Context
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.height
import androidx.compose.ui.unit.dp
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import kotlinx.coroutines.launch
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.window.Popup
import androidx.compose.ui.window.PopupProperties
import com.vg.run.ui.theme.RunTheme
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.vg.run.ui.theme.RunBlack
import com.vg.run.ui.theme.RunGrey
import com.vg.run.ui.theme.RunWhite

// ---------------------------------------------------------------------------
// MainActivity — single-activity host for the entire app.
//
// Security purpose:
//   • The PIN screen is shown every time the app comes to the foreground.
//     When the user switches away (home button, app switcher, screen off),
//     the vault is locked and the Activity is recreated on return, forcing
//     PIN re-entry. This prevents an adversary who picks up an unlocked
//     device from seeing the conversation.
//   • The RunViewModel is scoped to this Activity, so the vault reference
//     is cleared when the Activity is destroyed.
// ---------------------------------------------------------------------------

class MainActivity : ComponentActivity() {

    // Per-app language override (localization plumbing, both platforms):
    // identity on API 33+ (LocaleManager keeps every context in sync on its
    // own); on API 29-32 re-configures the base context to the stored
    // override tag, if any. See AppLocale.kt for the wipe-asymmetry note.
    override fun attachBaseContext(newBase: Context) {
        super.attachBaseContext(AppLocale.wrap(newBase))
    }

    // Foreground inactivity auto-lock (Lever C):
    // backgrounding already locks via onStop() → finish, so the remaining
    // exposure is the app sitting OPEN and idle with the screen on. After
    // AUTO_LOCK_TIMEOUT_MS without any user interaction while the vault is
    // unlocked, finish the Activity — the same teardown path as onStop, so the
    // ViewModel's onCleared closes the vault and wipes the key from RAM.
    //
    // The idle clock lives in the ViewModel ([RunViewModel.lastInteractionElapsedMs]),
    // not here: a configuration change recreates this Activity but keeps the
    // ViewModel, and an Activity-local clock was reset by every recreation (S2 F1,
    // review 2026-11-06 — rotating the phone every few seconds kept both the idle
    // lock and the periodic re-auth from ever firing).
    //
    // The ViewModel this Activity has already obtained, or null. Never looked up
    // from onUserInteraction: ViewModelProvider CONSTRUCTS the ViewModel when it is
    // absent, and under the deniable-wipe cover that would start Tor (see onResume).
    private var runVm: RunViewModel? = null

    override fun onUserInteraction() {
        super.onUserInteraction()
        runVm?.noteUserInteraction()
    }

    // Lever-C warning countdown (threat-slider spec) AND the
    // periodic-re-auth warning (docs/periodic-reauth-design.md) share this one
    // overlay: seconds left until WHICHEVER deadline is nearer, or null when
    // no warning is due. Written ONLY by the watchdog below.
    private val lockCountdownSecs = mutableStateOf<Int?>(null)

    // True when [lockCountdownSecs] reflects the periodic re-auth deadline
    // rather than Lever C's idle timeout — selects the overlay copy variant
    // and the reauth_countdown a11y id. See [autoLockCheck].
    private val lockCountdownIsReauth = mutableStateOf(false)

    // Single-window "paused-not-stopped" teardown (see onPause). A bounded, DELAYED fallback: too far past what any
    // of Rún's own in-app prompts need to resolve to ever fire on a benign one; see
    // the constant + Runnable's own doc for why.
    private val pauseCoverHandler = Handler(Looper.getMainLooper())
    private val pauseCoverTeardown = Runnable {
        if (BuildConfig.DEBUG) {
            // Localization instrumentation only (no behavior change): proves
            // whether a language-switch relaunch (AppLocale.apply) trips this
            // single-window teardown path or is correctly recognised as a
            // configuration change.
            LogBuffer.append("D", "MainActivity",
                "pauseCoverTeardown: isChangingConfigurations=$isChangingConfigurations")
        }
        if (!isChangingConfigurations && !isFinishing && !isDestroyed) {
            LogBuffer.append("W", "MainActivity",
                "paused (single-window) past the grace window — tearing down session (vault lock)")
            finishAndRemoveTask()
        }
    }

    private val autoLockHandler = Handler(Looper.getMainLooper())

    // ONE watchdog drives BOTH Lever C (idle auto-lock) and the periodic
    // random re-auth at MAXIMUM (docs/periodic-reauth-design.md): the deadline
    // that fires is whichever is NEARER, sharing one cadence and one overlay.
    // Only the Lever-C branch is compiled out of debug builds (pure touch-idle
    // is incompatible with UI automation); the re-auth branch runs in EVERY
    // build — see ReauthPolicy.isEnabled's own debug-off-by-default gate, which
    // a release binary can never override.
    private val autoLockCheck = object : Runnable {
        override fun run() {
            // Same ViewModel instance as setContent's viewModel() (same store +
            // default factory).
            val vm = ViewModelProvider(this@MainActivity)
                .get(RunViewModel::class.java)
            runVm = vm
            val nowElapsed = SystemClock.elapsedRealtime()

            // Lever C (idle auto-lock). Only lock when a vault is actually
            // open — idling on the PIN screen holds nothing sensitive.
            var leverCRemainingMs = Long.MAX_VALUE
            if (!BuildConfig.DEBUG && vm.vault != null) {
                val idleMs = nowElapsed - vm.lastInteractionElapsedMs
                // Per-level auto-lock (threat-level slider); a legacy vault with no
                // chosen level keeps the current default, and an UNREADABLE stored
                // level gets the shortest tier timeout (shared fail-safe decision —
                // locking sooner is the safe direction).
                val timeoutMs = CredentialPolicy.autoLockTimeoutMs(
                    vm.vaultSelector.protectionLevelForEnforcement())
                leverCRemainingMs = timeoutMs - idleMs
            }

            // Periodic random re-auth at MAXIMUM — "since unlock", not idle.
            // reauthDeadlineElapsedMs is null whenever no vault is open (cleared
            // on every lock). Belt-and-braces: also
            // explicit-gate on vm.vault != null, so a path that nulls the vault
            // without going through lockSession (performEmergencyWipe used to
            // leave a stale deadline armed — now fixed at its source too) can
            // never fire a re-auth lock against an already-wiped session.
            var reauthRemainingMs = Long.MAX_VALUE
            val reauthDeadline = vm.reauthDeadlineElapsedMs
            if (reauthDeadline != null && vm.vault != null) {
                reauthRemainingMs = ReauthPolicy.remainingMs(reauthDeadline, nowElapsed)
            }

            val reauthIsNearer = reauthRemainingMs <= leverCRemainingMs
            val remainingMs = if (reauthIsNearer) reauthRemainingMs else leverCRemainingMs

            if (remainingMs <= 0) {
                lockCountdownSecs.value = null
                if (reauthIsNearer) {
                    LogBuffer.append("W", "MainActivity", "periodic re-auth — locking vault")
                    vm.lockForReauth()
                    // RE-POST, unlike the Lever-C branch below. The re-auth lock is
                    // IN-PROCESS (navigate to "pin", no finishAndRemoveTask), so this
                    // Activity stays RESUMED and onResume — the only other poster of
                    // this Runnable — will not run again. Returning without re-posting
                    // would let ONE re-auth permanently disarm BOTH watchdogs for the
                    // rest of the foreground session: no further periodic re-auth (the
                    // "at least once every ten minutes" bound silently becomes
                    // once-ever) and, worse, no Lever-C idle auto-lock either, so the
                    // re-unlocked vault could then sit open and idle indefinitely.
                    // Coarse cadence: until the re-unlock lands, vm.vault and
                    // vm.reauthDeadlineElapsedMs are both null (lockSession clears
                    // them), so every tick in between is a two-null no-op.
                    autoLockHandler.postDelayed(this, CredentialPolicy.AUTO_LOCK_CHECK_INTERVAL_MS)
                } else {
                    LogBuffer.append("W", "MainActivity", "inactivity auto-lock — locking vault")
                    finishAndRemoveTask()
                }
                return
            }
            // Warning countdown ("Locking in N… — tap to stay" / "Passphrase check
            // in N…"): shown for the last AUTO_LOCK_WARNING_MS INSIDE the window —
            // the deadline above never moves (a grace period would widen the idle
            // exposure bound / defeat the re-auth's hard bound). Any touch resets
            // the ViewModel idle clock via onUserInteraction, which only affects Lever C's
            // clock; the next tick hides the overlay again once neither is close.
            if (remainingMs <= CredentialPolicy.AUTO_LOCK_WARNING_MS) {
                lockCountdownSecs.value = ((remainingMs + 999) / 1000).toInt()
                lockCountdownIsReauth.value = reauthIsNearer
            } else {
                lockCountdownSecs.value = null
            }
            // Near the deadline, tick at 1 s — that drives the countdown AND makes
            // the lock punctual (the coarse 10 s poll alone could fire it up to
            // ~10 s late).
            val interval =
                if (remainingMs <= CredentialPolicy.AUTO_LOCK_FINE_WINDOW_MS)
                    CredentialPolicy.AUTO_LOCK_FINE_CHECK_INTERVAL_MS
                else CredentialPolicy.AUTO_LOCK_CHECK_INTERVAL_MS
            autoLockHandler.postDelayed(this, interval)
        }
    }

    /** Reset the idle clock as if the user touched the screen — the countdown
     *  overlay's "tap to stay" calls this (a Popup renders in its own window, so
     *  its taps don't dispatch through Activity.onUserInteraction). Lever-C ONLY:
     *  the periodic re-auth deadline never moves, so this cannot defer it (its
     *  own overlay variant renders no "tap to stay" affordance — see
     *  LockCountdownOverlay). */
    private fun keepUnlocked() {
        runVm?.noteUserInteraction()
        lockCountdownSecs.value = null
    }

    override fun onResume() {
        super.onResume()
        // The deniable-wipe cover
        // ([ProcessWipeCover]) only ever gated onCreate's rendering. onResume
        // runs on EVERY foreground transition regardless of what onCreate drew —
        // including a launcher tap that lands on a CACHED process (finished by
        // finishAndRemoveTask but not yet killed by the OS), where onCreate
        // reran, saw the cover armed, and correctly painted the black Box, but
        // this method then still fired unconditionally 10s later: the watchdog
        // (autoLockCheck) looks up RunViewModel via ViewModelProvider — which
        // CONSTRUCTS it if absent — and RunViewModel.init unconditionally kicks
        // off the pre-unlock Tor start, recreating tor_direct and beaconing the
        // relay from a phone that must look dead. Bail out before ANY of that,
        // including AuthActivityHolder (no BiometricPrompt surface over the
        // cover) and — deliberately — before the pauseCoverHandler.removeCallbacks
        // below: leaving that delayed teardown armed just re-tears-down a process
        // that must never show content again, which is the outcome we want here,
        // not a bug. The ViewModel's Tor kick-off also self-guards on the cover
        // (belt); this is the primary stop.
        if (ProcessWipeCover.armed) {
            LogBuffer.append("W", "MainActivity",
                "process-wipe cover armed on resume — skipping watchdog/AuthActivityHolder")
            return
        }
        // Connection-log panel (ConnectionLog.kt): fixed phrase, no identifiers.
        // CODED (3-arg append): the connect timeline and the debug-log
        // "worth a tick" test both read [ConnectionLog.Code], and this producer
        // was the reason APP_FOREGROUNDED existed in the enum but was never
        // emitted. Text unchanged. iOS sibling: ContentView's scenePhase handler.
        ConnectionLog.append(
            ConnectionLog.Kind.SYSTEM,
            "app foregrounded",
            ConnectionLog.Code.APP_FOREGROUNDED,
        )
        // Cancel the single-window pause-cover fallback (see onPause / the Runnable's
        // doc) — we're back in foreground, whatever paused us (our own prompt, or a
        // real cover that went away) is resolved.
        pauseCoverHandler.removeCallbacks(pauseCoverTeardown)
        // Obtained only AFTER the cover check above (the lookup constructs the
        // ViewModel when absent). A resume that follows a configuration change is
        // NOT user activity: resetting the idle clock there let rotation churn
        // postpone Lever C forever (S2 F1). Any other resume (first launch, back
        // from a BiometricPrompt or the camera-permission dialog) starts it fresh.
        val vm = ViewModelProvider(this).get(RunViewModel::class.java)
        runVm = vm
        if (!vm.consumeConfigurationChangeRecreation()) vm.noteUserInteraction()
        // The watchdog is now ALWAYS posted (docs/periodic-reauth-design.md): the
        // periodic re-auth branch inside it must tick even in a debug build so a
        // TEST_REAUTH_INTERVAL_MS-armed e2e spec gets checked. The Lever-C (idle
        // auto-lock) branch stays gated INSIDE the Runnable on !BuildConfig.DEBUG
        // — pure touch-idle is incompatible with UI automation: UiAutomator2 drives
        // the app via accessibility with no user-interaction events during the e2e's
        // multi-minute no-touch Tor waits, so the 2-min lock would tear the session
        // down mid-suite. RELEASE keeps the full auto-lock as before.
        //
        // Evaluated NOW, not AUTO_LOCK_CHECK_INTERVAL_MS from now (S2 F1): this
        // Runnable is the Activity's only evaluator and onPause removes it, so a
        // first tick 10 s after every resume meant a recreation more often than
        // every 10 s (rotation, a dark-theme toggle) re-armed it forever and a
        // past-due re-auth never fired. Running it here locks a past-due session
        // before the restored screen takes input; the Runnable re-posts itself at
        // the right cadence. RunViewModel's own ticker is the Activity-independent
        // backstop.
        autoLockHandler.removeCallbacks(autoLockCheck)
        autoLockCheck.run()
        // Lever B: the auth-bound DB-key unwrap shows a BiometricPrompt, which
        // needs the current foreground Activity. Publish it while resumed.
        AuthActivityHolder.activity = this
    }

    override fun onPause() {
        super.onPause()
        autoLockHandler.removeCallbacks(autoLockCheck)
        lockCountdownSecs.value = null
        // The next onResume belongs to the recreated instance and must not count
        // as user activity (see onResume, S2 F1). The ViewModel carries the flag
        // across the recreation; this instance is about to be destroyed.
        if (isChangingConfigurations) runVm?.markConfigurationChangeRecreation()
        if (AuthActivityHolder.activity === this) AuthActivityHolder.activity = null

        // In multi-window (split-screen / freeform / desktop),
        // losing foreground focus to the other pane fires onPause but NOT onStop, so
        // neither the whole-session background teardown (onStop → finishAndRemoveTask)
        // nor the Lever-C idle watchdog (just removed above) can close the vault — it
        // would sit OPEN and unlocked indefinitely while the other pane is driven,
        // available for a leisurely live-RAM acquisition. Tear the session down here
        // too when we're paused in multi-window, using the SAME teardown as onStop
        // (onCleared closes the vault + wipes the key + stops Tor).
        //
        // Guards keep this off the transient same-task overlays that also pause us but
        // must NOT re-lock mid-flow (the Android analog of the iOS transient re-lock
        // bug): NOT during a configuration change (rotation, or entering/leaving
        // multi-window — onStop finishes those), NOT if already finishing, and NOT in
        // single-window mode. In single-window a Lever-B BiometricPrompt or the CAMERA
        // permission dialog we raise for QR pairing pauses us with
        // isInMultiWindowMode == false, so they never trip this. (Compose Dialogs/
        // Popups — About, the countdown — don't pause the Activity at all.) On
        // large-screen multi-resume devices where an unfocused pane stays RESUMED and
        // onPause never fires, the idle watchdog is likewise never removed and still
        // fires the auto-lock, so that case is covered too.
        if (isInMultiWindowMode && !isChangingConfigurations && !isFinishing) {
            LogBuffer.append("W", "MainActivity", "paused in multi-window — tearing down session (vault lock)")
            finishAndRemoveTask()
            return
        }

        // The teardown above only covers multi-window. A SINGLE-window paused-not-stopped
        // state — a translucent / non-fullscreen activity placed on top of Rún — is
        // the OTHER way to reach onPause without onStop, and isInMultiWindowMode is
        // false for it, so the branch above never trips. Left alone this is an
        // UNBOUNDED window: the idle watchdog was just removed above and onStop never
        // runs, so a hostile persistent overlay would keep the vault open (SQLCipher
        // page key resident) indefinitely.
        //
        // From inside this Activity there is no reliable way to tell that apart from
        // our OWN in-app prompts that pause us the identical way in single-window —
        // the Lever-B BiometricPrompt (BiometricGate.kt; bounded at 120 s internally)
        // and the CAMERA permission dialog for QR pairing (paragraph above). Guessing
        // wrong and tearing the session down mid-prompt would be exactly the Android
        // analog of the iOS transient re-lock bug this file already goes out of its
        // way not to reintroduce. So instead of an immediate teardown, arm a DELAYED
        // one: if we are STILL paused this long after losing foreground — comfortably
        // past BiometricGate's own ceiling, so any real in-app prompt has already
        // resolved (success, cancel, or its own timeout) and resumed us — tear the
        // session down the same way onStop does. onResume cancels this on every
        // ordinary resume (including a same-task dialog closing), so it only ever
        // fires when foreground truly never came back.
        if (!isChangingConfigurations && !isFinishing) {
            pauseCoverHandler.postDelayed(pauseCoverTeardown, PAUSE_COVER_GRACE_MS)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Fail loud if a RELEASE app somehow links a DEBUG shared module
        // (Argon2 would run at the debug cost and provision weak vaults). Pass the APP's
        // own build type — the signal independent of the shared framework's isDebugBuild.
        assertKdfBuildIntegrity(appIsReleaseBuild = !BuildConfig.DEBUG)
        // FLAG_SECURE blocks screenshots AND screen recording. Release keeps it
        // (anti-forensic screen-capture protection). DEBUG builds drop it so the
        // physical-device e2e suites can screen-record the run for diagnosis —
        // otherwise `screenrecord`/MediaProjection capture only black frames.
        // Consistent with the other DEBUG-gated relaxations (auto-lock skip,
        // pin_count a11y, Argon2 cost); debug builds are never shipped.
        if (!BuildConfig.DEBUG) {
            window.setFlags(
                WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE
            )
        }
        enableEdgeToEdge()

        // Order is load-bearing: the cover check runs before ANY vault-state read,
        // the test hooks before the inactivity check, and both before the
        // orphaned-credential probe and the first ViewModel lookup.
        if (renderProcessWipeCoverIfArmed()) return
        runLaunchTestHooks()

        // Check inactivity threshold BEFORE any UI renders or vaults open.
        InactivityWipe.checkAndWipeIfNeeded(this)

        selfHealOrphanedCredentials()
        observeSessionRetirement()

        setContent {
            @OptIn(ExperimentalComposeUiApi::class)
            // Dialogs/popups live in their own windows, so their touches never
            // reach onUserInteraction. Publish the same idle-clock reset the
            // Activity uses so every separate-window surface can report activity.
            CompositionLocalProvider(
                LocalKeepUnlocked provides { keepUnlocked() }
            ) {
            RunTheme {
                val viewModel: RunViewModel = viewModel()
                runVm = viewModel
                val navController = rememberNavController()

                // A global, process-lifetime deniable-wipe
                // cover rendered as a SIBLING of (and gating) the NavHost —
                // NOT a per-screen `remember { mutableStateOf(false) }` local
                // (the ChangePinScreen / RecoveryEntryScreen pattern this
                // replaces as the sole cover). Those locals live on the NavHost
                // back stack: a BACK press with no BackHandler popped the wiped
                // screen and re-revealed whatever sits underneath (`contacts`,
                // rendered with a null vault). Skipping the NavHost entirely —
                // the same early-`return@RunTheme` shape as the Device
                // Compromised gate just below — removes the back-stack
                // entirely, so there is nothing left for BACK to pop into; the
                // BackHandler below is still added so a system BACK is
                // consumed rather than falling through to the Activity's
                // default (finish) action mid-cover. `wipedThisSession` is the
                // LIVE same-composition signal ([RunViewModel.performEmergencyWipe]
                // with `deniable = true`); `ProcessWipeCover.armed` also covers
                // an Activity (re)create that happens to land here instead of
                // onCreate's own early ProcessWipeCover branch — belt-and-braces, same
                // flag either way. Mirrors iOS `ContentView`'s top-level
                // `wipedThisSession` branch (`ContentView.swift:230-236`).
                val wipedThisSession by viewModel.wipedThisSession.collectAsState()
                if (wipedThisSession || ProcessWipeCover.armed) {
                    BackHandler(enabled = true) { /* swallow — no escape from the cover */ }
                    Box(
                        modifier = Modifier
                            .fillMaxSize()
                            .background(RunBlack)
                    )
                    return@RunTheme
                }

                // Periodic random re-auth at MAXIMUM (docs/periodic-reauth-design.md):
                // collect the fired flag and navigate to "pin" IN-PROCESS — modeled
                // on the vaultSessionRetired collector in onCreate, but a NAVIGATE
                // rather than finishAndRemoveTask (RunViewModel.lockForReauth keeps
                // Tor up so the re-unlock's connectViaTor adopts the live instance).
                // popUpTo(0) clears the WHOLE back stack — the fired lock can land on
                // ANY screen (conversation, add contact, settings…), not only the
                // contact list. consumeReauthLocked() resets the flag so it can't
                // re-fire the navigation on the next collector attach/recomposition.
                LaunchedEffect(Unit) {
                    viewModel.reauthLocked.collect { fired ->
                        if (fired) {
                            // Belt-and-braces: RunViewModel.lockForReauth
                            // now refuses to fire at all once the vault is null (including
                            // right after a deniable wipe), so this should be unreachable in
                            // practice — but never navigate the wipe cover away on the
                            // strength of a StateFlow race between this collector and the
                            // `wipedThisSession` read above.
                            if (!viewModel.wipedThisSession.value && !ProcessWipeCover.armed) {
                                navController.resetTo(Routes.PIN)
                            }
                            viewModel.consumeReauthLocked()
                        }
                    }
                }

                // Root detection: a risk signal the user can acknowledge and
                // continue past, never a hard block (see IntegrityGate).
                val integrityAck = remember {
                    mutableStateOf(false)
                }
                if (viewModel.isDeviceCompromised && !integrityAck.value) {
                    IntegrityGate(onAck = { integrityAck.value = true })
                    return@RunTheme
                }

                // Route to setup ONLY when no vault exists by EITHER measure.
                // isConfigured() reads the KeyValueStore; vaultFileExists() asks the
                // filesystem. The store read is the one that can transiently say
                // "fresh install" for a provisioned vault, and landing on setup is
                // not a cosmetic error — completing it provisions over the real
                // vault (the DB file is keyed with the old key, reads as NOTADB and
                // is deleted). The file check has no such failure mode, so requiring
                // BOTH to say "nothing here" is what keeps a bad store read from
                // costing the user every contact they have. VaultSelector's
                // provision guard is the backstop if anything still gets through.
                val startDestination = if (
                    viewModel.vaultSelector.isConfigured() || viewModel.vaultSelector.vaultFileExists()
                ) {
                    Routes.PIN
                } else {
                    Routes.SETUP
                }

                RunNavHost(
                    navController = navController,
                    viewModel = viewModel,
                    startDestination = startDestination,
                    activity = this@MainActivity,
                )

                // Lever-C warning countdown. Rendered as a sibling of the NavHost
                // via a Popup (its own window) — NOT a Box wrapping the NavHost:
                // wrapping made the NavHost pass unbounded height down and
                // collapsed ConversationScreen's weight(1f) message list to zero
                // (cross:multi caught it). A Popup contributes no layout node here,
                // so the NavHost keeps the exact constraints it had as the sole
                // child of setContent.
                LockCountdownOverlay(
                    secondsLeft = lockCountdownSecs.value,
                    isReauth = lockCountdownIsReauth.value,
                    onStay = { keepUnlocked() }
                )
            }
            }
        }
    }

    /**
     * Renders ONLY the black deniable-wipe cover when [ProcessWipeCover] is armed
     * and returns true, so onCreate stops there.
     */
    private fun renderProcessWipeCoverIfArmed(): Boolean {
        // A completed in-session emergency wipe keeps the PROCESS
        // alive behind a black, powered-off-looking cover (see
        // RunViewModel.performEmergencyWipe / PinEntryScreen's `isWiped` early
        // return) so a seized device looks dead rather than revealing a wipe
        // happened. That flag lived in `remember { mutableStateOf(false) }` —
        // COMPOSITION-local, not `rememberSaveable`, not on the retained
        // ViewModel — so it evaporates the instant the composition is rebuilt.
        // MainActivity.onStop() deliberately skips finishAndRemoveTask() during
        // a configuration change (rotation), so a rotation recreates THIS
        // Activity in the SAME PROCESS and rebuilds the composition from
        // scratch — reverting the black cover to an interactive PIN prompt (or,
        // via NavHost's restored back-stack route, straight past it) on one
        // tool-free action, in exactly the coercion scenario the cover exists
        // for. [ProcessWipeCover] is RAM-only but PROCESS-lifetime, not
        // composition-lifetime, so it survives the recreation — short-circuit
        // BEFORE any of onCreate's vault-state reads (TestHooks, InactivityWipe,
        // the orphan check, isConfigured()/vaultFileExists() for
        // startDestination) run against state this same process may have
        // already crypto-erased and deleted. The same `remember`-local pattern
        // exists in ChangePinScreen.kt and RecoveryEntryScreen.kt; gating here
        // covers all of them at once, since none of them is reachable without
        // going through this onCreate first. Mirrors iOS, whose equivalent flag
        // (AppState.wipedThisSession) lives on the StateObject rather than a
        // View's @State for the identical reason (ContentView's wiped_cover
        // branch) — this is the Android-side parity fix.
        //
        // [ProcessWipeCover], NOT [ProcessWipeLatch]. Gating this on the latch
        // was a regression: the latch is armed by EVERY wipe,
        // including the launch-time ones onCreate runs next (InactivityWipe, the
        // orphaned-credential self-heal, the debug test-wipe hook) that exist
        // precisely to fall through to setup. That black-screened a HEALTHY,
        // freshly re-provisioned vault on the first rotation — permanently, since
        // nothing but a force-quit clears a process-lifetime flag. The cover is
        // armed only by a DENIABLE in-session wipe; see ProcessWipeCover's kdoc.
        if (ProcessWipeCover.armed) {
            LogBuffer.append("W", "MainActivity",
                "process-wipe cover armed on (re)create — rendering the black cover only")
            setContent {
                Box(
                    Modifier
                        .fillMaxSize()
                        .background(RunBlack)
                )
            }
            return true
        }
        return false
    }

    /**
     * The launch-time e2e hooks (real implementations in src/debug only; release
     * links no-op stubs) and the channel-name refresh, in their original order.
     */
    private fun runLaunchTestHooks() {
        // e2e test-wipe hook — must run BEFORE any vault state loads. The real
        // implementation lives only in src/debug; release links a no-op
        // TestHooks, so the wipe-via-intent path is absent from shipped builds
        // (compiled out, not merely dead-stripped). Safe to call unconditionally.
        TestHooks.handleTestWipe(this, intent)

        // e2e app-language pin (`--es test_language <tag>`) — the Android
        // sibling of iOS's `--test-language=` launch argument, and the only
        // lever that exists below API 33 (`cmd locale set-app-locales` is
        // API 33+, and the test phones include an API-30 phone). Must run
        // AFTER handleTestWipe: the wipe resets the per-app language to
        // follow-system, so pinning before it would be undone. May
        // relaunch this Activity (both AppLocale.apply arms do) — it consumes
        // the extra first, so the relaunch is one-shot. Real implementation in
        // src/debug only; release links a no-op stub.
        TestHooks.handleTestLanguage(this, intent)

        // Localization: pick up a language change made while this process was
        // already running (e.g. API 29-32 AppLocale.apply on a DIFFERENT
        // MainActivity instance in the same process) by re-localizing the
        // channel NAME on any channel that already exists. Never CREATES one
        // (see the function's own doc) — a channel's existence is evidence
        // push was opted into, and this must not manufacture that evidence.
        NotificationHelper.refreshChannelNameIfExists(this)

        // Periodic random re-auth at MAXIMUM (docs/periodic-reauth-design.md):
        // e2e-only fixed-interval override, absent from release (see TestHooks).
        // Must also run before any vault opens — ReauthPolicy.isEnabled is read
        // by onVaultOpened on the FIRST unlock, so the override has to be armed
        // before that.
        TestHooks.handleTestReauth(intent)

        // e2e-only: force the update nudge's Play-Store two-button variant to
        // render on this sideloaded/emulator debug build (RunViewModel.isPlayInstall
        // has no real installer-of-record to check there otherwise). Real
        // implementation in src/debug only; release links a no-op stub — see
        // TestHooks.
        TestHooks.handleTestForceStoreInstall(intent)

        // e2e-only: the physical-phone A/B's no-hedge control arm for the descriptor hedge
        // (DescriptorHedge). `--ez TEST_DESCRIPTOR_HEDGE_OFF true` on the TEST_WIPE
        // launch; persisted by the debug TestHooks so the connect:cycle suite's
        // plain activateApp relaunches keep it. Release links a no-op stub, and
        // DescriptorHedge.setNoHedgeControl refuses outside a debug build anyway.
        TestHooks.handleTestDescriptorHedge(this, intent)
    }

    /** Orphaned-credential self-heal; see the comment inside. Runs before setContent. */
    private fun selfHealOrphanedCredentials() {
        // Orphaned-credential self-heal — parity with iOS
        // (AppState.runLaunchSecurityChecks / credentialsReadable). If a credential
        // verifier is stored but can't be decrypted with the current Android
        // Keystore key (Keystore reset, restore-to-new-device, or a reinstall that
        // regenerated the master key), the PIN-wrapped SQLCipher key is
        // unrecoverable — the vault data is already lost. Without this, isConfigured()
        // stays true and the user is stranded at a PIN screen that rejects EVERY PIN
        // until the wrong-PIN counter finally fires a destructive wipe. Detect the
        // orphan here and clean-reprovision to setup instead. credentialsReadable()
        // DEFERS (returns true) on a transient locked-key read, so a still-provisioned
        // vault is never false-wiped. Must run BEFORE setContent so the wipe's
        // deleteSharedPreferences is reflected by the fresh store RunViewModel builds.
        //
        // The probe DECRYPTS the credential
        // verifier, which unwraps the Tink/Keystore AES-256 data keyset into this
        // process — and it runs on EVERY launch of a configured vault, not only on
        // the rare orphan. The provider used to be constructed inline as an argument
        // (`crypto = CryptoProvider(this)`), so nothing here held a reference and
        // `VaultSelector.crypto` is private: there was no `wipeKey()` reachable from
        // MainActivity, and the unwrapped keyset stayed live through the rest of
        // onCreate and until GC, on a launch that then sits on the PIN screen. It is
        // owned in a named local now and scrubbed on every exit path. This provider
        // is a THROWAWAY, distinct from RunViewModel.cryptoProvider (which the unlock
        // actually uses), so the scrub cannot affect the unlock — and Android's
        // wipeKey() only drops the cached CryptoManager, which manager() re-creates
        // lazily on the next use anyway. Idiom: RunViewModel.performEmergencyWipe /
        // InactivityWipe / iOS AppState.inactivityCrypto (commit 41633aa).
        val orphanCrypto = CryptoProvider(this)
        try {
            val orphanCheck = VaultSelector(
                store = KeyValueStore(this, VAULT_SELECTOR_PREFS_NAME),
                crypto = orphanCrypto,
                // Never invoked by the readability probe (it opens no DB), but the
                // VaultSelector constructor requires a factory.
                vaultFactory = androidVaultFactory(this)
            )
            if (orphanCheck.isConfigured() && !orphanCheck.credentialsReadable()) {
                // Only crypto-erase when the device is UNLOCKED —
                // parity with InactivityWipe (above) and iOS (isProtectedDataAvailable).
                // credentialsReadable() DEFERS on a transient locked-key read, but that
                // relies on the Keystore failure surfacing as a keystore-typed cause; a
                // bare GeneralSecurityException on some OEM could classify a LOCKED good
                // vault as unreadable and wipe it. Gating on device state (not exception
                // taxonomy) means the destructive branch is never reached while locked.
                if (InactivityWipe.isDeviceCurrentlyLocked(this)) {
                    platformLogWarn("MainActivity", "orphan check deferred — device locked (avoid false-wipe)")
                } else {
                    platformLogWarn("MainActivity", "orphaned credentials detected — wiping (clean re-provision)")
                    // Crypto-erase-FIRST: drop the unwrapped keyset BEFORE the
                    // Keystore master key is destroyed, so a RAM acquisition right
                    // after the wipe can't recover what the wipe just erased on
                    // disk. Exactly InactivityWipe's ordering; the finally below is
                    // the catch-all for the non-destructive paths, not a substitute
                    // for this (it would run AFTER wipePersistentState).
                    try { orphanCrypto.wipeKey() } catch (_: Exception) { /* best-effort */ }
                    WipeRoutine.wipePersistentState(this)
                }
            }
        } finally {
            // Every other exit — above all the overwhelmingly common "vault is
            // healthy, keep going" one, and any throw out of the probe.
            // wipeKey() is idempotent, so the destructive branch's earlier call
            // is neither undone nor harmfully repeated. Wrapped because a throw
            // from a finally would REPLACE an in-flight exception.
            try { orphanCrypto.wipeKey() } catch (_: Exception) { /* best-effort */ }
        }
    }

    /** Tears the session down when VaultSelector retires the live vault handle. */
    private fun observeSessionRetirement() {
        // VaultSelector retired (closed) the live vault handle
        // mid-session — a SQLCipher re-key on a credential tier upgrade did not
        // verifiably commit, so the handle's codec write context can no longer be
        // trusted (see VaultSelector.retireRekeyedVaultHandle). The handle is
        // already closed; the only safe continuation is the same whole-session
        // teardown the Lever-C auto-lock uses (finishAndRemoveTask → onCleared
        // closes/nulls everything), after which the next unlock's rotation
        // reconcile reopens the vault under whichever key really holds the file.
        // Same ViewModel instance as setContent's viewModel() (same store +
        // default factory — the auto-lock watchdog relies on the same identity).
        val vm = ViewModelProvider(this).get(RunViewModel::class.java)
        lifecycleScope.launch {
            vm.vaultSessionRetired.collect { retired ->
                if (retired && !isFinishing && !isDestroyed) {
                    LogBuffer.append("W", "MainActivity",
                        "vault handle retired after a failed re-key — tearing down session (vault lock)")
                    finishAndRemoveTask()
                }
            }
        }
    }

    /**
     * Called when the Activity is no longer visible (user pressed home,
     * switched apps, or locked the screen). Finishes the Activity so
     * the next time it's opened, onCreate runs fresh with the PIN screen.
     * The vault is cleared when the ViewModel is destroyed.
     */
    override fun onStop() {
        super.onStop()
        // finishAndRemoveTask() below IS the whole-session teardown (onCleared ->
        // lockSession: vault closed, keyset wiped, Tor stopped or handed off).
        // armTorKeepAliveOnBackground() must run BEFORE it: the OS refuses a
        // foreground-service start from onCleared. The keep-alive's bound (about
        // 2 min, never on MAXIMUM) lives in TorKeepAlive.kt. Do not reorder.
        if (BuildConfig.DEBUG) {
            // Localization instrumentation only (no behavior change): proves
            // whether a language-switch relaunch (AppLocale.apply) trips this
            // whole-session teardown path or is correctly recognised as a
            // configuration change below.
            LogBuffer.append("D", "MainActivity",
                "onStop: isChangingConfigurations=$isChangingConfigurations")
        }
        // Don't finish during configuration changes (rotation, etc.).
        if (!isChangingConfigurations) {
            // Connection-log panel: the whole-session teardown starts here
            // (finishAndRemoveTask -> onCleared -> lockSession, which clears the
            // buffer). Logged before the clear so a config-change stop, which
            // does NOT tear down, still shows the transition.
            // Coded for the same reason as onResume's APP_FOREGROUNDED above.
            ConnectionLog.append(
                ConnectionLog.Kind.SYSTEM,
                "app backgrounded",
                ConnectionLog.Code.APP_BACKGROUNDED,
            )
            // Bounded Tor keep-alive (TorKeepAlive.kt): decide + start the
            // foreground service HERE, while the app is still leaving the
            // foreground (the OS refuses a later start from onCleared). The
            // teardown below is unchanged; lockSession only hands the live Tor to
            // the keeper instead of stopping it when this armed. Never under the
            // deniable-wipe cover: there the ViewModel may not even exist, and
            // ViewModelProvider would CONSTRUCT one (see onResume).
            if (!ProcessWipeCover.armed) {
                try {
                    androidx.lifecycle.ViewModelProvider(this)
                        .get(RunViewModel::class.java)
                        .armTorKeepAliveOnBackground()
                } catch (_: Exception) { /* best-effort: Tor then stops as before */ }
            }
            finishAndRemoveTask()
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        // Drop the pending single-window pause-cover fallback (see onPause) so a
        // destroyed instance's Runnable can't fire finishAndRemoveTask() late (a
        // config-change recreation guards against posting it in the first place, but
        // this covers every other destroy path defensively).
        pauseCoverHandler.removeCallbacks(pauseCoverTeardown)
    }

    private companion object {
        // How long the single-window
        // paused-not-stopped fallback (onPause) waits before treating a still-paused
        // Activity as a real cover rather than one of Rún's own in-app prompts.
        // BiometricGate.authenticate (shared/androidMain/BiometricGate.kt) bounds its
        // own platform BiometricPrompt at 120 s before giving up; the CAMERA
        // permission dialog for QR pairing resolves in a user tap, far under that.
        // Staying comfortably above BiometricGate's ceiling means onResume's cancel
        // (above) always wins for a genuine in-app prompt — this only ever fires when
        // foreground never came back at all.
        private const val PAUSE_COVER_GRACE_MS = 150_000L // 2m30s
    }
}

/**
 * The app's navigation graph. Rendered from MainActivity's setContent only AFTER
 * the deniable-wipe cover and the integrity gate have had their say (both return
 * early before this call). Declared below MainActivity on purpose: source tests
 * take the FIRST `NavHost(` in the file as "the NavHost call", which must stay
 * after the cover branch.
 */
@OptIn(ExperimentalComposeUiApi::class)
@Composable
private fun RunNavHost(
    navController: NavHostController,
    viewModel: RunViewModel,
    startDestination: String,
    activity: ComponentActivity,
) {
    NavHost(
        navController = navController,
        startDestination = startDestination,
        modifier = Modifier.semantics { testTagsAsResourceId = BuildConfig.DEBUG }
    ) {
        entryRoutes(navController, viewModel, activity)
        sessionRoutes(navController, viewModel, activity)
    }
}

/**
 * The pre-session half of the graph: first-launch setup, the move flows, the
 * PIN / recovery unlock and the protection-level choice. Everything here is
 * reachable with NO open vault.
 */
@OptIn(ExperimentalComposeUiApi::class)
private fun NavGraphBuilder.entryRoutes(
    navController: NavHostController,
    viewModel: RunViewModel,
    activity: ComponentActivity,
) {
    // First launch forks here (docs/device-move.md, phone B):
    // "set up as new" and "move from another phone" both continue
    // into the SAME PinSetupScreen — the move never changes how a
    // vault is provisioned, it only leaves a handle in RAM that
    // the first unlock then imports.
    composable(Routes.SETUP) {
        SetupChooserScreen(
            onSetUpAsNew = { navController.navigate(Routes.SETUP_PIN) },
            onMoveFromPhone = { navController.navigate(Routes.SETUP_MOVE) },
        )
    }

    composable(Routes.SETUP_MOVE) {
        MoveFromDeviceScreen(
            onHandle = { handle ->
                // RAM only — never persisted (it carries the read
                // capability AND the one-time code). A process
                // death here simply means rescan.
                viewModel.setPendingMoveHandle(handle)
                navController.navigate(Routes.SETUP_PIN)
            },
            onBack = { navController.popBackStack() },
        )
    }

    composable(Routes.SETUP_PIN) {
        PinSetupScreen(
            viewModel = viewModel,
            onSetupComplete = { openedRealVault ->
                // First run opens the real vault directly after
                // the PINs are chosen; only fall back to the PIN
                // screen if the auto-open somehow failed. With a
                // scanned handle waiting, the import runs first.
                navController.navigateClearing(
                    postSetupRoute(openedRealVault, viewModel.pendingMoveHandle != null),
                    upTo = Routes.SETUP,
                )
            }
        )
    }

    composable(Routes.MOVE_IMPORT) {
        MoveImportScreen(
            viewModel = viewModel,
            onImported = {
                navController.resetTo(Routes.CONTACTS)
            },
            onSkipped = {
                navController.resetTo(Routes.CONTACTS)
            },
        )
    }

    // Old phone. "move_export" is the settings entry (explainer
    // first); "move_frozen" is where EVERY unlock lands while the
    // vault carries `mig_frozen`, so a frozen phone can never
    // reach the contact list — reachable would mean polling, and
    // one received message forks the new phone's ratchet.
    composable(Routes.MOVE_EXPORT) {
        MoveToNewDeviceScreen(
            viewModel = viewModel,
            frozenEntry = false,
            onBack = { navController.popBackStack() },
            onUnfrozen = {
                navController.resetTo(Routes.CONTACTS)
            },
            onWiped = {
                navController.resetTo(Routes.SETUP)
            },
        )
    }

    composable(Routes.MOVE_FROZEN) {
        MoveToNewDeviceScreen(
            viewModel = viewModel,
            frozenEntry = true,
            onBack = { },
            onUnfrozen = {
                navController.resetTo(Routes.CONTACTS)
            },
            onWiped = {
                navController.resetTo(Routes.SETUP)
            },
        )
    }

    composable(Routes.PIN) {
        PinEntryScreen(
            viewModel = viewModel,
            onUnlocked = {
                val next = moveAwarePostUnlockRoute(
                    postUnlockRoute(viewModel.vaultSelector, deviceLockState(activity)),
                    moveFrozen = viewModel.moveManager.isFrozen(),
                    pendingMoveImport = viewModel.pendingMoveHandle != null,
                )
                navController.navigateClearing(next, upTo = Routes.PIN)
            },
            onUseRecoveryCode = {
                navController.navigate(Routes.RECOVER)
            },
            // The orphaned vault was erased, so the file the routing
            // check keys on is gone and setup is now the correct — and
            // no longer destructive — destination.
            onVaultErased = {
                navController.navigateClearing(Routes.SETUP, upTo = Routes.PIN)
            }
        )
    }

    composable(Routes.RECOVER) {
        RecoveryEntryScreen(
            viewModel = viewModel,
            onRecovered = {
                // Recovery re-provisions the vault plain — it may have no
                // level either, so run the same post-unlock check. A
                // recovery-code unlock of a FROZEN vault is still a
                // frozen vault: same routing, same reason.
                val next = moveAwarePostUnlockRoute(
                    postUnlockRoute(viewModel.vaultSelector, deviceLockState(activity)),
                    moveFrozen = viewModel.moveManager.isFrozen(),
                    pendingMoveImport = viewModel.pendingMoveHandle != null,
                )
                navController.navigateClearing(next, upTo = Routes.PIN)
            },
            onCancel = { navController.popBackStack() }
        )
    }

    composable(Routes.PROTECTION_SETUP) {
        ProtectionLevelMigrationScreen(
            viewModel = viewModel,
            onDone = {
                navController.navigateClearing(Routes.CONTACTS, upTo = Routes.PROTECTION_SETUP)
            }
        )
    }

    // Forced tier change: this vault is below the floor its device
    // now requires (no lock screen → MAXIMUM, DeviceLockPolicy).
    // Reuses the settings flow because that is the one place that
    // drives the CREDENTIAL change inline — persisting the tier
    // alone would claim a passphrase this vault doesn't have.
    //
    // This is a GATE, not a nag, and it
    // used to be neither — onBack navigated to "contacts"
    // unconditionally, so one Cancel tap on the credential step
    // dropped a lock-less phone back into the app at CASUAL (it
    // re-presented on the next unlock, but the vault stayed fully
    // usable at a ~20-bit PIN in between, which is all a seizure
    // needs). iOS closed the identical hole
    // (ContentView.swift) by RE-EVALUATING the policy on dismiss;
    // this is that fix, from the same inputs postUnlockRoute uses.
    // The two legitimate ways out are unchanged: finish the
    // migration (an authenticated MAXIMUM clears the floor), or set
    // a device passcode — leaving for Settings backgrounds the app,
    // which finishAndRemoveTask()s it, so the re-probe happens on
    // the next launch's unlock.
    composable(Routes.PROTECTION_FORCED) {
        // Delegates to [postUnlockRoute] rather than re-deriving a
        // boolean, so all THREE of its answers are honoured — in
        // particular a `null` floor read goes to the one-time
        // chooser here exactly as it does at unlock, never to
        // "contacts". Returns whether it left.
        val leaveIfNoLongerForced: () -> Boolean = {
            val next = postUnlockRoute(
                viewModel.vaultSelector,
                deviceLockState(activity),
            )
            if (next == Routes.PROTECTION_FORCED) {
                false
            } else {
                navController.navigateClearing(next, upTo = Routes.PROTECTION_FORCED)
                true
            }
        }
        // Route-level BACK. The screen's own handler (credential
        // step → back to the chooser, which carries the "set a
        // device passcode" button, and a swallow while a write is
        // in flight) is nested deeper and wins while it is enabled,
        // so this fires on the BARE chooser.
        //
        // There, BACK must not be SWALLOWED: a
        // dead BACK button on the first screen of the session is
        // indistinguishable from a hung app, and the pre-diff
        // behaviour was a real, honest exit — the back stack under
        // this route is empty, so BACK finished the Activity, whose
        // onStop then finishAndRemoveTask()s the task with the vault
        // locked. That is not an escape: nothing is reachable
        // afterwards, and the next launch re-probes and re-presents
        // this gate. So leave the app instead of ignoring the press.
        BackHandler(enabled = true) {
            if (!leaveIfNoLongerForced()) {
                LogBuffer.append("W", "ProtectionLevel",
                    "back on the forced tier gate — finishing (vault locks, gate re-presents next launch)")
                activity.finish()
            }
        }
        ProtectionLevelSettingsScreen(
            viewModel = viewModel,
            forced = true,
            onBack = {
                if (!leaveIfNoLongerForced()) {
                    LogBuffer.append("W", "ProtectionLevel",
                        "forced tier change dismissed but the floor still applies — staying")
                }
            },
        )
    }
}

/**
 * The in-session half of the graph: the contact list and everything opened
 * from it. Every screen here assumes an open vault (a lock routes back to
 * [Routes.PIN] with the whole back stack cleared).
 */
@OptIn(ExperimentalComposeUiApi::class)
private fun NavGraphBuilder.sessionRoutes(
    navController: NavHostController,
    viewModel: RunViewModel,
    activity: ComponentActivity,
) {
    composable(Routes.CONTACTS) {
        // Defense in depth. Several
        // callbacks reach the contact list WITHOUT consulting the
        // floor — the two MoveToNewDeviceScreen `onUnfrozen`s and
        // the one-time chooser's `onDone` — so a lock-less phone
        // could land here at CASUAL and stay until the next unlock.
        // Re-ask the SAME decision on entry instead of checking
        // every inbound edge: one cheap floor read + KeyguardManager
        // probe per entry to this destination, and a no-op in the
        // overwhelmingly common case. Re-runs on every re-entry (a
        // pop back from a conversation) on purpose — that is what
        // makes it cover future callers too.
        //
        // Narrowed to the FORCED answer on purpose. The unlock path
        // keeps [postUnlockRoute]'s full three-way result, but here
        // an ambiguous read (`null` ⇒ "protection_setup") must NOT
        // bounce the user out of the contact list: this effect
        // re-runs on every re-entry, and DeviceLockPolicy's own rule
        // is that only a DEFINITE "no lock" forces anything —
        // ambiguity is never evidence. The once-per-vault chooser
        // stays a decision for unlock, where it is reached once.
        LaunchedEffect(Unit) {
            val next = postUnlockRoute(
                viewModel.vaultSelector,
                deviceLockState(activity),
            )
            if (next == Routes.PROTECTION_FORCED) {
                LogBuffer.append("W", "ProtectionLevel",
                    "contact list entered while the tier floor still applies — rerouting to the gate")
                navController.navigateClearing(next, upTo = Routes.CONTACTS)
            }
        }
        ContactListScreen(
            viewModel = viewModel,
            onContactTapped = { contactId ->
                navController.navigate(Routes.conversation(contactId))
            },
            onAddContact = {
                navController.navigate(Routes.ADD_CONTACT)
            },
            onChangePin = {
                navController.navigate(Routes.CHANGE_PIN)
            },
            onGroupTapped = { groupId ->
                navController.navigate(Routes.group(groupId))
            },
            onCreateGroup = {
                navController.navigate(Routes.CREATE_GROUP)
            },
            onProtectionLevel = {
                navController.navigate(Routes.PROTECTION_LEVEL)
            },
            onMoveToNewDevice = {
                navController.navigate(Routes.MOVE_EXPORT)
            }
        )
    }

    composable(Routes.PROTECTION_LEVEL) {
        ProtectionLevelSettingsScreen(
            viewModel = viewModel,
            onBack = { navController.popBackStack() }
        )
    }

    composable(Routes.CREATE_GROUP) {
        CreateGroupScreen(
            viewModel = viewModel,
            onCreated = { groupId ->
                navController.replaceTop(Routes.group(groupId))
            },
            onBack = {
                navController.popBackStack()
            }
        )
    }

    composable(
        route = Routes.GROUP,
        arguments = listOf(
            navArgument("groupId") { type = NavType.StringType }
        )
    ) { backStackEntry ->
        val groupId = backStackEntry.arguments?.getString("groupId") ?: return@composable
        GroupConversationScreen(
            viewModel = viewModel,
            groupId = groupId,
            onBack = {
                navController.popBackStack()
            },
            onOpenInfo = {
                navController.navigate(Routes.groupInfo(groupId))
            },
            // NO-PARK: another group's GROUP_ECHO "Open group" replaces this one.
            onOpenGroup = { otherGroupId ->
                navController.replaceTop(Routes.group(otherGroupId))
            }
        )
    }

    composable(
        route = Routes.GROUP_INFO,
        arguments = listOf(
            navArgument("groupId") { type = NavType.StringType }
        )
    ) { backStackEntry ->
        val groupId = backStackEntry.arguments?.getString("groupId") ?: return@composable
        GroupInfoScreen(
            viewModel = viewModel,
            groupId = groupId,
            onLeft = {
                // Left or removed — drop out of the group's
                // conversation stack entirely.
                navController.popBackStack(Routes.CONTACTS, inclusive = false)
            },
            onBack = {
                navController.popBackStack()
            }
        )
    }

    composable(Routes.CHANGE_PIN) {
        ChangePinScreen(
            viewModel = viewModel,
            onDone = {
                navController.popBackStack()
            },
            onCancel = {
                navController.popBackStack()
            }
        )
    }

    composable(Routes.ADD_CONTACT) {
        AddContactScreen(
            viewModel = viewModel,
            onContactAdded = {
                navController.popBackStack()
            },
            onBack = {
                navController.popBackStack()
            }
        )
    }

    composable(
        route = Routes.CONVERSATION,
        arguments = listOf(
            navArgument("contactId") { type = NavType.StringType }
        )
    ) { backStackEntry ->
        val contactId = backStackEntry.arguments?.getString("contactId") ?: return@composable
        ConversationScreen(
            viewModel = viewModel,
            contactId = contactId,
            onBack = {
                navController.popBackStack()
            },
            // NO-PARK: a GROUP_ECHO bubble's "Open group" REPLACES this
            // conversation (back then returns to the contact list).
            onOpenGroup = { groupId ->
                navController.replaceTop(Routes.group(groupId))
            }
        )
    }
}

/**
 * The compromised-device screen. Root detection is a bypassable HEURISTIC, not a
 * boundary: surface it as a risk signal the user can acknowledge and continue
 * past. A hard block helps no one (a real attacker patches the check out) while
 * it locks out privacy-conscious rooted / custom-ROM users, who ARE the audience
 * for a Tor messenger.
 */
@Composable
private fun IntegrityGate(onAck: () -> Unit) {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(RunBlack),
        contentAlignment = Alignment.Center
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(
                stringResource(R.string.gate_compromised_title),
                style = MaterialTheme.typography.headlineSmall,
                color = RunWhite
            )
            Spacer(
                modifier = Modifier.height(12.dp)
            )
            Text(
                stringResource(R.string.gate_compromised_body),
                style = MaterialTheme.typography.bodyMedium,
                color = RunGrey,
                textAlign = TextAlign.Center,
                modifier = Modifier.padding(horizontal = 32.dp)
            )
            Spacer(
                modifier = Modifier.height(24.dp)
            )
            TextButton(
                onClick = onAck
            ) {
                Text(stringResource(R.string.gate_compromised_continue))
            }
        }
    }
}

/**
 * Where the setup flow lands (docs/device-move.md, phone B step 3-4).
 *
 * Pure, so the decision is unit-testable without an Activity: the vault-open
 * failure still routes to the PIN screen exactly as before, and a handle
 * scanned before onboarding sends the first unlock through the import screen
 * instead of straight to the contact list.
 */
internal fun postSetupRoute(openedRealVault: Boolean, hasPendingMoveHandle: Boolean): String = when {
    !openedRealVault -> Routes.PIN
    hasPendingMoveHandle -> Routes.MOVE_IMPORT
    else -> Routes.CONTACTS
}

/**
 * Move-aware wrapper around [postUnlockRoute]'s answer.
 *
 * Frozen wins over everything, including the protection-tier screens: this
 * device is the OLD phone of a move, it is not sending or receiving, and the
 * only decisions left are finish / cancel / wipe. A pending import (NEW phone,
 * handle in RAM, first unlock) comes next; otherwise the ordinary route stands.
 *
 * Both flags are read from RAM/one `_meta` read at the call site, so this stays
 * a pure function over them.
 */
internal fun moveAwarePostUnlockRoute(
    baseRoute: String,
    moveFrozen: Boolean,
    pendingMoveImport: Boolean,
): String = when {
    moveFrozen -> Routes.MOVE_FROZEN
    pendingMoveImport -> Routes.MOVE_IMPORT
    else -> baseRoute
}

/**
 * Where a successful unlock lands — and, since 2026-09-22, where
 * the forced gate's own dismissal and an entry to the contact list land too.
 * A PURE function of the floor read and the lock probe. THREE outcomes, checked
 * in this order, and every consumer must honour all three:
 *  1. No level ever chosen (legacy pre-slider vault) — or a read that PROVES
 *     nothing (damaged blob / device-key outage) → the one-time chooser. That is
 *     NOT "no gate": the chooser cannot persist an unproven MAXIMUM
 *     either, so the floor is re-armed rather than escaped, and its write
 *     self-heals the slot.
 *  2. The stored level is BELOW the floor this device requires — i.e. the phone
 *     has no lock screen, so the device-key half of CR-1 is free to anyone
 *     holding it and only a passphrase still protects the vault → the forced
 *     tier change. This runs on EVERY unlock on purpose: gating the chooser
 *     alone would miss the phone that HAD a lock screen at provision time and
 *     lost it afterwards, which on Android CASUAL nothing else detects (no
 *     auth-bound key to invalidate; setUnlockedDeviceRequired simply goes
 *     vacuous). See DeviceLockPolicy.
 *  3. Otherwise → straight to contacts.
 *
 * The forced route's EXIT used to re-derive this with a two-way boolean, so a
 * `null` read there fell into "not forced ⇒ contacts" while the unlock path sent
 * the same state to the chooser. One decision, one place.
 */
internal fun protectionRouteFor(stored: ProtectionLevel?, lock: DeviceLockState): String = when {
    stored == null -> Routes.PROTECTION_SETUP
    DeviceLockPolicy.needsForcedMigration(stored, lock) -> Routes.PROTECTION_FORCED
    else -> Routes.CONTACTS
}

/**
 * [protectionRouteFor] over the live vault.
 *
 * The forced-MAXIMUM migration must read the PROVENANCE-aware floor
 * accessor, never the lenient protectionLevelOrNull() — an unauthenticated
 * (planted cleartext) vlt_lvl must count as "not proven at the floor ⇒ force",
 * not as a trusted MAXIMUM that suppresses the migration.
 *
 * Called at unlock, on the forced route's dismissal (the Android twin of iOS's
 * re-evaluation), and once on entry to the contact list — so a tier state
 * that changed under any of them cannot route three different ways.
 */
internal fun postUnlockRoute(vaultSelector: VaultSelector, lock: DeviceLockState): String {
    val stored = vaultSelector.protectionLevelForFloorCheck()
    val route = protectionRouteFor(stored, lock)
    if (route == Routes.PROTECTION_FORCED) {
        LogBuffer.append("W", "ProtectionLevel",
            "device has no lock screen and vault is at ${stored?.storageValue} — forcing the tier change")
    }
    return route
}

// ---------------------------------------------------------------------------
// Lever-C warning countdown overlay (threat-slider spec): shown for
// the last AUTO_LOCK_WARNING_MS before the idle auto-lock closes the app —
// matters most at MAXIMUM's 60 s, where a long read otherwise ends in an
// unexplained app close. Purely informational: the lock deadline is UNCHANGED
// (the warning sits inside the Lever-C window, never extends it). Since
// docs/periodic-reauth-design.md this ALSO renders the periodic re-auth
// warning ([isReauth] true) — same overlay, different copy, and with NO "tap
// to stay" affordance (that deadline never moves regardless of touches).
//
// Rendered in a full-screen focusable Popup, deliberately NOT a Box wrapping the
// NavHost — wrapping forced the NavHost to pass unbounded height down and
// collapsed ConversationScreen's weight(1f) message list to zero (regression
// caught by cross:multi). A Popup lives in its own window and adds no layout
// node to the NavHost's parent. Because of that separate window, its taps do
// NOT reach Activity.onUserInteraction, so the scrim's tap calls [onStay]
// directly to reset the IDLE clock (Lever C only — a tap can never defer the
// re-auth deadline) and consumes the tap so it can't fall through. Never
// visible in a debug build with NO periodic-re-auth override armed — the
// countdown state is written only by the shared watchdog, whose Lever-C
// branch is release-only and whose re-auth branch is debug-off-by-default.
// ---------------------------------------------------------------------------
@Composable
private fun LockCountdownOverlay(secondsLeft: Int?, isReauth: Boolean, onStay: () -> Unit) {
    if (secondsLeft == null) return
    // Re-auth: dismissal is a no-op — nothing here can move that deadline, so
    // there is no "stay" gesture to honor.
    val noOpDismiss: () -> Unit = {}
    // Rendered as a Dialog, not a Popup. A Popup and a Dialog are both separate
    // windows, but an already-open Dialog (About carousel, Donate/tip flow, referral
    // picker, group invite) sat ON TOP of the Popup — so in exactly the situation
    // the countdown exists for, the user saw no warning at all before the app
    // closed. The countdown is created last, so as a Dialog it lands above them.
    // Still adds no layout node to the NavHost's parent (the reason this was never
    // a Box wrapper — see the note above).
    Dialog(
        // dismissOnClickOutside/BackPress disabled below for re-auth too, so the
        // overlay stays up until the deadline fires.
        onDismissRequest = if (isReauth) noOpDismiss else onStay,
        properties = DialogProperties(
            usePlatformDefaultWidth = false,
            dismissOnClickOutside = !isReauth,
            dismissOnBackPress = !isReauth,
        ),
    ) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(RunBlack.copy(alpha = 0.85f))
                .let { if (isReauth) it else it.pointerInput(Unit) { detectTapGestures { onStay() } } },
            contentAlignment = Alignment.Center
        ) {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                if (isReauth) {
                    Text(
                        stringResource(R.string.gate_reauth_countdown, secondsLeft),
                        style = MaterialTheme.typography.headlineSmall,
                        color = RunWhite,
                        modifier = Modifier.testTag("reauth_countdown"),
                    )
                } else {
                    Text(
                        stringResource(R.string.gate_lock_countdown, secondsLeft),
                        style = MaterialTheme.typography.headlineSmall,
                        color = RunWhite
                    )
                    Spacer(
                        modifier = Modifier.height(12.dp)
                    )
                    Text(
                        stringResource(R.string.gate_lock_countdown_tap_to_stay),
                        style = MaterialTheme.typography.bodyMedium,
                        color = RunGrey
                    )
                }
            }
        }
    }
}

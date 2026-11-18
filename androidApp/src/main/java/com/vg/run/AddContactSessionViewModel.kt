package com.vg.run

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import java.util.concurrent.atomic.AtomicBoolean

// ---------------------------------------------------------------------------
// One add-contact pairing session (ratchet-bootstrap plan, phase 0 G2 + phase 2 §4.1).
//
// The pairing secret half used to live in `remember {}` inside AddContactScreen.
// MainActivity declares no `configChanges`, so rotation, a dark-mode / locale /
// font-scale switch or a fold recreated the Activity, rebuilt the composition,
// wiped the old half and generated a NEW one. A peer that had already scanned our
// secret-only QR then derived a different pairing secret than we did, and the
// pairing was silently dead.
//
// Lifetime rule (iOS sibling: `pairingSession` in AddContactView.swift):
//   ONE pairing session = ONE [PairingSession] (one secret half + one one-time
//   key). It survives a configuration change and dies on a real leave.
//
//   * Survives: this ViewModel is obtained from the add-contact NavBackStackEntry,
//     whose ViewModelStore the NavController keeps across an Activity recreation.
//     The screen's dispose skips [endSession] while the Activity
//     `isChangingConfigurations`.
//   * Dies: [endSession] on every other dispose of the screen (finish, back arrow,
//     cancel pairing, nav-away, the vault-lock reset to the PIN route, the
//     emergency-wipe cover dropping the NavHost) and in [onCleared] (entry popped,
//     or the Activity finishing — which is how the whole-session background
//     teardown ends, so this holder cannot outlive the vault).
//   * After [endSession] the session is unusable (every accessor answers null or
//     throws, never zeroed bytes as key material). A screen that composes again for
//     the same entry gets a NEW session from [resumeOrStartNewSession] (fresh half,
//     fresh one-time key, wizard back at Choice). [restartPairing] does the same
//     without leaving the screen ("start again").
//
// Nothing here goes through SavedStateHandle, rememberSaveable or any Bundle: the
// secret half, the one-time key, the scanned peer code and the minted capabilities
// are RAM-only, and a process death loses the session (by design).
// ---------------------------------------------------------------------------

/**
 * Configuration-change-surviving state of one add-contact pairing session. See the
 * file header for the lifetime rule. The Compose-observable fields are the wizard
 * progress the screen used to `remember`; the screen binds them as delegated locals.
 */
internal class AddContactSessionViewModel(
    /** Test seam only: null (production) = [viewModelScope]. */
    private val mintScope: CoroutineScope? = null,
) : ViewModel() {

    private var pairing: PairingSession? = null

    /**
     * Bumped by [restartPairing]. The screen keys its session-derived values on it
     * (`remember(session, session.generation)`), so a restart inside a live
     * composition rebuilds the codes from the NEW session instead of the ended one.
     */
    var generation by mutableStateOf(0)
        private set

    /**
     * The running mint: which transport (MessageManager) it is bound to, its OWN
     * abort flag, and its job. A fresh flag per mint, never reset: `Job.cancel()`
     * does not stop the blocking grind inside mintInboxPair, so a shared flag
     * re-armed for a later mint would let an aborted grind resume and mint inboxes
     * nobody uses.
     */
    private class MintRun(val owner: Any, val abort: AtomicBoolean) {
        var job: Job? = null
    }
    private var currentMint: MintRun? = null

    /** The running mint's abort flag (null when none runs). Tests read it. */
    internal val runningMintAbortFlag: AtomicBoolean?
        get() = currentMint?.abort

    var mintState by mutableStateOf<MintState>(MintState.WaitingForRelay)
    var step by mutableStateOf(AddStep.Choice)
    var shown by mutableStateOf(false)
    var pendingContactId by mutableStateOf<String?>(null)
    var pendingAlias by mutableStateOf("")
    var mnemonicText by mutableStateOf("")
    var savedPeerInboxId by mutableStateOf<String?>(null)
    var peerInboxArrived by mutableStateOf(false)
    var showCancelPairing by mutableStateOf(false)
    var addError by mutableStateOf<String?>(null)

    /**
     * The scan-first side's key confirmation failed (the two phones derived different
     * keys): the Done step shows "pairing failed — start again". Reset by
     * [endSession] / [restartPairing].
     */
    var pairingFailed by mutableStateOf(false)

    private var scannedState by mutableStateOf<ScannedContact?>(null)

    /**
     * The scanned peer code ([ScannedContact] wraps the parsed [PairingScan]). It is
     * dropped on replace / clear / [endSession]; the peer's half inside it is text
     * (the code's own base64), which cannot be zeroed — the decoded copy that the
     * save makes is wiped by [PairingSession.save] itself. Re-assigning the same
     * instance is a no-op, so a failed save keeps the scan for the retry.
     */
    var scannedData: ScannedContact?
        get() = scannedState
        set(value) {
            scannedState = value
        }

    /**
     * This session's secret half: the SAME array across configuration changes. If
     * the previous session was ended (its half wiped), a new session starts here
     * instead — never the zeroed bytes.
     */
    fun resumeOrStartNewSession(): ByteArray = currentPairing().mySecretHalf()

    /**
     * The live [PairingSession] (codes, parse, save). Starts a new one if none is
     * open or the previous one ended. The screen reads it only from composition
     * (inside `remember`) and from event handlers.
     */
    fun currentPairing(): PairingSession {
        val current = pairing
        if (current != null && current.isActive) return current
        val fresh = PairingSession.start()
        pairing = fresh
        return fresh
    }

    /** True while a session is open and its half is usable. */
    val isActive: Boolean
        get() = pairing?.isActive == true

    /**
     * "Start again": a real end of this session (abort the mint, wipe, reset the
     * wizard), then a NEW session in the same screen. [error] is shown above the
     * wizard afterwards (set AFTER the reset, which clears it).
     */
    fun restartPairing(error: String? = null) {
        endSession()
        currentPairing()
        generation++
        addError = error
    }

    /** Production wiring: the mint runs on [mgr] via [MessageManager.mintInboxPair]. */
    fun startMintIfIdle(mgr: MessageManager, toState: (MintedInboxPair?) -> MintState): Boolean =
        startMintIfIdle(mgr, { abort -> mgr.mintInboxPair(abort = abort) }, toState)

    /**
     * Starts the inbox mint on transport [owner] unless it is not needed:
     *  - Ready → kept, always. Its inboxes are relay-side capabilities that do not
     *    depend on the transport, and once saved into a (pending) contact they are
     *    the ones the peer must reach — replacing them would strand the pairing.
     *  - Solving on the SAME [owner] → no-op, so a recomposition after a
     *    configuration change re-attaches to the running grind.
     *  - Solving on a DIFFERENT owner (Tor recycled, RunViewModel built a new
     *    MessageManager) → that mint is aborted (its own flag) and a new one starts
     *    here. The secret half is not touched, so the instant secret-only code the
     *    peer may already have scanned stays byte-identical.
     * [toState] maps the result (null = the relay could not be reached) onto the
     * screen's MintState. A result from a superseded / aborted mint, or one that
     * lands after [endSession], is dropped. Returns true when a mint was started.
     */
    fun startMintIfIdle(
        owner: Any,
        minter: suspend (PowAbort) -> MintedInboxPair?,
        toState: (MintedInboxPair?) -> MintState,
    ): Boolean {
        val half = pairing ?: return false
        if (!half.isActive) return false
        when (mintState) {
            is MintState.Ready -> return false
            is MintState.Solving -> {
                if (currentMint?.owner === owner) return false
                abortRunningMint()
            }
            else -> Unit
        }
        val abort = AtomicBoolean(false)
        val run = MintRun(owner, abort)
        currentMint = run
        mintState = MintState.Solving
        run.job = (mintScope ?: viewModelScope).launch {
            val result = minter(PowAbort { abort.get() })
            if (currentMint !== run || abort.get() || !half.isActive || pairing !== half) return@launch
            currentMint = null
            mintState = toState(result)
        }
        return true
    }

    /**
     * The transport under a RUNNING mint is gone ([current] is null or a different
     * MessageManager): abort that mint and park in WaitingForRelay, so the screen's
     * re-arm starts a new one once a transport is back. Ready / Failed / waiting
     * states are left alone.
     */
    fun abandonMintIfTransportChanged(current: Any?) {
        if (mintState !is MintState.Solving) return
        if (current != null && currentMint?.owner === current) return
        abortRunningMint()
        mintState = MintState.WaitingForRelay
    }

    /** Sets the running mint's OWN flag (never reset) and cancels its job. */
    private fun abortRunningMint() {
        currentMint?.let { run ->
            run.abort.set(true)
            run.job?.cancel()
        }
        currentMint = null
    }

    /**
     * A real leave: abort the mint, end the pairing session (zeroes our half and the one-time key), and drop
     * the minted capabilities and the wizard progress. Idempotent. NOT called on a
     * configuration-change dispose.
     */
    fun endSession() {
        abortRunningMint()
        // Zeroes the half in place (every alias: MintState.Ready, the scan / paste
        // children) and the one-time private key; the session is unusable after.
        pairing?.end()
        pairing = null
        scannedData = null
        // MintState.Ready aliases the (now zeroed) half and holds our inbox read
        // caps; drop the reference so nothing renders or saves from it.
        mintState = MintState.WaitingForRelay
        step = AddStep.Choice
        shown = false
        pendingContactId = null
        pendingAlias = ""
        mnemonicText = ""
        savedPeerInboxId = null
        peerInboxArrived = false
        showCancelPairing = false
        addError = null
        pairingFailed = false
    }

    override fun onCleared() {
        endSession()
        super.onCleared()
    }
}

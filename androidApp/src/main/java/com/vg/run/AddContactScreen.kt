package com.vg.run

import android.Manifest
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.util.Base64
import android.util.Size
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.resolutionselector.ResolutionSelector
import androidx.camera.core.resolutionselector.ResolutionStrategy
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalResources
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.viewmodel.compose.viewModel
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.vg.run.ui.theme.RunBlack
import com.vg.run.ui.theme.RunError
import com.vg.run.ui.theme.RunGrey
import com.vg.run.ui.theme.RunSurface
import com.vg.run.ui.theme.RunSurfaceAlt
import com.vg.run.ui.theme.RunWhite
import java.util.UUID
import java.util.concurrent.Executors
import androidx.activity.compose.BackHandler
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.lifecycle.LifecycleOwner
import android.content.Context
import android.os.SystemClock
import com.google.zxing.ChecksumException
import com.google.zxing.FormatException
import com.google.zxing.NotFoundException
import java.util.concurrent.ExecutorService

// ---------------------------------------------------------------------------
// AddContactScreen — secure contact exchange via QR code.
//
// Security purpose:
//
//   • Contact exchange is done in-person via QR code. No server, no phone
//     number lookup, no username search — there is no central directory that
//     could be subpoenaed or surveilled to reveal who talks to whom.
//
//   • The QR code carries this device's mint result — a server-generated
//     inbox ID + this device's write-capability — plus our half of the shared
//     secret. The peer scans it, gives us back theirs, and both devices
//     persist a (peerInboxId, peerWriteCap) outbound record + our own
//     (myInboxId, myReadCap) inbound record. Read caps stay local; only
//     write caps cross the QR.
//
//   • The camera is used exclusively for QR decoding. No image is captured,
//     buffered, or stored — each frame is analysed in-memory and immediately
//     discarded. The camera is released as soon as a valid QR is decoded.
//
//   • The user chooses an alias (pseudonym) for the new contact. No real
//     name, phone number, or email is collected or stored.
//
//   • Mint requires a Hashcash-style PoW (~1–5s on a phone) and is started
//     in the background as soon as the screen opens. A spinner is shown
//     until mint completes. Backing out cancels the solve via [PowAbort].
// ---------------------------------------------------------------------------

/**
 * Shown when the vault refuses the add because one of the peer's inbox ids
 * already belongs to a contact we hold (`InboxInUseException`). `inbox_ids` is
 * keyed by inboxId with replace-on-conflict, so accepting it would have silently
 * destroyed the other contact's route — refusing is the safe outcome, and the
 * user's way out is deleting the stale contact first. Kept byte-identical to the
 * iOS string in AddContactView.swift (cross-platform parity).
 */
private fun inboxInUseMessage(context: Context): String =
    context.getString(R.string.add_contact_inbox_in_use)

/**
 * What the Done step is allowed to claim. App Store 2.1(a) rejection of 1.6.13
 * ("both devices stuck on waiting after scanned code"): the QR exchange is a
 * TWO-scan dance — a device shows its instant SECRET-ONLY code, the peer scans
 * it, and the peer must then have its own (now full) code scanned back. That
 * second scan is the ONLY thing that produces an inbox announce. The Done step
 * used to say "✓ Contact added" with a Done button after the FIRST scan, so both
 * reviewers tapped Done on both phones, both destroyed the transient (never
 * persisted) inbox write capability + secret half, and both were left with
 * a permanently un-completable "Waiting for their inbox…" contact and no POST.
 *
 * The decision is deliberately a pure function of two inputs so it can be pinned
 * by a JVM unit test (AddContactDoneStateTest) rather than only by a device run:
 *
 *  - [savedPeerInboxId] — the peer inbox this device recorded AT SAVE TIME. Non-null
 *    means we scanned (or pasted) a FULL code, i.e. we already announced to them and
 *    the pairing needs nothing further from this screen.
 *  - [peerInboxArrived] — the peer's in-band announce has since landed on the
 *    background control poll and the contact is now fully paired.
 *
 * iOS sibling: `AddContactView.scanBackNeeded` (AddContactView.swift) — same two
 * inputs, same order; keep the two in lockstep.
 */
internal enum class AddContactDoneState {
    /** Pairing is complete both ways — the real "✓ Contact added" + Done. */
    COMPLETE,

    /** Half done: OUR full code still has to be scanned by the peer. */
    AWAITING_SCAN_BACK,
}

internal fun addContactDoneState(
    savedPeerInboxId: String?,
    peerInboxArrived: Boolean,
): AddContactDoneState =
    if (savedPeerInboxId != null || peerInboxArrived) AddContactDoneState.COMPLETE
    else AddContactDoneState.AWAITING_SCAN_BACK

/** Mint state for the current pairing session (held by [AddContactSessionViewModel]). */
internal sealed class MintState {
    /** No messageManager yet — waiting for Tor / vault setup. */
    data object WaitingForRelay : MintState()
    /** PoW + relay round-trips in flight. */
    data object Solving : MintState()
    /** All three mints succeeded: the TEXT inbox, the CONTROL inbox (v7 —
     *  drained by the background poller so group invites and announces reach
     *  this device without a conversation being open) and the GROUP-text
     *  inbox (a third pairwise inbox so group texts never light the contact
     *  dot). [grpMinted] is non-null on every fresh mint reaching this state
     *  — [MessageManager.mintInboxPair] never returns a non-null pair with a
     *  null [MintedInboxPair.grp] — kept nullable only because the shared
     *  type is (it also backs legacy referral records that predate it). */
    data class Ready(
        val minted: MintedInbox,
        val ctlMinted: MintedInbox,
        val grpMinted: MintedInbox?,
        val mySecret: ByteArray,
    ) : MintState()
    /** Mint failed. UI shows a retry affordance. */
    data class Failed(val reason: String) : MintState()
}

@OptIn(ExperimentalComposeUiApi::class)
@Composable
fun AddContactScreen(
    viewModel: RunViewModel,
    onContactAdded: () -> Unit,
    onBack: () -> Unit = {}
) {
    val vault = viewModel.vault ?: return
    val context = LocalContext.current
    // Configuration-aware (a locale change re-reads it); LocalContext is not.
    val resources = LocalResources.current

    // --- Pairing session (G2) ---
    // Our secret half, the mint and the wizard progress live in a ViewModel scoped
    // to this NavBackStackEntry, NOT in `remember`: MainActivity declares no
    // configChanges, so rotation / dark mode / locale / font scale / a fold rebuilds
    // this composition, and a `remember`ed half used to be wiped and REGENERATED
    // then — after the peer may already have scanned the old one (silently dead
    // pairing). Never rememberSaveable / SavedStateHandle for any of it: the half,
    // the scanned peer half and the minted caps are RAM-only. Lifetime rule and the
    // wipe points: AddContactSessionViewModel.kt. iOS sibling: `pairingSession` in
    // AddContactView.swift.
    val session: AddContactSessionViewModel = viewModel()
    // The SAME array for the whole session (identical QR across a rotation); a
    // session ended by a real leave is replaced by a new one, never reused.
    // `generation` changes on "start again" (a restart inside this composition), so
    // everything derived from the session is rebuilt from the NEW one.
    val pairing = remember(session, session.generation) { session.currentPairing() }
    val mySecret = remember(pairing) { pairing.mySecretHalf() }
    var mintState by session::mintState
    // Retry counter — bumped to re-key the LaunchedEffect on explicit Retry.
    // Don't key the effect on mintState itself: as soon as it flips to
    // Solving the effect would re-key and cancel the in-flight mint.
    var mintAttempt by remember { mutableIntStateOf(0) }
    // Resolved in composition scope because the only consumer is inside the mint
    // LaunchedEffect below, where `stringResource` (a @Composable) cannot be
    // called — and reading it off `LocalContext.current` there is not
    // configuration-aware (lint LocalContextGetResourceValueCall).
    val mintFailedRelayText = stringResource(R.string.add_contact_mint_failed_relay)

    // Mint kicks off as soon as Tor connects (which is when messageManager
    // becomes non-null in RunViewModel). The key here MUST be a Compose-
    // observable state — viewModel.messageManager is a plain var, so changes
    // to it don't trigger recomposition and the LaunchedEffect would never
    // re-key when Tor lands. torState IS observable (StateFlow), so use that
    // and read messageManager inside; this mirrors what AddContactView does
    // on iOS via .onReceive(appState.$torState).
    val torState by viewModel.torState.collectAsState()
    // Pre-connect stall UX only — neither of these gates the mint (WaitingForRelay
    // stays NON-TERMINAL: no auto-fail, no Retry that would double-mint).
    val torBootstrapStalled by viewModel.torBootstrapStalled.collectAsState()
    // Real Tor bootstrap percent — the pacer's PHASE-ONE input; see
    // BootstrapProgressPacer / the ContactListScreen sibling. Ignored once Tor
    // is Connected (realTarget switches to its phase-two target then).
    val torPercent = when (val s = torState) {
        is TorManager.ConnectionState.Bootstrapping -> s.progress
        else -> 0
    }
    val torConnectedNow = torState is TorManager.ConnectionState.Connected
    // This screen's analog of ContactListScreen's `isRelayReachable`: phase
    // two ("Connecting to Relay…") is visible for as long as Tor is
    // connected but our own mint hasn't started/landed yet (MintState stays
    // WaitingForRelay). Anchor + 1s ticker mirror the ContactListScreen
    // sibling exactly — elapsedRealtime is kernel uptime, immune to
    // wall-clock changes.
    val mintWaitingForRelay = mintState is MintState.WaitingForRelay
    // Paced percent for the snackbar's status line — the shared
    // [BootstrapProgressPacer], exactly like ContactListScreen (and both iOS
    // views). App Store review 2.1 on 1.6.15: the old numbers FROZE (Tor parks
    // at 95% building its first circuit; the old phase-two curve was capped at
    // 95) and a frozen percent reads as a hang. Here "done" is the mint
    // leaving WaitingForRelay — this screen's analog of the contact list's
    // relay reachability. elapsedRealtime is kernel uptime, immune to
    // wall-clock changes.
    val connectPacer = remember { BootstrapProgressPacer { SystemClock.elapsedRealtime() } }
    val connectRealTarget = rememberUpdatedState(
        BootstrapProgressPacer.realTarget(torConnected = torConnectedNow, torPercent = torPercent)
    )
    val connectDone = rememberUpdatedState(!mintWaitingForRelay)
    var connectPercent by remember { mutableIntStateOf(0) }
    // Keyed on Unit: the cadence must not be re-armed by every Tor progress
    // emission (that would starve the creep); rememberUpdatedState keeps the
    // inputs fresh inside the loop.
    LaunchedEffect(Unit) {
        while (true) {
            connectPacer.observe(connectRealTarget.value, connectDone.value)
            connectPercent = connectPacer.displayed()
            delay(1000)
        }
    }
    // RE-ARM the mint (App Store 2.1(a), 1.6.13 "stuck on waiting"). The mint
    // LaunchedEffect below is keyed on (torState, mintAttempt) — both EDGES — and its
    // `viewModel.messageManager ?: run { WaitingForRelay; return }` branch is reachable
    // while torState is ALREADY Connected: the ViewModel's own Connected collector races
    // this screen's on the same StateFlow, and a Tor recycle can drop the transport
    // without a state change. Its "the next tick will catch it" comment was wrong —
    // torState never emits again (StateFlow conflates an equal Connected), so nothing
    // re-keys and the screen parks on "Setting up your inbox…" FOREVER: no minted pair,
    // so no saveContact, no announce POST and no contact row for the poll loops, while
    // the peer sits on "Waiting for their inbox…". THIS is the missing tick.
    //
    // Level trigger, not a spin: it only bumps once a transport is actually back, and
    // only while the mint is parked (never while Solving — that would cancel the
    // in-flight grind). iOS sibling: AddContactView's 1 Hz Timer .onReceive.
    val mintTransportReady = torConnectedNow || !RelayConfig.isTorRequired
    LaunchedEffect(mintWaitingForRelay, mintTransportReady) {
        while (mintWaitingForRelay && mintTransportReady) {
            delay(1000)
            if (mintState is MintState.WaitingForRelay && viewModel.messageManager != null) {
                mintAttempt++
            }
        }
    }
    // Maps a mint result onto the session's MintState. Our secret half is the
    // session's (unchanged across a re-mint), so the instant code never changes.
    val toMintState: (MintedInboxPair?) -> MintState = { result ->
        if (result != null) {
            MintState.Ready(result.main, result.ctl, result.grp, mySecret)
        } else {
            MintState.Failed(mintFailedRelayText)
        }
    }
    // A RUNNING mint is bound to the MessageManager it started on. When Tor is
    // recycled RunViewModel drops that manager and builds a new one; the old grind
    // would then sit on "Solving" until it fails into Retry. While Solving, check
    // once a second: no manager → abort it and park (the re-arm above restarts it
    // once one is back); a different manager → abort it and restart on the current
    // one (same half). Same manager → no-op. Never touches a Ready mint.
    val mintSolving = mintState is MintState.Solving
    LaunchedEffect(mintSolving) {
        while (mintSolving) {
            delay(1000)
            val current = viewModel.messageManager
            if (current == null) {
                session.abandonMintIfTransportChanged(null)
            } else {
                session.startMintIfIdle(current, toMintState)
            }
        }
    }
    LaunchedEffect(torState, mintAttempt) {
        // Direct-HTTP mode (dev/emulator, non-.onion relay) never emits a
        // Tor Connected state — the ViewModel wires messageManager without
        // ever touching torState. Gate on Connected ONLY when Tor is
        // actually required, like ContactListScreen and iOS's
        // isTorConnected do; otherwise the mint never starts on emulators.
        //
        // A Ready mint is KEPT here (it used to be reset to WaitingForRelay on every
        // Tor drop). Its inboxes do not depend on the circuit, and in the scan-first
        // role they are already saved into the pending contact: a re-mint put NEW,
        // unsaved inboxes into the scan-back QR, so the peer wrote to and announced
        // into inboxes this device never polls. iOS already keeps `.ready`.
        if (RelayConfig.isTorRequired && torState !is TorManager.ConnectionState.Connected) {
            if (mintState !is MintState.Solving && mintState !is MintState.Ready) {
                mintState = MintState.WaitingForRelay
            }
            return@LaunchedEffect
        }
        val mgr = viewModel.messageManager ?: run {
            // Tor said connected but messageManager hasn't been wired yet —
            // the ViewModel's Connected branch races us on the same StateFlow
            // emission. The next tick will catch it; stay in WaitingForRelay.
            if (mintState !is MintState.Solving && mintState !is MintState.Ready) {
                mintState = MintState.WaitingForRelay
            }
            return@LaunchedEffect
        }
        // Idempotent on retry: a Ready state stays Ready unless the user
        // bumps mintAttempt.
        if (mintState is MintState.Ready) return@LaunchedEffect
        // TWO mints per pairing: the text inbox + the control inbox (v7),
        // minted SEQUENTIALLY in shared code (MessageManager.mintInboxPair) so
        // Android and iOS behave identically — one full-speed PoW grind at a
        // time, never two competing for the cores. The blocking grind/HTTP work
        // runs on Dispatchers.Default inside mintInboxPair.
        //
        // The mint runs in the SESSION's scope, not this effect's: a configuration
        // change disposes this composition, and the grind must neither be aborted
        // nor restarted then (startMintIfIdle no-ops while Solving on the same
        // manager, and always on Ready, so the recreated screen re-attaches to it).
        // A real leave aborts it (endSession).
        session.startMintIfIdle(mgr, toMintState)
    }
    // End the session (abort the solve, zero the pairing-secret ByteArrays, drop the
    // minted caps and the progress) as the add-contact flow leaves the tree — on
    // EVERY real exit path (finish, back arrow, cancel pairing, nav-away, the
    // re-auth reset to the PIN route, the wipe cover), but NOT on the dispose of a
    // configuration change, whose recreated screen resumes this same session.
    // mySecret is aliased into MintState.Ready and passed to the Scan/Paste children,
    // but Kotlin ByteArrays are shared by reference (no copy-on-write), so the single
    // fill(0) in PairingSecretHalf.wipe clears every alias at once — no orphaned live
    // copy survives, unlike the iOS Data COW hazard (#1). The derived combinedSecret
    // (the actual per-contact key) is zeroed in saveContact()/CodeExchangeTab's own
    // finally right after the vault write; the scanned PEER half alone cannot
    // reconstruct the pairing key without mySecret, which is wiped there.
    // AddContactSessionViewModel.onCleared is the backstop (entry popped, Activity
    // finishing — the whole-session background teardown included).
    val hostActivity = context.findActivity()
    DisposableEffect(session) {
        onDispose {
            // Unknown host → treat as a real leave (fail toward wiping).
            if (hostActivity?.isChangingConfigurations != true) session.endSession()
        }
    }

    val ready = mintState as? MintState.Ready
    val myInboxId = ready?.minted?.inboxId
    val myWriteCap = ready?.minted?.writeCapability
    val myReadCap  = ready?.minted?.readCapability
    // SECRET-ONLY payload for the Show step — renders INSTANTLY, before (or
    // even without) the mint. The peer saves us as a pending contact and our
    // inbox reaches them in-band afterwards (sendInboxAnnounce). This is what
    // removes the "Setting up inbox…" wait while two people stand together.
    // Rebuilt from the session's SAME half after a configuration change, so the QR
    // the peer may already have scanned is byte-identical.
    // The session builds both code shapes (shared codec, identical wire format on both
    // platforms; the one-time key `ek` rides along). Null only after the session ended,
    // when this composition is leaving the tree anyway.
    val myShowPayload = remember(pairing) { pairing.secretOnlyCode() }
    // Budgets in DEVICE pixels (the tiles are 260 dp and 200 dp): QrBitmap.kt picks the largest
    // whole-pixel module scale that fits, and CrispQrImage draws 1 bitmap pixel per device pixel.
    val showQrBudgetPx = qrBudgetPx(260.dp)
    val doneQrBudgetPx = qrBudgetPx(200.dp)
    val showQrBitmap = remember(myShowPayload, showQrBudgetPx) { myShowPayload?.let { generateQrBitmap(it, showQrBudgetPx) } }
    // FULL payload (inbox + writeCap + secret) for the Done step and the
    // paste exchange — these are mint-gated: the Done-step code is the one
    // the peer scans back, so it must carry the inbox.
    val myQrPayload = remember(pairing, ready) {
        if (ready == null) null
        else pairing.fullCode(
            inboxId = ready.minted.inboxId,
            writeCap = ready.minted.writeCapability,
            ctlInboxId = ready.ctlMinted.inboxId,
            ctlWriteCap = ready.ctlMinted.writeCapability,
            grpInboxId = ready.grpMinted?.inboxId,
            grpWriteCap = ready.grpMinted?.writeCapability,
        )
    }
    val qrBitmap = remember(myQrPayload, doneQrBudgetPx) {
        myQrPayload?.let { generateQrBitmap(it, doneQrBudgetPx) }
    }

    // --- Wizard state ---
    // The exchange is mutual: each device must BOTH show its code and scan the
    // other's. Scanning gives us both halves of the shared secret immediately,
    // so we save the contact as soon as we have a scan and land on the Done
    // step, which shows our QR (for the peer to scan us back) and an inline
    // mnemonic field — kept identical to the iOS flow.
    // All of it is session state (survives a configuration change, see above).
    var step by session::step
    var shown by session::shown
    // Assigning a new value (or null) zeroes the previous scan's secret half.
    var scannedData by session::scannedData
    var pendingContactId by session::pendingContactId
    var pendingAlias by session::pendingAlias
    var mnemonicText by session::mnemonicText
    // The peer inbox recorded AT SAVE TIME — null exactly when we saved from a
    // SECRET-ONLY scan and therefore still owe the peer a scan of our full code.
    // Set by BOTH save paths: the camera save below and the paste exchange (which
    // always trades full codes, so it is never null there — reading `scannedData`
    // for the Done-step role, as this screen used to, wrongly put the PASTE path in
    // the scan-back role because CodeExchangeTab keeps its own parsed value; iOS
    // fixed the same divergence in addContactFromPastedCode).
    var savedPeerInboxId by session::savedPeerInboxId
    // The peer's in-band announce landed while this screen is still open, so the
    // half-done pairing completed under the user's eyes.
    var peerInboxArrived by session::peerInboxArrived
    // Key confirmation failed on the scan-first side — see the waiting loop below.
    val pairingFailed = session.pairingFailed
    // "Cancel pairing" confirm gate — the ONLY way out of the scan-back state.
    var showCancelPairing by session::showCancelPairing
    // The add can now be REFUSED by the vault (InboxInUseException). saveContact()
    // is driven from a LaunchedEffect, so an uncaught throw would kill the coroutine
    // (and in a release build take the process with it) instead of telling the user.
    var addError by session::addError

    fun saveContact() {
        // Idempotency latch: the scan-before-mint LaunchedEffect
        // and the Show-step onNext can both reach this; pendingContactId is set
        // on the first successful save, so any second call returns here instead
        // of inserting a duplicate contact.
        if (pendingContactId != null) return
        val data = scannedData ?: return
        val r = mintState as? MintState.Ready ?: return  // the save (not the QR) needs our mint
        platformLog("AddContact", "[save] saveContact: step=$step full=${data.inboxId != null}")
        addError = null
        // Alias is auto-generated; the mnemonic is added on the Done step (or left empty).
        val alias = generateRandomAlias()
        pendingAlias = alias
        val newContactId = UUID.randomUUID().toString()
        // ONE shared save: the session derives the pairing secret from both halves and
        // runs the one-time-bootstrap transaction iff the peer's code carried `ek`,
        // else the legacy one — it never throws and wipes its own derived copies. Both
        // halves are in hand here (the exchange is mutual), so the role order is fixed
        // at pairing. Our half and the parsed scan stay ours. A save that used the
        // one-time key has spent it whatever the outcome, so a second save in this
        // session answers START_AGAIN (below) and both people pair again.
        val outcome = pairing.save(
            vault = vault,
            contactId = newContactId,
            peer = data.scan,
            myInboxId = r.minted.inboxId,
            myReadCap = r.minted.readCapability,
            myCtlInboxId = r.ctlMinted.inboxId,
            myCtlReadCap = r.ctlMinted.readCapability,
            alias = alias,
            mnemonic = "",
            myGrpInboxId = r.grpMinted?.inboxId,
            myGrpReadCap = r.grpMinted?.readCapability,
        )
        when (outcome) {
            PairingSaveOutcome.SAVED_V3, PairingSaveOutcome.SAVED_LEGACY -> {
                pendingContactId = newContactId
                savedPeerInboxId = data.inboxId
                // We scanned their FULL code, so we have a send channel — deliver our
                // own inboxes in-band (they only saw our secret-only QR). Idempotent
                // on the receiving side; survives leaving this screen (ViewModel scope).
                if (data.inboxId != null) {
                    viewModel.announceInbox(
                        newContactId,
                        r.minted.inboxId, r.minted.writeCapability,
                        r.ctlMinted.inboxId, r.ctlMinted.writeCapability,
                        r.grpMinted?.inboxId, r.grpMinted?.writeCapability,
                    )
                }
                platformLog("AddContact", "[save] saved → step=Done")
                step = AddStep.Done
            }
            // One of the peer's inbox ids is already owned here, so the vault refused
            // the write (nothing was written). Surface it and stay on this step so the
            // user can back out or re-scan. Scanning the same code again meets the same
            // refusal; with a one-time-key code the next save restarts the pairing.
            PairingSaveOutcome.INBOX_IN_USE -> addError = inboxInUseMessage(context)
            // The peer's code is unusable: drop the scan (the scanner shows again) and
            // say so, instead of leaving the wizard on a wait that cannot end.
            PairingSaveOutcome.INVALID_CODE -> {
                scannedData = null
                addError = resources.getString(R.string.add_contact_invalid_code)
            }
            // Nothing was saved and this session cannot complete (its one-time key is
            // spent, or the write failed): a NEW session, with the reason shown.
            PairingSaveOutcome.START_AGAIN ->
                session.restartPairing(resources.getString(R.string.add_contact_start_again_error))
        }
    }

    // Scan-before-mint recovery: if the peer QR is decoded while
    // the mint is still in flight, onScanned stores scannedData but cannot save
    // (mint not Ready) and the analyzer is latched (decoded=true), so nothing
    // re-fires the save when the mint lands — the add silently dead-ends.
    // Complete the save the moment the mint becomes Ready while still on Scan.
    // (Mutually exclusive with onScanned's save: if mint was Ready at scan time
    // we are already on Done and this no-ops.)
    LaunchedEffect(mintState, scannedData, step) {
        if (step == AddStep.Scan && scannedData != null && mintState is MintState.Ready) {
            saveContact()
        }
    }

    // App Store 2.1(a) (1.6.13): while the Done step is in the AWAITING_SCAN_BACK
    // state the pairing completes OFF-SCREEN — the peer scans our full code and
    // their inbox reaches us as an in-band announce applied by the background
    // control poll. Nothing pushes that into this composable, so ask the vault.
    // Runs ONLY in that state (a completed/absent pairing never starts the loop),
    // reads on IO (two SQLCipher lookups), and stops on the first positive.
    LaunchedEffect(step, savedPeerInboxId, pendingContactId, peerInboxArrived) {
        val cid = pendingContactId ?: return@LaunchedEffect
        if (step != AddStep.Done || savedPeerInboxId != null || peerInboxArrived) return@LaunchedEffect
        platformLog("AddContact", "[done] awaiting the peer's announce (scan-back)")
        while (true) {
            // Positive evidence only: contactFullyPaired is healthy AND sendable.
            // Never "!contactAwaitingPeerInbox", which also goes true on a stale row.
            if (withContext(Dispatchers.IO) { contactFullyPaired(vault, cid) }) {
                platformLog("AddContact", "[done] peer inbox arrived — pairing complete")
                // Success always wins over a failure notice shown earlier.
                session.pairingFailed = false
                peerInboxArrived = true
                return@LaunchedEffect
            }
            // Key confirmation (one-time-bootstrap pairings): if the announce we are
            // waiting for never decrypts, say so and offer a fresh start. The notice
            // is NOT terminal and deletes nothing: this loop keeps polling, so a later
            // real message that decrypts (or the announce landing) clears it and the
            // normal success path runs; the contact is deleted only by the user's
            // "Start again" tap. Positive evidence only; false for a legacy contact.
            // iOS sibling: pollScanBackPairing (AddContactView.swift).
            val failedNow = withContext(Dispatchers.IO) { contactPairingFailed(vault, cid) }
            if (failedNow != session.pairingFailed) {
                platformLog("AddContact", "[done] pairing key confirmation failed=$failedNow")
                session.pairingFailed = failedNow
            }
            // The announce is applied by the background control sweep, whose idle
            // cadence is 60–90 s. Tick the convergence arm every second while this
            // state shows so the sweep runs FAST (and a loop already asleep wakes)
            // — measured 69 s → seconds (2026-09-27, pairing-two-scan spec).
            // Bounded per visit inside MessageManager. iOS sibling: the 1 Hz timer
            // in AddContactView.
            // Named: the sweep peeks THIS contact first.
            viewModel.messageManager?.notePairingAwaitingPeer(cid)
            delay(1_000)
        }
    }

    // Zeroing the SCANNED peer's pairing-secret half — the sibling of the paste
    // path's parsed.secret wipe (CodeExchangeTab below) and of mySecret's wipe.
    // `scannedData.secret` (a fresh ByteArray from Base64.decode) is consumed by
    // deriveSharedSecret in saveContact and otherwise never zeroed, so a
    // Back-to-Choice (scannedData = null) or nav-away would leak it in RAM until GC.
    // It used to be a DisposableEffect(scannedData) here; that also fired on a
    // configuration-change dispose and zeroed a scan the session still needed, so
    // the wipe now lives in the session: AddContactSessionViewModel.scannedData's
    // setter zeroes the replaced/cleared scan, and endSession zeroes the current
    // one on a real leave. Kotlin ByteArrays are shared by reference (no COW), so
    // that single fill(0) clears every alias (the value passed into
    // saveContact/deriveSharedSecret) at once.

    // The half-done pairing state. While it holds, this screen owns the ONLY copy
    // of the inbox write capability the peer still has to scan (our own
    // inbound write cap and secret half are never persisted), so leaving is
    // irreversible and must be confirmed — see [addContactDoneState].
    val scanBackNeeded = step == AddStep.Done &&
        addContactDoneState(savedPeerInboxId, peerInboxArrived) ==
        AddContactDoneState.AWAITING_SCAN_BACK

    /**
     * The deliberate way out of the scan-back state: delete the half-finished
     * contact (shared path — local delete is the gate, then a best-effort
     * relay DELETE of both inbound inboxes) so no un-completable "Waiting for
     * their inbox…" row lingers, then leave. Popping from the LOCAL-delete
     * callback means the contact list re-queries the vault after the row is gone.
     */
    fun cancelPairingAndLeave() {
        showCancelPairing = false
        val cid = pendingContactId
        if (cid == null) {
            onBack()
            return
        }
        pendingContactId = null
        viewModel.deleteContactInBackground(cid) { onBack() }
    }

    /**
     * "Start again" after a failed key confirmation: delete the half-made contact
     * through the shared delete path (local delete first, then a best-effort relay
     * DELETE of both inbound inboxes), then begin a NEW pairing session in this same
     * screen (fresh half, fresh one-time key, wizard back at Choice). iOS sibling:
     * `startAgainAfterFailure` (AddContactView.swift).
     */
    fun startAgainAfterFailure() {
        val cid = pendingContactId
        if (cid != null) viewModel.deleteContactInBackground(cid) { viewModel.refreshContactList() }
        session.restartPairing()
    }

    // System BACK while the pairing is half done routes through the same confirm as
    // the header arrow — otherwise the reflex gesture silently strands the peer
    // (they are holding a phone that is about to scan a code that no longer exists).
    BackHandler(enabled = scanBackNeeded) { showCancelPairing = true }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .semantics { testTagsAsResourceId = BuildConfig.DEBUG }
            .background(RunBlack)
            // Edge-to-edge: root takes the navigation-bar inset (the same idiom
            // as ConversationScreen); FinishingStep's own navigationBarsPadding
            // is then a no-op because this one consumes the inset.
            .navigationBarsPadding()
    ) {
        // Header with back arrow. The surface colour extends behind the status
        // bar via statusBarsPadding() (was a fixed 36.dp spacer that guessed the
        // status-bar height — wrong on tall-cutout devices).
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(RunSurface)
                .statusBarsPadding()
                .padding(horizontal = 12.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = backArrowGlyph(),  // RTL-aware: "←" LTR / "→" RTL
                fontSize = 22.sp,
                color = RunGrey,
                modifier = Modifier
                    .testTag("add_contact_cancel")
                    .clickable {
                        when (step) {
                            AddStep.Choice -> onBack()
                            // Same gate as the BackHandler above: a Done step that
                            // still owes the peer a scan may only be left through the
                            // confirm, which deletes the half-finished contact.
                            AddStep.Done -> if (scanBackNeeded) showCancelPairing = true
                                            else onContactAdded()
                            else -> {
                                step = AddStep.Choice
                                scannedData = null
                                shown = false
                                // A stale refusal banner (from a failed
                                // saveContact() while on Show/Scan) must not survive
                                // back-navigation into a fresh Choice/Show/Scan attempt —
                                // parity with iOS's identical Back/Cancel handler
                                // (AddContactView.swift), which already clears
                                // errorMessage here.
                                addError = null
                            }
                        }
                    }
                    .padding(8.dp)
            )
            Spacer(Modifier.width(8.dp))
            Text(
                text = stringResource(R.string.add_contact_title),
                style = MaterialTheme.typography.titleMedium,
                color = RunWhite
            )
        }

        // The vault refused the add (an inbox id in the peer's code is already
        // owned here). Rendered ABOVE the step content so it is visible whichever
        // step drove the save (Show's onNext, or Scan's mint-ready LaunchedEffect).
        addError?.let { msg ->
            Text(
                text = msg,
                style = MaterialTheme.typography.bodySmall,
                color = RunError,
                modifier = Modifier
                    .testTag("add_contact_error")
                    .padding(horizontal = 16.dp, vertical = 8.dp)
            )
        }

        when (step) {
            AddStep.Choice -> ChoiceStep(
                // A "start again" reason shown over the Choice step is stale once the
                // user begins the new attempt.
                onShow = { addError = null; step = AddStep.Show },
                onScan = { addError = null; step = AddStep.Scan },
                // The hidden 5-tap "no-camera paste exchange" is a dev/e2e aid.
                // Gate it out of release so the gesture is inert in production
                // (mirrors the log-viewer 5-tap in ContactListScreen). Keeping it
                // reachable in release put the contact bundle on the clipboard via
                // an undocumented gesture — unnecessary surface.
                onRevealPaste = { if (BuildConfig.DEBUG) step = AddStep.Paste }
            )
            AddStep.Show -> if (showQrBitmap != null && myShowPayload != null) ShowStep(
                // The Show QR is the instant secret-only code — no mint gate.
                qrBitmap = showQrBitmap,
                showPayload = myShowPayload,
                alreadyScanned = scannedData != null,
                onNext = {
                    // Step logging mirrors iOS AddContactView ("[show]"/"[scan]"/"[save]"/"[done]"),
                    // so a production debug-log stream shows WHERE a pairing spent its time
                    // (2026-10-26: 30 s of a Pixel pairing could not be attributed). No ids.
                    platformLog("AddContact", "[show] Next tapped: prevShown=$shown scanned=${scannedData != null}")
                    shown = true
                    if (scannedData != null) saveContact() else step = AddStep.Scan
                },
            )
            AddStep.Scan -> {
                if (scannedData != null && pendingContactId == null) {
                    // Scanned, but our own mint hasn't landed — the save (and
                    // for show-first users, the announce) needs it. Surface
                    // the wait/failure that used to live on the Show step.
                    FinishingStep(
                        mintState = mintState,
                        // Pre-connect honesty (App Store review 2.1 sibling): while
                        // the mint waits on Tor, say WHY it's taking so long instead
                        // of "Reaching the relay…" forever.
                        torBootstrapStalled = torBootstrapStalled,
                        torConnected = torConnectedNow,
                        displayPercent = connectPercent,
                        onRetry = { mintAttempt++ },
                    )
                } else {
                    ScanCodeTab(
                        myInboxId = myInboxId,
                        pairing = pairing,
                        // Deadlock guard: a device that already SHOWED its
                        // (secret-only) code must scan a FULL code — two
                        // secret-only halves could never exchange inboxes.
                        requireFull = shown,
                        onScanned = { data ->
                            // onScanned runs on the camera ANALYSIS thread — only record
                            // the scanned data here. The save is performed solely by the
                            // scan-before-mint LaunchedEffect on the MAIN thread once
                            // mint is Ready, so the two paths can't race into a double
                            // insert. Lands on Done (our QR + mnemonic).
                            platformLog("AddContact", "[scan] onScanned received scan (full=${data.inboxId != null})")
                            scannedData = data
                        }
                    )
                }
            }
            AddStep.Done -> if (pairingFailed) PairingFailedStep(
                onStartAgain = { startAgainAfterFailure() },
            ) else DoneStep(
                qrBitmap = qrBitmap,
                myQrPayload = myQrPayload,
                // Scan-first users (we scanned a secret-only code) MUST have
                // their full code scanned back — it carries our inbox. For
                // show-first users the peer learns our inbox in-band instead.
                scanBackNeeded = scanBackNeeded,
                // The "your inbox is delivered automatically" line belongs to the
                // SHOW-first role only. A pairing that completed via the peer's
                // scan-back gets the bare "✓ Contact added" — we never announced.
                showAnnounceHint = savedPeerInboxId != null,
                alias = pendingAlias,
                mnemonic = mnemonicText,
                onMnemonicChange = { mnemonicText = it },
                onDone = {
                    // Persist the mnemonic (if non-empty) to the just-saved
                    // contact, then close.
                    //
                    // Routed through ContactEdits (commonMain) — the same entry
                    // point ContactListScreen and both iOS screens use — instead of a
                    // local getContact/insertContact pair. insertContact is a WHOLE-ROW
                    // upsert, so an unlocked read-modify-write here can write back a
                    // stale snapshot of the four anti-replay counters and roll an
                    // inbound baseline backward (replay window reopened) or reuse an
                    // outbound counter (silent message loss) — the background control
                    // poll is running while this screen is open. ContactEdits re-reads
                    // inside ContactRowLocks and swallows a transient write failure
                    // (this ran raw inside a Compose callback, where the @Throws
                    // insertContact would have crashed the app).
                    val cid = pendingContactId
                    val typed = mnemonicText.trim()
                    if (cid != null && typed.isNotEmpty()) {
                        ContactEdits.updateMnemonic(vault, cid, typed)
                    }
                    onContactAdded()
                },
                onCancelPairing = { showCancelPairing = true },
            )
            AddStep.Paste -> CodeExchangeTab(
                myQrPayload = myQrPayload,
                pairing = pairing,
                myInboxId = myInboxId,
                myReadCap = myReadCap,
                mintState = mintState,
                vault = vault,
                onContactSaved = { contactId, alias, peerInboxId ->
                    pendingContactId = contactId
                    pendingAlias = alias
                    // The paste exchange always trades FULL codes, so this is never
                    // null — without it the Done step would render the scan-back
                    // role (and its "Keep waiting" gate) over a pairing that is
                    // already complete, which is what the camera-path `scannedData`
                    // read used to do here.
                    savedPeerInboxId = peerInboxId
                    platformLog("AddContact", "[paste] saved → step=Done")
                    step = AddStep.Done
                },
                onStartAgain = { msg -> session.restartPairing(msg) },
            )
        }
    }

    // Consent gate for the irreversible exit. RuneDialog WITH a title (a title-less
    // card flattens its children in the a11y tree); destructive action LAST per the
    // ordering safety rule in RuneDialog.kt, so the reflex tap keeps the pairing.
    if (showCancelPairing) {
        RuneDialog(
            onDismissRequest = { showCancelPairing = false },
            title = stringResource(R.string.add_contact_cancel_pairing_title),
            message = stringResource(R.string.add_contact_cancel_pairing_message),
            testTag = "add_contact_cancel_pairing_dialog",
            actions = listOf(
                runeSecondary(
                    stringResource(R.string.add_contact_keep_waiting),
                    testTag = "add_contact_cancel_pairing_keep",
                ) { showCancelPairing = false },
                runeDestructive(
                    stringResource(R.string.common_delete),
                    testTag = "add_contact_cancel_pairing_confirm",
                ) { cancelPairingAndLeave() },
            ),
        )
    }
}

/** Steps of the add-contact wizard. */
internal enum class AddStep { Choice, Show, Scan, Done, Paste }

// ---------------------------------------------------------------------------
// Step 1 — choose how to start. The exchange is mutual, so picking "Show" or
// "Scan" only decides which half comes first; the wizard then walks the other.
// A hidden 5-taps-within-3s gesture (mirroring the log-viewer's hidden open)
// reveals the no-camera paste exchange, kept for dev/e2e.
// ---------------------------------------------------------------------------

@Composable
private fun ChoiceStep(
    onShow: () -> Unit,
    onScan: () -> Unit,
    onRevealPaste: () -> Unit
) {
    var tapCount by remember { mutableIntStateOf(0) }
    var lastTapMs by remember { mutableLongStateOf(0L) }

    Box(Modifier.fillMaxSize()) {
        Column(
            modifier = Modifier.fillMaxSize().padding(32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Text(
                text = stringResource(R.string.add_contact_choice_heading),
                style = MaterialTheme.typography.titleLarge,
                color = RunWhite,
                textAlign = TextAlign.Center
            )
            Spacer(Modifier.height(8.dp))
            Text(
                text = stringResource(R.string.add_contact_choice_subtitle),
                style = MaterialTheme.typography.bodyLarge.copy(fontSize = 14.sp),
                color = RunGrey,
                textAlign = TextAlign.Center
            )
            Spacer(Modifier.height(40.dp))

            ChoiceButton(text = stringResource(R.string.add_contact_choice_show), tag = "add_choice_show", onClick = onShow)
            Spacer(Modifier.height(16.dp))
            ChoiceButton(text = stringResource(R.string.add_contact_choice_scan), tag = "add_choice_scan", onClick = onScan)
        }

        // Hidden gesture: 5 taps within 3 s reveal the no-camera paste exchange.
        Box(
            modifier = Modifier
                .align(Alignment.BottomCenter)
                .padding(bottom = 24.dp)
                .width(140.dp)
                .height(90.dp)
                .testTag("add_paste_reveal")
                .clickable(
                    indication = null,
                    interactionSource = remember { MutableInteractionSource() }
                ) {
                    val now = System.currentTimeMillis()
                    if (now - lastTapMs > 3000) tapCount = 0
                    lastTapMs = now
                    tapCount++
                    if (tapCount >= 5) {
                        tapCount = 0
                        onRevealPaste()
                    }
                }
        )
    }
}

@Composable
private fun ChoiceButton(text: String, tag: String, onClick: () -> Unit) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(tag)
            .clip(RoundedCornerShape(12.dp))
            .background(RunSurfaceAlt)
            .clickable(onClick = onClick)
            .padding(vertical = 20.dp),
        contentAlignment = Alignment.Center
    ) {
        Text(text, color = RunWhite, style = MaterialTheme.typography.bodyLarge)
    }
}

// ---------------------------------------------------------------------------
// Step — show this device's QR for the contact to scan. `alreadyScanned` is
// true when we've already scanned theirs (scan-first path), so the next tap
// finishes instead of routing to the scanner.
// ---------------------------------------------------------------------------

@Composable
private fun ShowStep(
    qrBitmap: Bitmap,
    /** The raw secret-only JSON the [qrBitmap] encodes — surfaced as text for the
     *  e2e scanner-injection seam only (BuildConfig.DEBUG). iOS sibling:
     *  `debug_instant_code` in AddContactView.showStep. */
    showPayload: String,
    alreadyScanned: Boolean,
    onNext: () -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxSize().padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Text(
            text = stringResource(R.string.add_contact_show_heading),
            style = MaterialTheme.typography.bodyLarge,
            color = RunGrey,
            textAlign = TextAlign.Center
        )
        Spacer(Modifier.height(32.dp))
        // add_show_qr: the bitmap carries its own white quiet zone (4 modules, far wider than
        // the 12 dp corner clip's inset), so an element screenshot of this node is directly
        // scannable (e2e camera specs). Drawn 1 bitmap pixel per device pixel (CrispQrImage).
        // iOS sibling: add_show_qr in AddContactView.showStep.
        CrispQrImage(
            bitmap = qrBitmap,
            modifier = Modifier.clip(RoundedCornerShape(12.dp)).testTag("add_show_qr"),
        )
        // Debug-only: the SAME payload as text, so an e2e run can hand the peer's
        // scanner what a camera would have read off the QR above. Base64-of-JSON,
        // matching the paste tab's `debug_my_code` and what `scan_inject_field`
        // expects. Inert in release (not rendered at all).
        if (BuildConfig.DEBUG) {
            Text(
                text = Base64.encodeToString(showPayload.toByteArray(Charsets.UTF_8), Base64.NO_WRAP),
                style = MaterialTheme.typography.bodySmall.copy(fontSize = 9.sp),
                color = RunGrey,
                maxLines = 3,
                modifier = Modifier.testTag("debug_instant_code"),
            )
        }
        Spacer(Modifier.height(24.dp))
        Text(
            text = if (alreadyScanned) stringResource(R.string.add_contact_show_hint_scanned)
                   else stringResource(R.string.add_contact_show_hint_pending),
            style = MaterialTheme.typography.bodyLarge.copy(fontSize = 13.sp),
            color = RunGrey.copy(alpha = 0.7f),
            textAlign = TextAlign.Center
        )
        Spacer(Modifier.height(32.dp))
        Box(
            modifier = Modifier
                .testTag("add_show_next")
                .clip(RoundedCornerShape(8.dp))
                .background(RunWhite)
                .clickable(onClick = onNext)
                .padding(horizontal = 32.dp, vertical = 12.dp),
            contentAlignment = Alignment.Center
        ) {
            Text(
                if (alreadyScanned) stringResource(R.string.add_contact_next)
                else stringResource(R.string.add_contact_show_first_android),
                color = RunBlack,
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Step — scanned, waiting for our own mint to finish the save. This is where
// the old Show-step "Setting up inbox…" wait moved when the Show QR became
// instant: the inbox setup now overlaps the human QR-exchange instead of
// preceding it, and this pane is only ever visible if the mint is SLOWER
// than the scanning dance.
// ---------------------------------------------------------------------------

@Composable
private fun FinishingStep(
    mintState: MintState,
    torBootstrapStalled: Boolean,
    torConnected: Boolean,
    displayPercent: Int?,
    onRetry: () -> Unit,
) {
    // Smooth time-estimate of the mint (proof-of-work grind) for the progress
    // snackbar — mirrors iOS; NOT a literal attempt counter (the parallel solver
    // doesn't surface per-attempt counts).
    val mintProgress by animateFloatAsState(
        targetValue = when (mintState) {
            is MintState.Solving -> 0.9f
            is MintState.Ready -> 1f
            else -> 0.06f
        },
        animationSpec = tween(
            durationMillis = if (mintState is MintState.Solving) 9000 else 300,
            easing = FastOutSlowInEasing
        ),
        label = "mint_progress"
    )
    // App Store review 2.1 (iOS 0.8.159) rejected the sibling screen for spinning
    // on the literal "Reaching the relay…" for 15+ minutes when Tor never
    // bootstrapped. Same hole here: say WHY once the bootstrap has blown its
    // budget, and show the live two-phase status line while it IS moving.
    // Still non-terminal — the mint resumes on its own the moment Tor connects.
    val mintStatusLine = when (mintState) {
        is MintState.WaitingForRelay ->
            if (torBootstrapStalled) RelayConnectHints.MINT_STALLED_HINT
            // connectStatusLine no longer takes a percent (2026-09-16: the
            // digits moved to an animated dots cadence on the ContactListScreen
            // sibling only — this snackbar already has its own moving
            // LinearProgressIndicator below, so it doesn't need one too).
            // [displayPercent] is kept as a parameter for call-site/telemetry
            // stability even though it's unused here now.
            else RelayConnectHints.connectStatusLine(torConnected)
        is MintState.Solving -> stringResource(R.string.add_contact_solving_pow)
        else -> stringResource(R.string.add_contact_setting_up_inbox)
    }
    Column(
        // navigationBarsPadding: this screen has no Scaffold and the activity is
        // edge-to-edge, so without the inset the bottom-anchored mint snackbar
        // ("Reaching the relay…") sat under/against the gesture bar — same
        // pattern as ConversationScreen's input row and CreateGroupScreen.
        modifier = Modifier.fillMaxSize().navigationBarsPadding().padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        if (mintState is MintState.Failed) {
            Spacer(Modifier.weight(1f))
            Text(
                text = mintState.reason,
                style = MaterialTheme.typography.bodyLarge,
                color = RunGrey,
                textAlign = TextAlign.Center,
                modifier = Modifier.testTag("add_mint_failed"),
            )
            Spacer(Modifier.height(20.dp))
            Box(
                modifier = Modifier
                    .testTag("add_mint_retry")
                    .clip(RoundedCornerShape(8.dp))
                    .background(RunWhite)
                    .clickable(onClick = onRetry)
                    .padding(horizontal = 32.dp, vertical = 12.dp),
                contentAlignment = Alignment.Center
            ) {
                Text(stringResource(R.string.common_retry), color = RunBlack)
            }
            Spacer(Modifier.weight(1f))
        } else {
            Spacer(Modifier.weight(1f))
            // Progress snackbar — mirrors iOS: a status line + a bar that eases
            // across a typical PoW solve and completes when the mint lands.
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(12.dp))
                    .background(RunSurface)
                    .padding(16.dp)
                    .testTag("mint_snackbar"),
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    // ADDITIVE tag for the honest pre-connect variant, on the ROW so
                    // the status Text keeps its long-standing `add_mint_pending` tag
                    // (never rename an existing one — other sessions run against
                    // pre-deploy binaries). Present only while the hint is showing.
                    modifier = if (mintState is MintState.WaitingForRelay && torBootstrapStalled) {
                        Modifier.testTag("add_mint_stalled")
                    } else {
                        Modifier
                    },
                ) {
                    Text(
                        text = "⬢",
                        fontSize = 14.sp,
                        color = Color(0xFFDBB575),
                    )
                    Spacer(Modifier.width(8.dp))
                    Text(
                        text = mintStatusLine,
                        style = MaterialTheme.typography.bodyMedium,
                        color = RunWhite,
                        modifier = Modifier.weight(1f).testTag("add_mint_pending"),
                    )
                }
                Spacer(Modifier.height(10.dp))
                LinearProgressIndicator(
                    progress = { mintProgress },
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(3.dp)),
                    color = Color(0xFFBF3826),
                    trackColor = RunSurfaceAlt,
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Final step — TWO states, see [addContactDoneState]:
//
//   AWAITING_SCAN_BACK ("Almost there") — we scanned their instant secret-only
//     code, so the pairing is HALF done: our full code (the one carrying our
//     inbox) still has to be scanned by them, and that scan is the only thing
//     that produces the announce POST. No success claim, no Done button; the
//     screen stays put until the announce lands or the user explicitly cancels.
//   COMPLETE ("✓ Contact added") — nothing further is owed; Done as before.
//
// iOS sibling: AddContactView.doneStep.
// ---------------------------------------------------------------------------

/**
 * The scan-first side's key confirmation failed: the two phones did not end up with
 * the same secure channel, so the half-made contact can never complete. A plain
 * notice and ONE action — it deletes that contact and starts a new pairing. No silent
 * dead end. iOS sibling: `pairingFailedStep` (AddContactView.swift), same ids.
 */
@Composable
private fun PairingFailedStep(onStartAgain: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 24.dp, vertical = 32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            text = stringResource(R.string.add_contact_pairing_failed),
            style = MaterialTheme.typography.bodyLarge.copy(fontSize = 14.sp),
            color = RunError,
            textAlign = TextAlign.Center,
            modifier = Modifier.testTag("pairing_failed_notice"),
        )
        Spacer(Modifier.height(24.dp))
        Box(
            modifier = Modifier
                .testTag("pairing_failed_start_again")
                .clip(RoundedCornerShape(8.dp))
                .background(RunWhite)
                .clickable(onClick = onStartAgain)
                .padding(horizontal = 32.dp, vertical = 12.dp),
            contentAlignment = Alignment.Center,
        ) {
            Text(stringResource(R.string.add_contact_pairing_failed_action), color = RunBlack)
        }
    }
}

@Composable
private fun DoneStep(
    qrBitmap: Bitmap?,
    /** The raw FULL JSON the [qrBitmap] encodes — surfaced as text in the
     *  scan-back state for the e2e scanner-injection seam only
     *  (BuildConfig.DEBUG). iOS sibling: `debug_scanback_code` in doneStep. */
    myQrPayload: String?,
    scanBackNeeded: Boolean,
    showAnnounceHint: Boolean,
    alias: String,
    mnemonic: String,
    onMnemonicChange: (String) -> Unit,
    onDone: () -> Unit,
    onCancelPairing: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 24.dp, vertical = 16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        // The heading is the STATE: "Almost there" (id add_contact_scan_back_title)
        // while the peer still has to scan, "✓ Contact added" once they have.
        Text(
            text = if (scanBackNeeded) stringResource(R.string.add_contact_scan_back_title)
                   else stringResource(R.string.add_contact_done_heading),
            style = MaterialTheme.typography.titleMedium,
            color = RunWhite,
            textAlign = TextAlign.Center,
            modifier = if (scanBackNeeded) Modifier.testTag("add_contact_scan_back_title")
                       else Modifier,
        )
        if (alias.isNotBlank()) {
            Spacer(Modifier.height(4.dp))
            Text(
                text = stringResource(R.string.add_contact_saved_as, alias),
                style = MaterialTheme.typography.bodyLarge.copy(fontSize = 13.sp),
                color = RunWhite.copy(alpha = 0.85f),
                textAlign = TextAlign.Center,
                modifier = Modifier.testTag("add_done_alias"),
            )
        }
        Spacer(Modifier.height(6.dp))
        if (scanBackNeeded) {
            // Scan-first role: this full code carries our inbox — the peer
            // scanning it back is what completes the pairing.
            Text(
                text = stringResource(R.string.add_contact_scan_back_hint),
                style = MaterialTheme.typography.bodyLarge.copy(fontSize = 13.sp),
                color = RunGrey,
                textAlign = TextAlign.Center,
                modifier = Modifier.testTag("add_contact_scan_back_hint"),
            )
            Spacer(Modifier.height(14.dp))
            if (qrBitmap != null) {
                CrispQrImage(
                    bitmap = qrBitmap,
                    modifier = Modifier
                        .clip(RoundedCornerShape(12.dp))
                        .testTag("add_contact_scan_back_qr"),
                )
                // Debug-only: the same FULL payload as text — the code the peer
                // must scan BACK to finish the pairing, and the only way an e2e
                // run can deliver it without a camera. Inert in release.
                if (BuildConfig.DEBUG && myQrPayload != null) {
                    Text(
                        text = Base64.encodeToString(myQrPayload.toByteArray(Charsets.UTF_8), Base64.NO_WRAP),
                        style = MaterialTheme.typography.bodySmall.copy(fontSize = 9.sp),
                        color = RunGrey,
                        maxLines = 3,
                        modifier = Modifier.testTag("debug_scanback_code"),
                    )
                }
            } else {
                // Mint still settling — the code appears the moment it does.
                Text(
                    text = stringResource(R.string.add_contact_qr_preparing),
                    style = MaterialTheme.typography.bodyLarge.copy(fontSize = 13.sp),
                    color = RunGrey,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.testTag("add_done_qr_pending"),
                )
            }
        } else if (showAnnounceHint) {
            // Show-first role: the peer gets our inbox in-band — no scan-back.
            Text(
                text = stringResource(R.string.add_contact_announce_hint),
                style = MaterialTheme.typography.bodyLarge.copy(fontSize = 13.sp),
                color = RunGrey,
                textAlign = TextAlign.Center
            )
        }
        Spacer(Modifier.height(18.dp))
        if (!scanBackNeeded) {
            // Inline mnemonic — a personal memory aid for who this contact is.
            // Written to the contact on Done if non-empty; matches iOS. Hidden
            // while the pairing is half done: there is no Done button in that
            // state, so anything typed here would be silently dropped.
            Text(
                text = stringResource(R.string.add_contact_mnemonic_label),
                style = MaterialTheme.typography.bodyLarge.copy(fontSize = 12.sp),
                color = RunGrey,
                modifier = Modifier.fillMaxWidth().padding(start = 4.dp, bottom = 6.dp),
            )
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(12.dp))
                    .background(RunSurfaceAlt)
                    .padding(horizontal = 14.dp, vertical = 12.dp)
            ) {
                if (mnemonic.isEmpty()) {
                    Text(
                        text = stringResource(R.string.add_contact_mnemonic_placeholder),
                        style = MaterialTheme.typography.bodyLarge.copy(fontSize = 13.sp),
                        color = RunGrey,
                    )
                }
                NoPersonalizedLearning {
                    BasicTextField(
                        value = mnemonic,
                        onValueChange = onMnemonicChange,
                        textStyle = MaterialTheme.typography.bodyLarge.copy(
                            color = RunWhite, fontSize = 13.sp,
                        ),
                        cursorBrush = SolidColor(RunWhite),
                        singleLine = false,
                        maxLines = 3,
                        // No IME learning of this private contact note (text stays visible).
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                        modifier = Modifier.fillMaxWidth().testTag("add_done_mnemonic"),
                    )
                }
            }
            Spacer(Modifier.height(20.dp))
        }
        if (scanBackNeeded) {
            // PRIMARY = stay. A deliberate no-op: the pairing finishes on the
            // PEER's tap, so the only honest thing this screen can offer is to
            // keep holding the code up. It occupies the reflex position so the
            // irreversible action can never be the one muscle memory hits.
            Box(
                modifier = Modifier
                    .testTag("add_contact_keep_waiting")
                    .clip(RoundedCornerShape(8.dp))
                    .background(RunWhite)
                    .clickable { /* stay on this screen — see comment above */ }
                    .padding(horizontal = 32.dp, vertical = 12.dp),
                contentAlignment = Alignment.Center
            ) {
                Text(stringResource(R.string.add_contact_keep_waiting), color = RunBlack)
            }
            Spacer(Modifier.height(14.dp))
            // SECONDARY = the only way out, and it is confirmed + destructive.
            Text(
                text = stringResource(R.string.add_contact_cancel_pairing),
                style = MaterialTheme.typography.bodyLarge.copy(fontSize = 13.sp),
                color = RunGrey,
                textAlign = TextAlign.Center,
                modifier = Modifier
                    .testTag("add_contact_cancel_pairing")
                    .clickable(onClick = onCancelPairing)
                    .padding(horizontal = 24.dp, vertical = 10.dp),
            )
        } else {
            Box(
                modifier = Modifier
                    .testTag("add_contact_done")
                    .clip(RoundedCornerShape(8.dp))
                    .background(RunWhite)
                    .clickable(onClick = onDone)
                    .padding(horizontal = 32.dp, vertical = 12.dp),
                contentAlignment = Alignment.Center
            ) {
                Text(stringResource(R.string.common_done), color = RunBlack)
            }
        }
    }
}

/**
 * Parsed result from scanning another device's QR code.
 *
 * [inboxId]/[writeCap] are null for a SECRET-ONLY code — the instant QR a
 * device shows before its mint has finished. The peer's inbox then arrives
 * later through the in-band announce (see MessageManager.sendInboxAnnounce),
 * and the contact stays in the "awaiting peer inbox" state until it does.
 */
internal data class ScannedContact(
    /** The shared parse result — handed to [PairingSession.save] unchanged. */
    val scan: PairingScan,
) {
    val inboxId: String? get() = scan.inboxId
}

// ---------------------------------------------------------------------------
// Scan Code tab — camera preview with ZXing QR analysis.
//
// Security purpose: the camera feed is processed frame-by-frame in memory.
// No frame is written to disk, buffered to a file, or sent over the network.
// The camera is bound to the composable's lifecycle and released immediately
// when the user navigates away or a QR code is successfully decoded.
// ---------------------------------------------------------------------------

@Composable
private fun ScanCodeTab(
    myInboxId: String?,
    pairing: PairingSession,
    requireFull: Boolean,
    onScanned: (ScannedContact) -> Unit,
) {
    // The camera + ZXing plumbing moved to [QrCameraScanner] (shared with the
    // "Move to new device" scanner, MoveFromDeviceScreen). Behaviour here is
    // unchanged: the same frame decode on the same analysis thread, the same
    // pairing-payload validation, and the same "first accepted decode wins".
    //
    // `accept` is THE decode path: the camera analyzer calls it, and (debug only)
    // so does the scanner-injection row below — one validation, one onScanned.
    val accept: (String) -> Boolean = { text ->
        // One validation for both platforms (echo of our half / inbox / one-time key,
        // shapes, low-order `ek`), run by the session; null = not a usable code.
        val result = pairing.parsePeerCode(text, myInboxId, requireFull)
        if (result != null) {
            onScanned(ScannedContact(result))
            true
        } else {
            false
        }
    }
    // The DEBUG-only scanner-injection row (scan_inject_field / scan_inject_submit)
    // is rendered by QrCameraScanner itself, so the move-from-device scanner
    // exposes the same seam.
    QrCameraScanner(modifier = Modifier.fillMaxSize(), onDecodedText = accept)
}

// ---------------------------------------------------------------------------
// Scanner injection seam (BuildConfig.DEBUG only — an emulator has no camera).
//
// The two-scan camera dance (instant secret-only code out, full code scanned
// back) has NO automatable surface: the paste exchange always trades FULL codes
// on both sides, so `scanBackNeeded` is unreachable from the e2e suite and the
// scan-back screen's completion path was never covered. This feeds a
// harness-supplied payload into [QrCameraScanner]'s OWN decode path — the
// analysis executor → [QrDecodeHandoff] → main → onDecodedText, the exact route a
// decoded frame takes (thread and all) — so the injected code is
// indistinguishable from a decoded frame. That is what makes it a faithful
// repro surface: the 2026-09-27 move-scan crash (navigation from the analysis
// thread) reproduces through this row and is fixed by the same hand-off.
//
// Same gating model as the no-camera paste exchange: the whole
// row is `if (BuildConfig.DEBUG)`, so nothing renders and nothing is clickable in
// release, and its testTags are not automation ids there either
// (testTagsAsResourceId = BuildConfig.DEBUG). iOS sibling: `scanInjectRow` in
// AddContactView.swift — same two ids, same base64-of-JSON input.
//
// Input is base64-of-JSON (identical encoding to the paste tab's
// `debug_my_code`), not raw JSON: the harness types it through Appium setValue,
// and restricting it to the base64 alphabet keeps braces and quotes out of the
// keyboard path on both platforms. The QR carries the RAW JSON, which is exactly
// what `accept` receives after the decode below.
//
// Rendered by [QrCameraScanner] ABOVE the camera preview, on BOTH sides of its
// CAMERA-permission branch, so an emulator seat is drivable with the permission
// denied as well. Every caller of the scanner (pairing, move-from-device) gets it.
// ---------------------------------------------------------------------------

@Composable
private fun ScanInjectRow(onInject: (String) -> Unit) {
    if (!BuildConfig.DEBUG) return
    var injected by remember { mutableStateOf("") }
    Row(
        modifier = Modifier.fillMaxWidth().padding(8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(
            modifier = Modifier
                .weight(1f)
                .clip(RoundedCornerShape(8.dp))
                .background(RunSurfaceAlt)
                .padding(horizontal = 10.dp, vertical = 8.dp)
        ) {
            NoPersonalizedLearning {
                BasicTextField(
                    value = injected,
                    onValueChange = { injected = it },
                    textStyle = MaterialTheme.typography.bodySmall.copy(color = RunWhite, fontSize = 10.sp),
                    cursorBrush = SolidColor(RunWhite),
                    singleLine = false,
                    maxLines = 2,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    modifier = Modifier.fillMaxWidth().testTag("scan_inject_field"),
                )
            }
        }
        Spacer(Modifier.width(8.dp))
        Box(
            modifier = Modifier
                .testTag("scan_inject_submit")
                .clip(RoundedCornerShape(8.dp))
                .background(RunWhite)
                .clickable {
                    val raw = try {
                        String(Base64.decode(injected.trim(), Base64.NO_WRAP), Charsets.UTF_8)
                    } catch (_: Exception) {
                        return@clickable
                    }
                    // Cleared once the text is on its way (the decision is made
                    // asynchronously on main, like a frame's); the harness treats
                    // an emptied field as "submitted".
                    onInject(raw)
                    injected = ""
                }
                .padding(horizontal = 12.dp, vertical = 8.dp),
            contentAlignment = Alignment.Center,
        ) {
            Text("inject", color = RunBlack, style = MaterialTheme.typography.bodySmall)
        }
    }
}

// ---------------------------------------------------------------------------
// QrCameraScanner — the raw camera + ZXing surface, payload-agnostic.
//
// Extracted from ScanCodeTab so the device-move flow can scan its own handle
// JSON (docs/device-move.md) without a second copy of the CameraX lifecycle
// dance. [onDecodedText] returns true when it ACCEPTED the text; that latches
// the analyzer off (one decode per mount, exactly as before), while a rejected
// decode keeps the camera hunting so a stray QR in frame cannot dead-end the
// screen.
//
// Security posture is inherited, not changed: frames are decoded in memory,
// never written to disk or sent anywhere, and the camera is unbound the moment
// this leaves the composition.
// ---------------------------------------------------------------------------

@Composable
internal fun QrCameraScanner(
    modifier: Modifier = Modifier,
    scanTestTag: String? = null,
    onDecodedText: (String) -> Boolean,
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current

    // Camera permission handling.
    var hasPermission by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) ==
                PackageManager.PERMISSION_GRANTED
        )
    }

    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted -> hasPermission = granted }

    // Request permission on first composition if not already granted.
    LaunchedEffect(Unit) {
        if (!hasPermission) {
            permissionLauncher.launch(Manifest.permission.CAMERA)
        }
    }

    // Single-thread executor for frame analysis — avoids blocking the main thread.
    val analysisExecutor = remember { Executors.newSingleThreadExecutor() }

    // Decode on the analysis thread, ACCEPT on main (QrDecodeHandoff): the move
    // screen's callback navigates, and navigation is main-thread-only — calling
    // onDecodedText inline on the analyzer crashed every camera scan of a move
    // code (GrapheneOS report 2026-09-27). Also the "first accepted decode
    // wins" latch and the duplicate-frame drop while an acceptance is in flight.
    // Remembered ONCE (no key): the accepted-latch must survive recomposition,
    // and the callback lambda is rebuilt on every recomposition (it captures
    // unstable values), so read the latest one through rememberUpdatedState.
    val currentOnDecodedText by rememberUpdatedState(onDecodedText)
    val handoff = remember {
        QrDecodeHandoff(ContextCompat.getMainExecutor(context)) { currentOnDecodedText(it) }
    }

    // Release the executor when the composable leaves the tree (the camera unbind
    // sits with the AndroidView below). Declared here, above the permission
    // branch, so the executor the injection row uses is shut down either way.
    DisposableEffect(Unit) {
        onDispose { analysisExecutor.shutdown() }
    }

    Column(modifier = modifier) {
        // DEBUG-only injection seam: the text enters on the ANALYSIS thread, just
        // like a decoded frame, and takes the same hand-off to main.
        ScanInjectRow(onInject = { text ->
            try { analysisExecutor.execute { handoff.offer(text) } } catch (_: Exception) { }
        })
        if (!hasPermission) {
            // Permission not yet granted — show a brief message.
            Box(
                modifier = Modifier.fillMaxSize(),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    text = stringResource(R.string.add_contact_camera_permission),
                    style = MaterialTheme.typography.bodyLarge,
                    color = RunGrey,
                    textAlign = TextAlign.Center
                )
            }
        } else {
            QrCameraPreview(
                modifier = Modifier.fillMaxSize(),
                scanTestTag = scanTestTag,
                lifecycleOwner = lifecycleOwner,
                analysisExecutor = analysisExecutor,
                handoff = handoff,
            )
        }
    }
}

/** The CameraX preview + ZXing analysis surface behind [QrCameraScanner]. */
@Composable
private fun QrCameraPreview(
    modifier: Modifier,
    scanTestTag: String?,
    lifecycleOwner: LifecycleOwner,
    analysisExecutor: ExecutorService,
    handoff: QrDecodeHandoff,
) {

    // Hold the provider so onDispose can UNBIND the camera when
    // this scan sub-step leaves the tree. The camera is bound to the add_contact nav
    // entry (not this composable), so without unbinding it stays LIVE (LED/battery)
    // through the Done / "have them scan back" wait until the whole flow is popped.
    val cameraProviderRef = remember { mutableStateOf<ProcessCameraProvider?>(null) }

    // CameraX preview bound to an AndroidView.
    AndroidView(
        modifier = modifier.let { if (scanTestTag != null) it.testTag(scanTestTag) else it },
        factory = { ctx ->
            val previewView = PreviewView(ctx)

            val cameraProviderFuture = ProcessCameraProvider.getInstance(ctx)
            cameraProviderFuture.addListener({
                val cameraProvider = cameraProviderFuture.get()
                cameraProviderRef.value = cameraProvider   // for unbind on dispose

                val preview = Preview.Builder().build().also {
                    it.setSurfaceProvider(previewView.surfaceProvider)
                }

                // ImageAnalysis use-case: each frame is converted to a
                // YUV luminance source and fed to ZXing's MultiFormatReader.
                // 1280x720 (was 640x480): the pairing codes carry a one-time key
                // now and are denser (QR version 12 -> 13 on Android, 14 -> 15 on
                // iOS), so each module needs more camera pixels. The closest
                // available size is used when the device has no exact match (a
                // nearest-fallback strategy, preferring the larger side), and
                // KEEP_ONLY_LATEST keeps the decoder from queueing frames.
                val analysisResolution = ResolutionSelector.Builder()
                    .setResolutionStrategy(
                        ResolutionStrategy(
                            Size(1280, 720),
                            ResolutionStrategy.FALLBACK_RULE_CLOSEST_HIGHER_THEN_LOWER,
                        )
                    )
                    .build()
                val analysis = ImageAnalysis.Builder()
                    .setResolutionSelector(analysisResolution)
                    .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                    .build()

                analysis.setAnalyzer(analysisExecutor) { imageProxy ->
                    if (!handoff.done) {
                        decodeQrTextFromFrame(imageProxy)?.let { handoff.offer(it) }
                    }
                    imageProxy.close()
                }

                // Bind to back camera, fall back to front if unavailable.
                try {
                    cameraProvider.unbindAll()
                    try {
                        cameraProvider.bindToLifecycle(
                            lifecycleOwner,
                            CameraSelector.DEFAULT_BACK_CAMERA,
                            preview,
                            analysis
                        )
                    } catch (_: Exception) {
                        cameraProvider.unbindAll()
                        cameraProvider.bindToLifecycle(
                            lifecycleOwner,
                            CameraSelector.DEFAULT_FRONT_CAMERA,
                            preview,
                            analysis
                        )
                    }
                } catch (_: Exception) { }
            }, ContextCompat.getMainExecutor(ctx))

            previewView
        }
    )

    // Release the camera when the preview leaves the tree (the executor is shut
    // down by QrCameraScanner's own DisposableEffect).
    DisposableEffect(Unit) {
        onDispose {
            cameraProviderRef.value?.unbindAll()   // stop the camera on leave
        }
    }
}

/**
 * Attempts to decode a QR code from a CameraX [ImageProxy] frame using ZXing.
 *
 * Returns the raw decoded TEXT, or null when the frame holds no readable QR.
 * Payload validation is the caller's business (pairing payload for Add Contact,
 * move handle for the device move) — invalid or non-QR frames are silently
 * ignored here, no error is surfaced to the user.
 */
private fun decodeQrTextFromFrame(imageProxy: ImageProxy): String? {
    val plane = imageProxy.planes[0]
    val buffer = plane.buffer
    val width = imageProxy.width
    val height = imageProxy.height
    val rowStride = plane.rowStride

    // The Y-plane's row stride may be larger than the image width (padding
    // bytes at the end of each row). PlanarYUVLuminanceSource expects a
    // contiguous buffer where each row is exactly `dataWidth` bytes, so we
    // must use rowStride as the data width and crop to the actual image.
    val bytes = ByteArray(buffer.remaining())
    buffer.get(bytes)

    val source = PlanarYUVLuminanceSource(
        bytes, rowStride, height,
        0, 0, width, height,
        false
    )

    val reader = MultiFormatReader()
    val hints = mapOf(
        DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),
        DecodeHintType.TRY_HARDER to true,
        DecodeHintType.ALSO_INVERTED to true
    )

    // Try the normal image first, then an inverted copy. Our "Show my code"
    // tab renders white-on-black QR codes, which is the inverse of the
    // standard black-on-white that ZXing expects by default.
    val binaryBitmap = BinaryBitmap(HybridBinarizer(source))

    return try {
        reader.decode(binaryBitmap, hints).text
    } catch (_: NotFoundException) {
        null
    } catch (_: ChecksumException) {
        null
    } catch (_: FormatException) {
        null
    } catch (_: Exception) {
        null
    }
}

// ---------------------------------------------------------------------------
// Random alias generator — multiple formats (Verb Animal, Title Animal,
// Title Noun, Adjective Noun, Historical figure).
//
// The word pools + format distribution live in ContactAliasGenerator
// (shared/commonMain) so both platforms draw from the same alphabet.
// ---------------------------------------------------------------------------

private fun generateRandomAlias(): String = ContactAliasGenerator.generate()


// ---------------------------------------------------------------------------
// Code Exchange tab — copy/paste contact data as Base64, reached via the
// hidden 5-tap reveal gesture (add_paste_reveal), not a PIN.
//
// Security purpose: allows contact exchange without a camera, useful
// when contacts are remote. The 5-tap reveal keeps this less-secure
// exchange method out of the way of casual use. The payload is identical
// to the QR data — the same shared secret derivation applies.
// ---------------------------------------------------------------------------

@Composable
private fun CodeExchangeTab(
    myQrPayload: String?,
    pairing: PairingSession,
    myInboxId: String?,
    myReadCap: String?,
    mintState: MintState,
    vault: VaultDatabase,
    onContactSaved: (contactId: String, alias: String, peerInboxId: String?) -> Unit,
    onStartAgain: (message: String) -> Unit,
) {
    // Reached only via the hidden 5-tap gesture (the access gate). Mint runs
    // in the background while the user reads — until it completes, the "your
    // code" block stays as a "Setting up inbox…" placeholder. The "Add
    // contact" button only enables once both halves (our mint + their parsed
    // paste) are available.
    val context = LocalContext.current
    // Configuration-aware (a locale change re-reads it); LocalContext is not.
    val resources = LocalResources.current
    val myCode = remember(myQrPayload) {
        myQrPayload?.let { Base64.encodeToString(it.toByteArray(Charsets.UTF_8), Base64.NO_WRAP) }
    }
    var pastedCode by remember { mutableStateOf("") }
    var copied by remember { mutableStateOf(false) }
    // Idempotency latch (paste-path parity). The wizard's saveContact()
    // guards the camera path with pendingContactId, but this tab calls
    // pairing.save() directly, so a double-tap (or a click re-fired across a
    // recomposition, before the parent has switched to the Done step) inserted TWO
    // contacts for the same peer — each with its OWN freshly-minted inbox pair. That
    // silently splits the pairing: the peer writes to one of our inboxes while the
    // conversation drains the other, and the message never arrives. Set only after a
    // successful insert, so a failed save can still be retried — identical semantics to
    // saveContact() above and to iOS saveContact (AddContactView.swift:778).
    var savedContactId by remember { mutableStateOf<String?>(null) }
    // Sibling path: this tab saves from its own `clickable` lambda, so it maps the
    // save outcome (inbox in use, invalid code, start again) itself. Same refusals,
    // same messages as saveContact().
    var addError by remember { mutableStateOf<String?>(null) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        // --- My code section ---
        Text(
            text = stringResource(R.string.add_contact_your_code),
            style = MaterialTheme.typography.bodyLarge,
            color = RunGrey
        )

        Spacer(Modifier.height(8.dp))

        // Code display
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(12.dp))
                .background(RunSurfaceAlt)
                .padding(12.dp)
        ) {
            Text(
                text = myCode ?: when (mintState) {
                    is MintState.Failed -> stringResource(R.string.add_contact_mint_failed_prefix, mintState.reason)
                    else -> stringResource(R.string.add_contact_setting_up_inbox)
                },
                style = MaterialTheme.typography.bodySmall.copy(fontSize = 11.sp),
                color = RunWhite.copy(alpha = 0.7f),
                maxLines = 3,
                modifier = Modifier.testTag("debug_my_code")
            )
        }

        Spacer(Modifier.height(12.dp))

        Box(
            modifier = Modifier
                .clip(RoundedCornerShape(8.dp))
                .background(if (myCode == null) RunSurface else if (copied) RunSurface else RunWhite)
                .clickable(enabled = myCode != null) {
                    val code = myCode ?: return@clickable
                    // Sensitive + cleared after 20 s: this code carries half the
                    // per-contact shared secret + the inbox write capability. 20 s
                    // matches the iOS pasteboard expiry and leaves time to switch
                    // apps and paste. An in-process timer plus an AlarmManager
                    // backstop clear it, so the clear also fires after the process
                    // was killed or frozen in the background (maybe minutes late in
                    // Doze). Below API 33 a keyboard's own clipboard history is not
                    // reached: EXTRA_IS_SENSITIVE is set on every level, but IMEs
                    // honour it from API 33.
                    SensitiveClipboard.copy(context, "contact", code, clearAfterMs = 20_000)
                    copied = true
                }
                .padding(horizontal = 24.dp, vertical = 10.dp),
            contentAlignment = Alignment.Center
        ) {
            Text(
                if (copied) stringResource(R.string.common_copied) else stringResource(R.string.common_copy),
                color = if (copied) RunGrey else RunBlack
            )
        }

        Spacer(Modifier.height(32.dp))

        // --- Paste their code section ---
        Text(
            text = stringResource(R.string.add_contact_their_code),
            style = MaterialTheme.typography.bodyLarge,
            color = RunGrey
        )

        Spacer(Modifier.height(8.dp))

        Box(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(12.dp))
                .background(RunSurfaceAlt)
                .padding(horizontal = 16.dp, vertical = 14.dp)
        ) {
            if (pastedCode.isEmpty()) {
                Text(
                    text = stringResource(R.string.add_contact_paste_placeholder),
                    style = MaterialTheme.typography.bodyLarge,
                    color = RunGrey
                )
            }
            NoPersonalizedLearning {
                BasicTextField(
                    value = pastedCode,
                    onValueChange = { pastedCode = it },
                    textStyle = MaterialTheme.typography.bodySmall.copy(
                        color = RunWhite,
                        fontSize = 11.sp
                    ),
                    cursorBrush = SolidColor(RunWhite),
                    singleLine = false,
                    maxLines = 3,
                    // No IME learning of the pairing code (secret material).
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("debug_code_input")
                )
            }
        }

        Spacer(Modifier.height(16.dp))

        val parsed = remember(pastedCode, pairing) {
            try {
                val json = String(Base64.decode(pastedCode.trim(), Base64.NO_WRAP), Charsets.UTF_8)
                // The paste exchange always trades FULL codes (both sides can
                // wait for mint over copy/paste) — secret-only is rejected.
                pairing.parsePeerCode(json, myInboxId, requireFull = true)
            } catch (_: Exception) {
                null
            }
        }

        // Add is enabled only when we have BOTH halves — our own mint result
        // and a parseable peer code. Mint typically finishes during the user's
        // copy-and-paste round trip, but if not, the button waits. Once the save has
        // landed the button is latched off (savedContactId) — one contact per pairing.
        val ready = mintState as? MintState.Ready
        val canSave = parsed != null && ready != null && myInboxId != null && myReadCap != null &&
            savedContactId == null
        Box(
            modifier = Modifier
                .testTag("debug_add_contact_button")
                .clip(RoundedCornerShape(8.dp))
                .background(if (canSave) RunWhite else RunSurface)
                .clickable(enabled = canSave) {
                    if (savedContactId != null) return@clickable   // latch: already saved
                    val data = parsed ?: return@clickable
                    val r = ready ?: return@clickable
                    addError = null
                    val alias = generateRandomAlias()
                    val newContactId = UUID.randomUUID().toString()
                    // No announce here: the paste exchange always trades FULL
                    // codes, so neither side ends up pending. Both halves are present,
                    // so the session fixes the role order exactly as on the camera path.
                    when (
                        pairing.save(
                            vault = vault,
                            contactId = newContactId,
                            peer = data,
                            myInboxId = r.minted.inboxId,
                            myReadCap = r.minted.readCapability,
                            myCtlInboxId = r.ctlMinted.inboxId,
                            myCtlReadCap = r.ctlMinted.readCapability,
                            alias = alias,
                            mnemonic = "",
                            myGrpInboxId = r.grpMinted?.inboxId,
                            myGrpReadCap = r.grpMinted?.readCapability,
                        )
                    ) {
                        PairingSaveOutcome.SAVED_V3, PairingSaveOutcome.SAVED_LEGACY -> {
                            // Latch AFTER the save succeeded (a refused save leaves the
                            // latch clear, so the user can retry) — same order as saveContact().
                            savedContactId = newContactId
                            // Always non-null here: `parsed` is built with
                            // requireFull = true, so the paste path can never land the
                            // Done step in the scan-back state.
                            onContactSaved(newContactId, alias, data.inboxId)
                        }
                        // Refused, nothing written. The latch stays clear and the parse
                        // is untouched, so a retry (after deleting the stale contact)
                        // still works.
                        PairingSaveOutcome.INBOX_IN_USE -> addError = inboxInUseMessage(context)
                        PairingSaveOutcome.INVALID_CODE ->
                            addError = resources.getString(R.string.add_contact_invalid_code)
                        PairingSaveOutcome.START_AGAIN ->
                            onStartAgain(resources.getString(R.string.add_contact_start_again_error))
                    }
                }
                .padding(horizontal = 24.dp, vertical = 10.dp),
            contentAlignment = Alignment.Center
        ) {
            Text(
                stringResource(R.string.add_contact_title),
                color = if (canSave) RunBlack else RunGrey
            )
        }

        addError?.let { msg ->
            Spacer(Modifier.height(12.dp))
            Text(
                text = msg,
                style = MaterialTheme.typography.bodySmall,
                color = RunError,
                modifier = Modifier.testTag("add_contact_error")
            )
        }
    }
}

// QR bitmaps: see QrBitmap.kt (crisp whole-pixel modules; shared with the donate and move screens).

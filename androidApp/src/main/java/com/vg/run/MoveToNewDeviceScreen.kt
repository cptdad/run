package com.vg.run

import android.graphics.Bitmap
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.TextAutoSize
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import com.vg.run.ui.theme.RunBlack
import com.vg.run.ui.theme.RunGrey
import com.vg.run.ui.theme.RunSurface
import com.vg.run.ui.theme.RunWhite
import com.vg.run.ui.theme.RuneDanger
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import androidx.activity.compose.BackHandler
import androidx.compose.animation.core.Animatable
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.unit.IntOffset

// ---------------------------------------------------------------------------
// MoveToNewDeviceScreen — the OLD phone's whole side of a device move
// (docs/device-move.md §Protocol, phone A). One screen, driven by
// MoveManager.exportState:
//
//   explain → Preparing(step) → Ready (QR + text) → Moved (wipe / keep off)
//                                    ↘ Failed (retry / cancel)
//   FrozenNoCode  (a re-launch after the process died with a code on screen)
//
// It is ALSO the screen every unlock lands on while the vault carries
// `mig_frozen` (MainActivity routes "move_frozen" here): a frozen phone must
// not reach the contact list, because "reachable" would eventually mean
// "polling", and one received message forks the ratchet the new phone now owns.
//
// Screenshot protection is window-level (MainActivity's FLAG_SECURE in release),
// so nothing is added here. What IS added is the ON_STOP scrub: the one-time
// code is RAM-only and must not survive the foreground session that showed it.
// ---------------------------------------------------------------------------

@OptIn(ExperimentalComposeUiApi::class)
@Composable
fun MoveToNewDeviceScreen(
    viewModel: RunViewModel,
    /** True for the "every unlock while frozen" entry: skip the explainer, this
     *  phone is already stopped and the user needs the choices, not the pitch. */
    frozenEntry: Boolean,
    /** Back out of the explainer (settings entry only — nothing has happened yet). */
    onBack: () -> Unit,
    /** A cancel that actually landed: the phone is live again. */
    onUnfrozen: () -> Unit,
    /** The wipe landed; the vault is gone and setup is the only place left. */
    onWiped: () -> Unit,
) {
    val state by viewModel.moveManager.exportState.collectAsState()
    // The explainer is skipped for the frozen entry and consumed once tapped.
    // rememberSaveable is deliberate: a rotation mid-export must not drop the
    // user back onto the explain page for a move that is already running.
    var explained by rememberSaveable { mutableStateOf(frozenEntry) }
    // Between the explainer and the export sits a fresh
    // credential check (MoveCredentialPage). Saveable for the same rotation reason.
    var askingCredential by rememberSaveable { mutableStateOf(false) }
    // "Show again" / "Retry" re-issue a bundle under a fresh code, which is as
    // sensitive as the first export: the same credential prompt runs first
    // (MoveExportAuth.verifyAndGrant grants the one-shot token reissueExport
    // consumes). Saveable for the same rotation reason.
    var askingReissueCredential by rememberSaveable { mutableStateOf(false) }

    // Drop the RAM-only code when this leaves the foreground. The Activity
    // normally finishes on ON_STOP anyway (finishAndRemoveTask → onCleared),
    // which tears everything down; this covers the window before that lands and
    // mirrors the iOS `.background` handler. `.background`-equivalent only —
    // never a pause, for the same reason iOS never gates on `.inactive`.
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_STOP) viewModel.scrubMoveSecrets()
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    // The explainer is the only escapable page. Past it this phone is frozen —
    // BACK must not reveal the contact list underneath, which would be a live
    // screen on a device that must not poll (and, from the frozen entry, there
    // is nothing underneath at all: that route is navigated with popUpTo(0)).
    BackHandler(enabled = true) {
        if (askingReissueCredential) askingReissueCredential = false
        else if (askingCredential && !explained) askingCredential = false
        else if (!explained && !frozenEntry) onBack()
    }

    MoveScreenScaffold {
        if (!explained && askingCredential) {
            MoveCredentialPage(
                viewModel = viewModel,
                onVerified = {
                    explained = true
                    viewModel.beginMoveExport()
                },
                onCancel = { askingCredential = false },
                onWiped = onWiped,
            )
            return@MoveScreenScaffold
        }
        if (!explained) {
            MoveExplainPage(
                onContinue = { askingCredential = true },
                onBack = onBack,
            )
            return@MoveScreenScaffold
        }
        val reissueOffered = state is MoveExportState.FrozenNoCode || state is MoveExportState.Failed
        if (askingReissueCredential && reissueOffered) {
            MoveCredentialPage(
                viewModel = viewModel,
                onVerified = {
                    askingReissueCredential = false
                    viewModel.reissueMoveExport()
                },
                onCancel = { askingReissueCredential = false },
                onWiped = onWiped,
            )
            return@MoveScreenScaffold
        }
        when (val s = state) {
            // Idle here means "Continue was tapped, the bounded wait for a live
            // transport is running" — nothing is frozen yet, so the freeze copy
            // would be a lie. The neutral preparing line covers both that wait and
            // the instant before the first Preparing state lands.
            is MoveExportState.Idle -> MoveStatusPage(stringResource(R.string.move_step_mint))
            is MoveExportState.Preparing -> MoveStatusPage(
                when (s.step) {
                    MoveExportStep.UNREGISTER_PUSH -> stringResource(R.string.move_step_unregister)
                    MoveExportStep.FREEZE -> stringResource(R.string.move_step_freeze)
                    MoveExportStep.MINT -> stringResource(R.string.move_step_mint)
                    MoveExportStep.UPLOAD -> stringResource(R.string.move_step_upload)
                }
            )
            is MoveExportState.Ready -> MoveReadyPage(viewModel = viewModel, handle = s.handle)
            is MoveExportState.Moved -> MoveDonePage(viewModel = viewModel, onWiped = onWiped)
            is MoveExportState.FrozenNoCode -> MoveFrozenPage(
                viewModel = viewModel,
                onReissue = { askingReissueCredential = true },
                onUnfrozen = onUnfrozen,
                onWiped = onWiped,
            )
            is MoveExportState.Failed -> MoveFailedPage(
                viewModel = viewModel,
                error = s.error,
                onReissue = { askingReissueCredential = true },
                onUnfrozen = onUnfrozen,
            )
        }
    }
}

// ---------------------------------------------------------------------------

@OptIn(ExperimentalComposeUiApi::class)
@Composable
private fun MoveScreenScaffold(content: @Composable () -> Unit) {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .semantics { testTagsAsResourceId = BuildConfig.DEBUG }
            .background(RunBlack),
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .statusBarsPadding()
                .navigationBarsPadding()
                .padding(horizontal = 28.dp)
                .verticalScroll(rememberScrollState()),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Spacer(Modifier.height(24.dp))
            content()
            Spacer(Modifier.height(28.dp))
        }
    }
}

@Composable
private fun MoveExplainPage(onContinue: () -> Unit, onBack: () -> Unit) {
    Text(
        stringResource(R.string.move_explain_title),
        style = MaterialTheme.typography.headlineSmall,
        color = RunWhite,
        textAlign = TextAlign.Center,
    )
    Spacer(Modifier.height(12.dp))
    MoveBody(stringResource(R.string.move_explain_body))
    Spacer(Modifier.height(20.dp))
    MoveSection(
        title = stringResource(R.string.move_explain_moves_title),
        body = stringResource(R.string.move_explain_moves_body),
    )
    Spacer(Modifier.height(14.dp))
    MoveSection(
        title = stringResource(R.string.move_explain_stays_title),
        // The tier name comes from the shared tier-name resource — never a
        // hardcoded "Secure", which would drift from the slider's own label.
        body = stringResource(
            R.string.move_explain_stays_body,
            stringResource(R.string.protection_tier_name_private),
        ),
    )
    Spacer(Modifier.height(20.dp))
    Text(
        stringResource(R.string.move_explain_warning),
        style = MaterialTheme.typography.bodySmall.copy(fontSize = 12.5.sp),
        color = RuneDanger,
        textAlign = TextAlign.Center,
    )
    Spacer(Modifier.height(24.dp))
    MovePrimaryButton(
        label = stringResource(R.string.move_explain_continue_label),
        testTag = "move_explain_continue",
        onClick = onContinue,
    )
    Spacer(Modifier.height(10.dp))
    MoveTextButton(label = stringResource(R.string.common_back), testTag = "move_back", onClick = onBack)
}

/**
 * Fresh-credential gate in front of the export. Same policy as
 * the change-PIN current-credential step: [RunViewModel.verifyMoveExportAuth]
 * counts the guess against the daily change-PIN budget first, wipes at the cap,
 * and on a Lever B vault also demands the strong biometric. Re-uses the change-PIN
 * input widgets and their a11y ids (pin_prompt, passphrase_field,
 * credential_continue, the keypad) so existing helpers drive it unchanged.
 */
@Composable
private fun MoveCredentialPage(
    viewModel: RunViewModel,
    onVerified: () -> Unit,
    onCancel: () -> Unit,
    onWiped: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    val isPassphrase = remember { viewModel.vaultSelector.isPassphraseMode() }
    var enteredPin by remember { mutableStateOf("") }
    var enteredPhrase by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var errorFlash by remember { mutableStateOf(false) }
    val shakeOffset = remember { Animatable(0f) }

    fun submit(credential: String) {
        if (busy || credential.isEmpty()) return
        busy = true
        scope.launch {
            val outcome = viewModel.verifyMoveExportAuth(credential)
            when (outcome) {
                MoveExportAuth.Outcome.OK -> {
                    enteredPin = ""
                    enteredPhrase = ""
                    onVerified()
                    return@launch
                }
                MoveExportAuth.Outcome.WIPE -> {
                    viewModel.performEmergencyWipe()
                    onWiped()
                    return@launch
                }
                else -> {
                    // WRONG and DEFERRED both look like a rejected entry (a deferred
                    // biometric/outage is retried; nothing was granted or wiped).
                    errorFlash = true
                    launch { playShakeAnimation(shakeOffset) }
                    delay(500)
                    enteredPin = ""
                    enteredPhrase = ""
                    errorFlash = false
                    busy = false
                }
            }
        }
    }

    LaunchedEffect(enteredPin) {
        if (isPassphrase || enteredPin.length < PIN_LENGTH || busy) return@LaunchedEffect
        delay(150)
        submit(enteredPin)
    }

    Text(
        if (isPassphrase) stringResource(R.string.pin_change_enter_current_passphrase)
        else stringResource(R.string.pin_change_enter_current_pin),
        style = MaterialTheme.typography.bodyLarge,
        color = RunWhite,
        textAlign = TextAlign.Center,
        modifier = Modifier.testTag("pin_prompt"),
    )
    Spacer(Modifier.height(16.dp))
    if (isPassphrase) {
        Box(
            Modifier.offset { IntOffset(shakeOffset.value.toInt(), 0) }
        ) {
            PassphraseInputField(
                value = enteredPhrase,
                onValueChange = { enteredPhrase = it },
                placeholder = stringResource(R.string.pin_passphrase_placeholder),
                fieldTag = "passphrase_field",
                enabled = !busy,
                isError = errorFlash,
            )
        }
        Spacer(Modifier.height(16.dp))
        MovePrimaryButton(
            label = stringResource(R.string.common_continue),
            testTag = "credential_continue",
            onClick = { submit(enteredPhrase) },
        )
    } else {
        PinDotRow(filledCount = enteredPin.length, errorFlash = errorFlash, shakeOffset = shakeOffset)
        Spacer(Modifier.height(24.dp))
        PinKeypad(
            onDigit = { digit -> if (enteredPin.length < PIN_LENGTH) enteredPin += digit },
            onDelete = { if (enteredPin.isNotEmpty()) enteredPin = enteredPin.dropLast(1) },
            enabled = enteredPin.length < PIN_LENGTH && !busy,
        )
    }
    Spacer(Modifier.height(10.dp))
    MoveTextButton(label = stringResource(R.string.common_cancel), testTag = "move_credential_cancel", onClick = { if (!busy) onCancel() })
}

@Composable
private fun MoveStatusPage(status: String) {
    Spacer(Modifier.height(60.dp))
    CircularProgressIndicator(color = RunWhite, strokeWidth = 2.dp, modifier = Modifier.size(28.dp))
    Spacer(Modifier.height(20.dp))
    Text(
        status,
        style = MaterialTheme.typography.bodyLarge,
        color = RunWhite,
        textAlign = TextAlign.Center,
        // Same id as the Ready page's line: one "what is happening" element for
        // this screen, whichever phase it is in.
        modifier = Modifier.testTag("move_waiting_status"),
    )
}

/**
 * The code. Everything on this page is secret material, which is why the QR and
 * the text are dropped from the composition as soon as the state leaves `Ready`
 * (the ON_STOP scrub collapses Ready → FrozenNoCode, and this page goes with it).
 */
@Composable
private fun MoveReadyPage(viewModel: RunViewModel, handle: MoveHandle) {
    val context = LocalContext.current
    val handleText = remember(handle) { MoveHandleCodec.toQrText(handle) }
    val qr: Bitmap = remember(handleText) { generateQrBitmap(handleText, sizePx = 800) }
    var showText by remember { mutableStateOf(false) }
    var copied by remember { mutableStateOf(false) }
    var cancelRefusedMessage by remember { mutableStateOf<String?>(null) }
    var cancelHidden by remember { mutableStateOf(false) }
    val alreadyPickedUp = stringResource(R.string.move_cancel_refused)
    val couldNotConfirm = stringResource(R.string.move_cancel_unconfirmed)

    // 10 s peek while the code is up: pending == 0 or a 404 flips the state to
    // Moved. A failed peek changes nothing (a Tor hiccup must never read as
    // "the new phone has it" — RelayMoveTransport keeps those apart).
    LaunchedEffect(Unit) {
        while (true) {
            delay(10_000L)
            viewModel.refreshMoveTransferState()
        }
    }

    Text(
        stringResource(R.string.move_qr_title),
        style = MaterialTheme.typography.headlineSmall,
        color = RunWhite,
        textAlign = TextAlign.Center,
    )
    Spacer(Modifier.height(10.dp))
    MoveBody(stringResource(R.string.move_qr_body))
    Spacer(Modifier.height(18.dp))
    Image(
        bitmap = qr.asImageBitmap(),
        contentDescription = null,
        modifier = Modifier
            .size(260.dp)
            .clip(RoundedCornerShape(12.dp))
            .testTag("move_qr_image"),
    )
    Spacer(Modifier.height(14.dp))
    Text(
        stringResource(R.string.move_qr_warning),
        style = MaterialTheme.typography.bodySmall.copy(fontSize = 12.sp),
        color = RuneDanger,
        textAlign = TextAlign.Center,
    )
    Spacer(Modifier.height(16.dp))
    MoveTextButton(
        label = if (showText) stringResource(R.string.move_hide_text_label)
        else stringResource(R.string.move_show_text_label),
        testTag = "move_show_text_toggle",
        onClick = { showText = !showText },
    )
    if (showText) {
        Spacer(Modifier.height(12.dp))
        MoveBody(stringResource(R.string.move_handle_caption))
        Spacer(Modifier.height(8.dp))
        Box(
            Modifier
                .fillMaxWidth()
                .background(RunSurface, RoundedCornerShape(12.dp))
                .padding(horizontal = 14.dp, vertical = 12.dp),
        ) {
            // Deliberately NOT selectable. A
            // SelectionContainer put the system "Copy" action on a string that is a
            // full vault-export credential (read capability + one-time code), and
            // that path writes an UNFLAGGED, UNEXPIRING clip — no
            // EXTRA_IS_SENSITIVE (so it is eligible for clipboard preview/history
            // and, on OEM builds, cloud clipboard sync) and no timed clear. The
            // guarded [copyTransferHandle] button below is the only copy affordance:
            // it marks the clip sensitive and self-clears it after 60 s. Reading is
            // unaffected — the element's text IS the handle JSON
            // (MoveHandleCodec.toQrText), no truncation and no ellipsis, and the
            // testTag below is what the e2e reads.
            Text(
                handleText,
                color = RunWhite,
                fontFamily = FontFamily.Monospace,
                fontSize = 11.sp,
                modifier = Modifier.testTag("move_handle_text"),
            )
        }
        Spacer(Modifier.height(10.dp))
        MoveTextButton(
            label = if (copied) stringResource(R.string.common_copied) else stringResource(R.string.common_copy),
            testTag = "move_copy_button",
            onClick = {
                copyTransferHandle(context, handleText)
                copied = true
            },
        )
    }
    Spacer(Modifier.height(20.dp))
    Text(
        stringResource(R.string.move_waiting),
        style = MaterialTheme.typography.bodyLarge,
        color = RunWhite,
        textAlign = TextAlign.Center,
        modifier = Modifier.testTag("move_waiting_status"),
    )
    Spacer(Modifier.height(6.dp))
    MoveBody(stringResource(R.string.move_expiry_note))
    cancelRefusedMessage?.let {
        Spacer(Modifier.height(14.dp))
        Text(
            it,
            style = MaterialTheme.typography.bodySmall.copy(fontSize = 12.5.sp),
            color = RuneDanger,
            textAlign = TextAlign.Center,
            modifier = Modifier.testTag("move_error_text"),
        )
    }
    if (!cancelHidden) {
        Spacer(Modifier.height(18.dp))
        MoveTextButton(
            label = stringResource(R.string.move_cancel_label),
            testTag = "move_cancel_button",
            onClick = {
                viewModel.cancelMoveExport { ok ->
                    if (!ok) {
                        // Two different refusals, and the difference matters:
                        // MoveManager moves the state to Moved when the bundle is
                        // provably drained/gone, and leaves it alone when it could
                        // not ASK (no transport, failed peek). Only the first is
                        // final — hide the button for that one, keep it for the
                        // "try again in a moment" case.
                        val drained = viewModel.moveManager.exportState.value is MoveExportState.Moved
                        cancelRefusedMessage = if (drained) alreadyPickedUp else couldNotConfirm
                        cancelHidden = drained
                    }
                }
            },
        )
    }
}

@Composable
private fun MoveDonePage(viewModel: RunViewModel, onWiped: () -> Unit) {
    var keptOff by remember { mutableStateOf(false) }
    if (keptOff) {
        Text(
            stringResource(R.string.move_kept_off_title),
            style = MaterialTheme.typography.headlineSmall,
            color = RunWhite,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(12.dp))
        MoveBody(stringResource(R.string.move_kept_off_body))
        Spacer(Modifier.height(24.dp))
        MovePrimaryButton(
            label = stringResource(R.string.move_done_wipe_label),
            testTag = "move_done_wipe_button",
            danger = true,
        ) {
            viewModel.performEmergencyWipe(deniable = false)
            onWiped()
        }
        return
    }
    Text(
        stringResource(R.string.move_done_title),
        style = MaterialTheme.typography.headlineSmall,
        color = RunWhite,
        textAlign = TextAlign.Center,
    )
    Spacer(Modifier.height(12.dp))
    // "Picked up" is a HINT, not proof: an expired transfer inbox 404s exactly
    // like a drained one, so the copy sends the user to the new phone to confirm
    // before the irreversible step, and "Keep it off" always stays available.
    MoveBody(stringResource(R.string.move_done_body))
    Spacer(Modifier.height(10.dp))
    MoveBody(stringResource(R.string.move_done_expired_hint))
    Spacer(Modifier.height(24.dp))
    MovePrimaryButton(
        label = stringResource(R.string.move_done_wipe_label),
        testTag = "move_done_wipe_button",
        danger = true,
    ) {
        // deniable = false: an explicit, user-initiated wipe must land on setup, not
        // behind the black "nothing to see" cover (ProcessWipeCover).
        viewModel.performEmergencyWipe(deniable = false)
        onWiped()
    }
    Spacer(Modifier.height(10.dp))
    MoveTextButton(
        label = stringResource(R.string.move_done_keep_label),
        testTag = "move_done_keep_button",
        onClick = { keptOff = true },
    )
}

@Composable
private fun MoveFrozenPage(
    viewModel: RunViewModel,
    onReissue: () -> Unit,
    onUnfrozen: () -> Unit,
    onWiped: () -> Unit,
) {
    var cancelMessage by remember { mutableStateOf<String?>(null) }
    val alreadyPickedUp = stringResource(R.string.move_cancel_refused)
    val couldNotConfirm = stringResource(R.string.move_cancel_unconfirmed)

    Text(
        stringResource(R.string.move_frozen_title),
        style = MaterialTheme.typography.headlineSmall,
        color = RunWhite,
        textAlign = TextAlign.Center,
    )
    Spacer(Modifier.height(12.dp))
    MoveBody(stringResource(R.string.move_frozen_body))
    Spacer(Modifier.height(24.dp))
    MovePrimaryButton(
        label = stringResource(R.string.move_frozen_show_again_label),
        // The re-issue path: a fresh bundle under a fresh code. The vault has not
        // changed since the freeze, so this is always safe to repeat. [onReissue]
        // asks for the credential first, then calls reissueMoveExport().
        testTag = "move_error_retry",
        onClick = onReissue,
    )
    Spacer(Modifier.height(10.dp))
    MoveTextButton(
        label = stringResource(R.string.move_cancel_label),
        testTag = "move_cancel_button",
        onClick = {
            viewModel.cancelMoveExport { ok ->
                if (ok) {
                    onUnfrozen()
                } else {
                    val drained = viewModel.moveManager.exportState.value is MoveExportState.Moved
                    cancelMessage = if (drained) alreadyPickedUp else couldNotConfirm
                }
            }
        },
    )
    Spacer(Modifier.height(10.dp))
    MoveTextButton(
        label = stringResource(R.string.move_done_wipe_label),
        testTag = "move_done_wipe_button",
        danger = true,
    ) {
        viewModel.performEmergencyWipe(deniable = false)
        onWiped()
    }
    cancelMessage?.let {
        Spacer(Modifier.height(16.dp))
        Text(
            it,
            style = MaterialTheme.typography.bodySmall.copy(fontSize = 12.5.sp),
            color = RuneDanger,
            textAlign = TextAlign.Center,
            modifier = Modifier.testTag("move_error_text"),
        )
    }
}

@Composable
private fun MoveFailedPage(
    viewModel: RunViewModel,
    error: MoveError,
    onReissue: () -> Unit,
    onUnfrozen: () -> Unit,
) {
    var cancelMessage by remember { mutableStateOf<String?>(null) }
    val couldNotConfirm = stringResource(R.string.move_cancel_unconfirmed)
    val alreadyPickedUp = stringResource(R.string.move_cancel_refused)

    Spacer(Modifier.height(40.dp))
    Text(
        moveErrorMessage(error),
        style = MaterialTheme.typography.bodyLarge,
        color = RuneDanger,
        textAlign = TextAlign.Center,
        modifier = Modifier.testTag("move_error_text"),
    )
    Spacer(Modifier.height(24.dp))
    MovePrimaryButton(
        label = stringResource(R.string.common_retry),
        testTag = "move_error_retry",
        // reissue, not begin: a failure can have left a half-filled transfer
        // inbox recorded, and reissueExport is the path that discards it first.
        // [onReissue] asks for the credential first, like the first export.
        onClick = onReissue,
    )
    Spacer(Modifier.height(10.dp))
    // The phone is FROZEN on every post-freeze failure, so the way back to a
    // working phone must be on this page too — otherwise a mint failure with no
    // relay strands the user on an error screen with nothing but a retry.
    MoveTextButton(
        label = stringResource(R.string.move_cancel_label),
        testTag = "move_cancel_button",
        onClick = {
            viewModel.cancelMoveExport { ok ->
                if (ok) {
                    onUnfrozen()
                } else {
                    val drained = viewModel.moveManager.exportState.value is MoveExportState.Moved
                    cancelMessage = if (drained) alreadyPickedUp else couldNotConfirm
                }
            }
        },
    )
    cancelMessage?.let {
        Spacer(Modifier.height(16.dp))
        Text(
            it,
            style = MaterialTheme.typography.bodySmall.copy(fontSize = 12.5.sp),
            color = RunGrey,
            textAlign = TextAlign.Center,
        )
    }
}

// ---------------------------------------------------------------------------
// Shared bits (also used by MoveFromDeviceScreen.kt)
// ---------------------------------------------------------------------------

@Composable
internal fun MoveBody(text: String) {
    Text(
        text,
        style = MaterialTheme.typography.bodySmall.copy(fontSize = 12.5.sp),
        color = RunGrey,
        textAlign = TextAlign.Center,
    )
}

@Composable
internal fun MoveSection(title: String, body: String) {
    Text(title, style = MaterialTheme.typography.bodyLarge, color = RunWhite, textAlign = TextAlign.Center)
    Spacer(Modifier.height(4.dp))
    MoveBody(body)
}

@Composable
internal fun MovePrimaryButton(
    label: String,
    testTag: String,
    enabled: Boolean = true,
    danger: Boolean = false,
    onClick: () -> Unit,
) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(testTag)
            .clip(RoundedCornerShape(8.dp))
            .background(if (!enabled) RunSurface else if (danger) RuneDanger else RunWhite)
            .clickable(enabled = enabled, onClick = onClick)
            .padding(vertical = 13.dp),
        contentAlignment = Alignment.Center,
    ) {
        // ONE line, never a mid-word break.
        // iOS sibling: MoveToNewDeviceView.swift's primaryButton/dangerButton.
        Text(
            label,
            color = if (!enabled) RunGrey else if (danger) RunWhite else RunBlack,
            maxLines = 1,
            softWrap = false,
            autoSize = TextAutoSize.StepBased(minFontSize = 10.sp, maxFontSize = 16.sp, stepSize = 0.5.sp),
        )
    }
}

@Composable
internal fun MoveTextButton(
    label: String,
    testTag: String,
    danger: Boolean = false,
    onClick: () -> Unit,
) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(testTag)
            .clip(RoundedCornerShape(8.dp))
            .background(RunSurface)
            .clickable(onClick = onClick)
            .padding(vertical = 13.dp),
        contentAlignment = Alignment.Center,
    ) {
        // ONE line, never a mid-word break.
        // iOS sibling: MoveToNewDeviceView.swift's secondaryButton.
        Text(
            label,
            color = if (danger) RuneDanger else RunWhite,
            maxLines = 1,
            softWrap = false,
            autoSize = TextAutoSize.StepBased(minFontSize = 10.sp, maxFontSize = 16.sp, stepSize = 0.5.sp),
        )
    }
}

/** One place that maps a [MoveError] to copy, shared by both sides of the move. */
@Composable
internal fun moveErrorMessage(error: MoveError): String = when (error) {
    MoveError.NOT_UNLOCKED -> stringResource(R.string.move_error_locked)
    MoveError.MINT_FAILED -> stringResource(R.string.move_error_mint)
    MoveError.UPLOAD_FAILED -> stringResource(R.string.move_error_upload)
    MoveError.TOO_LARGE -> stringResource(R.string.move_error_too_large)
    MoveError.RELAY_UNREACHABLE -> stringResource(R.string.move_error_relay)
    MoveError.BUNDLE_GONE -> stringResource(R.string.move_error_bundle_gone)
    MoveError.BAD_CODE -> stringResource(R.string.move_error_bad_code)
    MoveError.BUNDLE_CORRUPT -> stringResource(R.string.move_error_corrupt)
    MoveError.SCHEMA_TOO_NEW -> stringResource(R.string.move_error_schema)
    MoveError.IMPORT_FAILED -> stringResource(R.string.move_error_import)
    MoveError.CANCEL_REFUSED -> stringResource(R.string.move_cancel_refused)
    MoveError.ALREADY_IMPORTED -> stringResource(R.string.move_error_already_imported)
}

/**
 * Copies the transfer handle, flagged sensitive and auto-cleared after 60 s —
 * the same discipline as the pairing code in AddContactScreen (this text is the
 * read capability AND the one-time code). EXTRA_IS_SENSITIVE is set on every API
 * level, but the platform and keyboards honour it from API 33 only: below that a
 * keyboard's own clipboard history may keep the handle, and the timed clear
 * cannot reach it. 60 s matches the iOS clear and leaves time to carry the
 * handle to the new device. The clear is carried by an in-process timer plus an
 * AlarmManager backstop, so it also fires after Rún's process was killed or
 * frozen in the background (possibly some minutes late under Doze).
 */
private fun copyTransferHandle(context: android.content.Context, text: String) {
    SensitiveClipboard.copy(context, "transfer", text, clearAfterMs = 60_000)
}

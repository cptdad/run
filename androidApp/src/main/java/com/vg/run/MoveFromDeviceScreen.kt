package com.vg.run

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
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
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vg.run.ui.theme.RunBlack
import com.vg.run.ui.theme.RunGrey
import com.vg.run.ui.theme.RunSurfaceAlt
import com.vg.run.ui.theme.RunWhite
import com.vg.run.ui.theme.RuneDanger

// ---------------------------------------------------------------------------
// The NEW phone's side of a device move (docs/device-move.md §Protocol, phone B)
// plus the setup chooser that leads into it.
//
// Ordering is the whole design here: the handle is scanned BEFORE the normal
// onboarding (PIN/passphrase, tier, provision) and is held in RAM on the
// ViewModel only. This phone provisions a completely ordinary fresh vault
// through the untouched path — nothing about the move installs a vault — and
// the import runs after the FIRST unlock, on top of it.
// ---------------------------------------------------------------------------

/**
 * First-launch fork: set up as new, or take over from another phone. Sits in
 * front of PinSetupScreen; both branches continue into the SAME setup flow.
 */
@OptIn(ExperimentalComposeUiApi::class)
@Composable
fun SetupChooserScreen(onSetUpAsNew: () -> Unit, onMoveFromPhone: () -> Unit) {
    MoveSetupScaffold {
        Spacer(Modifier.height(40.dp))
        Text(
            stringResource(R.string.setup_choose_title),
            style = MaterialTheme.typography.headlineSmall,
            color = RunWhite,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(12.dp))
        MoveBody(stringResource(R.string.setup_choose_body))
        Spacer(Modifier.height(32.dp))
        MovePrimaryButton(
            label = stringResource(R.string.setup_choose_new_label),
            testTag = "setup_choose_new",
            onClick = onSetUpAsNew,
        )
        Spacer(Modifier.height(12.dp))
        MoveTextButton(
            label = stringResource(R.string.setup_choose_move_label),
            testTag = "setup_choose_move",
            onClick = onMoveFromPhone,
        )
    }
}

/**
 * Scan (or paste) the transfer code shown by the old phone. Both paths are on
 * the SAME screen and always visible: no reveal gesture gates the paste field
 * (unlike Add Contact's code-exchange tab), because a user whose camera cannot
 * read the other screen has no other way through.
 *
 * Nothing is persisted here. [onHandle] hands the parsed handle to the
 * ViewModel's RAM-only slot and setup continues as normal.
 */
@OptIn(ExperimentalComposeUiApi::class)
@Composable
fun MoveFromDeviceScreen(
    onHandle: (MoveHandle) -> Unit,
    onBack: () -> Unit,
) {
    var pasted by remember { mutableStateOf("") }
    var invalid by remember { mutableStateOf(false) }

    MoveSetupScaffold {
        Spacer(Modifier.height(20.dp))
        Text(
            stringResource(R.string.move_from_title),
            style = MaterialTheme.typography.headlineSmall,
            color = RunWhite,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(10.dp))
        MoveBody(stringResource(R.string.move_from_body))
        Spacer(Modifier.height(18.dp))
        Box(
            Modifier
                .fillMaxWidth()
                .height(280.dp)
                .clip(RoundedCornerShape(12.dp))
                .background(RunSurfaceAlt),
        ) {
            // The shared camera surface (AddContactScreen.QrCameraScanner). It
            // returns true when the text was ACCEPTED, which latches the analyzer
            // off; a stray non-move QR in frame is rejected and scanning
            // continues instead of dead-ending the screen.
            QrCameraScanner(modifier = Modifier.fillMaxSize(), scanTestTag = "move_scan_view") { text ->
                val handle = MoveHandleCodec.parse(text)
                if (handle != null) {
                    onHandle(handle)
                    true
                } else {
                    false
                }
            }
        }
        Spacer(Modifier.height(20.dp))
        Text(
            stringResource(R.string.move_paste_label),
            style = MaterialTheme.typography.bodyLarge,
            color = RunGrey,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(8.dp))
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(12.dp))
                .background(RunSurfaceAlt)
                .padding(horizontal = 16.dp, vertical = 14.dp),
        ) {
            if (pasted.isEmpty()) {
                Text(
                    stringResource(R.string.move_paste_placeholder),
                    style = MaterialTheme.typography.bodyLarge,
                    color = RunGrey,
                )
            }
            NoPersonalizedLearning {
                BasicTextField(
                    value = pasted,
                    onValueChange = { pasted = it; invalid = false },
                    textStyle = MaterialTheme.typography.bodySmall.copy(color = RunWhite, fontSize = 11.sp),
                    cursorBrush = SolidColor(RunWhite),
                    singleLine = false,
                    maxLines = 3,
                    // Ascii + no autocorrect: keeps the IME from learning a transfer
                    // code, without making this a PASSWORD field — a password field
                    // is reported as not-displayed to the accessibility tree, and
                    // this input has to stay drivable.
                    keyboardOptions = KeyboardOptions(
                        keyboardType = KeyboardType.Ascii,
                        autoCorrectEnabled = false,
                    ),
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("move_paste_field"),
                )
            }
        }
        if (invalid) {
            Spacer(Modifier.height(10.dp))
            Text(
                stringResource(R.string.move_paste_invalid),
                style = MaterialTheme.typography.bodySmall.copy(fontSize = 12.5.sp),
                color = RuneDanger,
                textAlign = TextAlign.Center,
                modifier = Modifier.testTag("move_error_text"),
            )
        }
        Spacer(Modifier.height(12.dp))
        MovePrimaryButton(
            label = stringResource(R.string.move_paste_submit_label),
            testTag = "move_paste_submit",
            enabled = pasted.isNotBlank(),
        ) {
            val handle = MoveHandleCodec.parse(pasted)
            if (handle != null) onHandle(handle) else invalid = true
        }
        Spacer(Modifier.height(10.dp))
        MoveTextButton(label = stringResource(R.string.common_back), testTag = "move_back", onClick = onBack)
    }
}

/**
 * The post-unlock import (fetch → import → secure). Reached only with a handle
 * in the ViewModel's RAM slot; the run itself lives on the ViewModel, so a
 * rotation re-attaches to it instead of restarting it.
 */
@OptIn(ExperimentalComposeUiApi::class)
@Composable
fun MoveImportScreen(
    viewModel: RunViewModel,
    onImported: () -> Unit,
    onSkipped: () -> Unit,
) {
    val state by viewModel.moveImportState.collectAsState()

    // Idle only: a rotation recomposes this screen, and re-firing the import
    // after a FAILED one would silently retry behind the user's back (the retry
    // button is the place for that decision). A Running one re-attaches to the
    // ViewModel's job by simply collecting the state.
    LaunchedEffect(Unit) {
        if (viewModel.moveImportState.value is MoveImportUiState.Idle) viewModel.startPendingMoveImport()
    }
    LaunchedEffect(state) {
        if (state is MoveImportUiState.Done) onImported()
        // No handle and nothing running (abandoned, or navigated here twice):
        // there is nothing to show, so don't strand the user on a blank screen.
        if (state is MoveImportUiState.Idle && viewModel.pendingMoveHandle == null) onImported()
    }

    MoveSetupScaffold {
        Spacer(Modifier.height(48.dp))
        Text(
            stringResource(R.string.move_progress_title),
            style = MaterialTheme.typography.headlineSmall,
            color = RunWhite,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(28.dp))
        when (val s = state) {
            is MoveImportUiState.Failed -> {
                Text(
                    stringResource(R.string.move_import_failed_title),
                    style = MaterialTheme.typography.bodyLarge,
                    color = RunWhite,
                    textAlign = TextAlign.Center,
                )
                Spacer(Modifier.height(10.dp))
                Text(
                    moveErrorMessage(s.error),
                    style = MaterialTheme.typography.bodySmall.copy(fontSize = 12.5.sp),
                    color = RuneDanger,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.testTag("move_error_text"),
                )
                Spacer(Modifier.height(24.dp))
                MovePrimaryButton(
                    label = stringResource(R.string.common_retry),
                    testTag = "move_error_retry",
                    // The handle is still in RAM (only a SUCCESS clears it), and
                    // the import is idempotent, so a retry is always safe. It
                    // cannot help for BUNDLE_GONE — the drain is destructive —
                    // which is exactly what that error's copy says to do instead.
                    onClick = { viewModel.startPendingMoveImport() },
                )
                Spacer(Modifier.height(10.dp))
                MoveTextButton(
                    label = stringResource(R.string.move_import_skip_label),
                    testTag = "move_import_skip",
                    onClick = {
                        viewModel.abandonPendingMoveImport()
                        onSkipped()
                    },
                )
            }
            else -> {
                CircularProgressIndicator(color = RunWhite, strokeWidth = 2.dp, modifier = Modifier.size(28.dp))
                Spacer(Modifier.height(20.dp))
                Text(
                    when ((s as? MoveImportUiState.Running)?.step ?: MoveImportStep.FETCHING) {
                        MoveImportStep.FETCHING -> stringResource(R.string.move_progress_fetching)
                        MoveImportStep.IMPORTING -> stringResource(R.string.move_progress_importing)
                        MoveImportStep.SECURING -> stringResource(R.string.move_progress_securing)
                    },
                    style = MaterialTheme.typography.bodyLarge,
                    color = RunWhite,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.testTag("move_progress_status"),
                )
                Spacer(Modifier.height(12.dp))
                MoveBody(stringResource(R.string.move_progress_hint))
            }
        }
    }
}

@OptIn(ExperimentalComposeUiApi::class)
@Composable
private fun MoveSetupScaffold(content: @Composable () -> Unit) {
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
                .imePadding()
                .padding(horizontal = 28.dp)
                .verticalScroll(rememberScrollState()),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            content()
            Spacer(Modifier.height(28.dp))
        }
    }
}

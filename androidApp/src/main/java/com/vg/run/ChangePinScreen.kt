package com.vg.run

import androidx.compose.animation.core.Animatable
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.dp
import com.vg.run.ui.theme.RunBlack
import com.vg.run.ui.theme.RunGrey
import com.vg.run.ui.theme.RunWhite
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlin.math.roundToInt

// ---------------------------------------------------------------------------
// ChangeCredentialScreen — rotate the credential of the currently-unlocked
// vault, optionally switching its MODE (PIN ↔ passphrase, hardening plan
// Lever A "high-risk mode").
//
// Three steps: enter current credential → choose new → confirm new. The
// current step renders in the CURRENT mode's input (keypad or secure text
// field); the new steps render in the TARGET mode's. Reuses the exact same
// keypad/dots as setup and unlock so the PIN steps stay visually
// indistinguishable. The current credential authorizes the change —
// VaultSelector verifies it the same way unlock() does. A wrong current
// credential is rejected silently and does NOT count toward the auto-wipe
// budget (the user is already authenticated inside the vault); the daily
// change-PIN abuse cap bounds probing instead.
// ---------------------------------------------------------------------------

/** What the credential should be after the rotation. */
enum class CredentialChangeTarget {
    /** Keep the current mode (plain PIN→PIN or passphrase→passphrase change). */
    SAME,
    /** Enable high-risk mode: current PIN authorizes, new credential is a passphrase. */
    TO_PASSPHRASE,
    /** Disable high-risk mode: current passphrase authorizes, new credential is a PIN. */
    TO_PIN,
}

private enum class ChangeStep {
    ENTER_CURRENT,
    CHOOSE_NEW,
    CONFIRM_NEW
}

/** Back-compat entry point for the existing "change_pin" navigation route. */
@Composable
fun ChangePinScreen(
    viewModel: RunViewModel,
    onDone: () -> Unit,
    onCancel: () -> Unit
) = ChangeCredentialScreen(viewModel, CredentialChangeTarget.SAME, onDone, onCancel)

@OptIn(androidx.compose.ui.ExperimentalComposeUiApi::class)
@Composable
fun ChangeCredentialScreen(
    viewModel: RunViewModel,
    target: CredentialChangeTarget,
    onDone: () -> Unit,
    onCancel: () -> Unit,
    // Invoked with the freshly-set plaintext credential on a successful rotation,
    // immediately BEFORE onDone. Lets a caller (the Settings level-change) chain a
    // Lever B recovery-enable, which needs the final credential. Optional — the
    // back-compat "change_pin" route and other callers pass nothing.
    onCredentialSet: ((String) -> Unit)? = null,
    // false hides Cancel entirely. The one caller that
    // passes false is the FORCED protection migration
    // ([ProtectionLevelSettingsScreen] with `forced = true`), where this screen
    // IS the gate a lock-less device is held to: the vault's only remaining
    // factor is the credential, so a one-tap Cancel here left the phone on a
    // ~20-bit PIN with the tier screen degraded to a per-launch nag. Not a trap
    // — that caller installs a BackHandler returning to its chooser, which
    // carries the "set a device passcode" escape, and backgrounding the app
    // finishes the task anyway. Every other caller keeps its Cancel.
    cancellable: Boolean = true,
    // Reports whether a submitted value is
    // currently being EVALUATED — the verify, the KDF, or the atomic
    // changeCredential* write. The caller's own BackHandler must not tear this
    // screen down mid-write: disposal cancels the coroutine below, so a rotation
    // that already landed on disk would never reach [onCredentialSet] / [onDone]
    // and the UI would silently believe nothing changed.
    //
    // It goes back to FALSE once a rotation has SUCCEEDED and [onDone] has
    // returned, even though this screen's input deliberately stays disabled from
    // then on: what follows is the caller's own commit, which the caller tracks
    // itself. Reporting "busy" forever would leave a caller that gates BACK on it
    // with no way off a finished screen.
    onBusyChanged: ((Boolean) -> Unit)? = null,
) {
    val scope = rememberCoroutineScope()

    val currentIsPassphrase = remember { viewModel.vaultSelector.isPassphraseMode() }
    val newIsPassphrase = when (target) {
        CredentialChangeTarget.SAME -> currentIsPassphrase
        CredentialChangeTarget.TO_PASSPHRASE -> true
        CredentialChangeTarget.TO_PIN -> false
    }

    var step by remember { mutableStateOf(ChangeStep.ENTER_CURRENT) }
    // PIN-keypad buffer and passphrase-field buffer for the ACTIVE step; both
    // are cleared on every step change so nothing leaks between steps.
    var enteredPin by remember { mutableStateOf("") }
    var enteredPhrase by remember { mutableStateOf("") }
    var currentCredential by remember { mutableStateOf("") }
    var newCredential by remember { mutableStateOf("") }
    // Non-null while a submitted value is being evaluated (disables input).
    var pendingSubmission by remember { mutableStateOf<String?>(null) }

    val shakeOffset = remember { Animatable(0f) }
    var dotErrorFlash by remember { mutableStateOf(false) }
    // Set when the daily change-PIN cap triggers an emergency wipe. Mirrors
    // PinEntryScreen: render a black screen and stop interacting; the activity
    // finishes on background and the next launch shows first-run setup.
    var isWiped by remember { mutableStateOf(false) }

    // Which input style does the ACTIVE step use?
    val stepIsPassphrase = when (step) {
        ChangeStep.ENTER_CURRENT -> currentIsPassphrase
        else -> newIsPassphrase
    }

    val prompt = when (step) {
        ChangeStep.ENTER_CURRENT -> if (currentIsPassphrase) stringResource(R.string.pin_change_enter_current_passphrase) else stringResource(R.string.pin_change_enter_current_pin)
        ChangeStep.CHOOSE_NEW    -> if (newIsPassphrase) stringResource(R.string.pin_setup_choose_passphrase) else stringResource(R.string.pin_change_choose_new_pin)
        ChangeStep.CONFIRM_NEW   -> if (newIsPassphrase) stringResource(R.string.pin_change_confirm_passphrase) else stringResource(R.string.pin_change_confirm_new_pin)
    }

    suspend fun rejectAndReset(targetStep: ChangeStep) {
        dotErrorFlash = true
        scope.launch { playShakeAnimation(shakeOffset) }
        delay(500)
        enteredPin = ""
        enteredPhrase = ""
        dotErrorFlash = false
        step = targetStep
    }

    // Publish the busy edge BEFORE the effect that acts on it (both are keyed on
    // the same state, and Compose starts them in declaration order), so a caller
    // gating BACK on it can never observe "idle" while the write is already
    // under way.
    LaunchedEffect(pendingSubmission) { onBusyChanged?.invoke(pendingSubmission != null) }

    // PIN steps auto-submit on the 6th digit.
    LaunchedEffect(enteredPin) {
        if (stepIsPassphrase || enteredPin.length < PIN_LENGTH || pendingSubmission != null) return@LaunchedEffect
        delay(150)
        pendingSubmission = enteredPin
    }

    LaunchedEffect(pendingSubmission) {
        val submitted = pendingSubmission ?: return@LaunchedEffect

        when (step) {
            ChangeStep.ENTER_CURRENT -> {
                // Daily change-PIN abuse cap: every flow passes through this
                // current-credential check, so recording here bounds BOTH probe
                // channels (verify-only and change-then-reunlock). The MAX-th
                // attempt in a 24h window triggers an emergency wipe. Recorded
                // BEFORE the check so a wrong guess still counts.
                val wipe = try {
                    withContext(Dispatchers.IO) {
                        viewModel.changePinAttempts.recordAttemptAndCheckLimit()
                    }
                } catch (_: KeyUnavailableException) {
                    // Device key transiently unreadable (locked keybag / transient
                    // Keystore error) — the abuse counter can't be read or written.
                    // DEFER: never wipe on a transient, and don't run the
                    // current-credential check; reset and let the user retry once
                    // the key is readable again.
                    rejectAndReset(ChangeStep.ENTER_CURRENT)
                    pendingSubmission = null
                    return@LaunchedEffect
                }
                if (wipe) {
                    viewModel.performEmergencyWipe()
                    isWiped = true
                    pendingSubmission = null
                    return@LaunchedEffect
                }
                // KDF — keep off the main thread.
                val ok = withContext(Dispatchers.IO) {
                    viewModel.vaultSelector.verifyCredential(submitted)
                }
                if (ok) {
                    currentCredential = submitted
                    enteredPin = ""
                    enteredPhrase = ""
                    step = ChangeStep.CHOOSE_NEW
                } else {
                    rejectAndReset(ChangeStep.ENTER_CURRENT)
                }
                pendingSubmission = null
            }
            ChangeStep.CHOOSE_NEW -> {
                newCredential = submitted
                enteredPin = ""
                enteredPhrase = ""
                step = ChangeStep.CONFIRM_NEW
                pendingSubmission = null
            }
            ChangeStep.CONFIRM_NEW -> {
                if (submitted != newCredential) {
                    rejectAndReset(ChangeStep.CHOOSE_NEW)
                    pendingSubmission = null
                    return@LaunchedEffect
                }
                // changeCredential does KDF + re-wrap + atomic write. The mode
                // flag flips in the SAME atomic batch when the target differs.
                val result = withContext(Dispatchers.IO) {
                    if (target == CredentialChangeTarget.SAME) {
                        viewModel.vaultSelector.changeCredential(currentCredential, newCredential)
                    } else {
                        viewModel.vaultSelector.changeCredentialAndMode(
                            currentCredential, newCredential, newIsPassphrase
                        )
                    }
                }
                when (result) {
                    VaultSelector.ChangePinResult.SUCCESS -> {
                        // Hand the freshly-set credential back BEFORE it is cleared,
                        // so a caller can chain a step that needs the plaintext (the
                        // Settings level-change enables Lever B + mints a recovery code).
                        val cred = newCredential
                        // The rotation completed; reset the entry state.
                        currentCredential = ""
                        newCredential = ""
                        enteredPin = ""
                        enteredPhrase = ""
                        onCredentialSet?.invoke(cred)
                        onDone()
                        // The write is done and onDone has handed off; whatever runs
                        // next belongs to the caller, which tracks it itself. Reported
                        // explicitly because pendingSubmission stays non-null below, so
                        // the effect that publishes this will not fire again.
                        onBusyChanged?.invoke(false)
                        // pendingSubmission stays non-null: the screen can remain
                        // mounted after onDone (the Settings level-change keeps
                        // composing it while chaining the Lever B enable). Re-enabled
                        // input here re-presents "Confirm new PIN" and feeds anything
                        // typed into this stale confirm step against a cleared
                        // newCredential — a second rotation racing the enable.
                        return@LaunchedEffect
                    }
                    VaultSelector.ChangePinResult.WRONG_CURRENT -> {
                        // Shouldn't happen (current was verified) — restart.
                        currentCredential = ""
                        newCredential = ""
                        rejectAndReset(ChangeStep.ENTER_CURRENT)
                    }
                    VaultSelector.ChangePinResult.WEAK_CREDENTIAL -> {
                        // Shouldn't happen — the submit button gates the entropy
                        // floor (the shared API also enforces it as defense-in-depth).
                        // Send the user back to re-choose a stronger passphrase.
                        newCredential = ""
                        rejectAndReset(ChangeStep.CHOOSE_NEW)
                    }
                }
                pendingSubmission = null
            }
        }
    }

    if (isWiped) {
        // This screen-local cover is no longer the SOLE
        // gate — MainActivity now renders a process-lifetime black cover as a
        // sibling of (and ahead of) the whole NavHost the moment
        // RunViewModel.wipedThisSession flips, which drops this composable
        // (and the "change_pin" back-stack entry under it) entirely. Kept as
        // defense-in-depth for the single frame before that recomposition
        // lands, so it still needs its own BackHandler: without one, BACK
        // popped this destination off the NavHost back stack and re-revealed
        // "contacts" underneath — rendered with a null vault, but still a
        // live, interactive screen the user must never see again this
        // process (ProcessWipeCover's invariant).
        androidx.activity.compose.BackHandler(enabled = true) { /* swallow */ }
        Box(Modifier.fillMaxSize().background(RunBlack))
        return
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .semantics { testTagsAsResourceId = BuildConfig.DEBUG }
            .background(RunBlack)
    ) {
        Image(
            painter = painterResource(id = RunestoneArt.dim(viewModel.vaultSelector.displayProtectionLevel())),
            contentDescription = null,
            contentScale = ContentScale.FillWidth,
            modifier = Modifier
                .fillMaxWidth()
                .align(Alignment.TopCenter)
        )

        Column(
            modifier = Modifier
                .fillMaxSize()
                .statusBarsPadding()
                // Edge-to-edge (enableEdgeToEdge in MainActivity): keep the
                // bottom-anchored keypad/buttons above the 3-button navigation
                // bar and the soft keyboard — same idiom as ConversationScreen.
                .navigationBarsPadding()
                .imePadding()
                .padding(horizontal = 32.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            // Cancel — return without changing anything. NOT RENDERED on the
            // forced protection migration: there this screen is the gate
            // itself. Deliberately absent rather than disabled-but-present, so
            // nothing carries the `change_pin_cancel` tag that a test (or a
            // user) could take for a live escape; the row simply collapses.
            Box(modifier = Modifier.fillMaxWidth()) {
                if (cancellable) {
                    Text(
                        text = stringResource(R.string.common_cancel),
                        style = MaterialTheme.typography.bodyLarge,
                        color = RunGrey,
                        modifier = Modifier
                            .align(Alignment.CenterStart)
                            .testTag("change_pin_cancel")
                            .clickable(
                                interactionSource = remember { MutableInteractionSource() },
                                indication = null,
                                enabled = pendingSubmission == null
                            ) { onCancel() }
                    )
                }
            }

            Spacer(Modifier.height(16.dp))

            Text(
                text = prompt,
                style = MaterialTheme.typography.bodyLarge,
                color = RunWhite,
                textAlign = TextAlign.Center,
                modifier = Modifier.testTag("pin_prompt")
            )

            Spacer(Modifier.height(16.dp))

            if (stepIsPassphrase) {
                Box(Modifier.offset { IntOffset(shakeOffset.value.roundToInt(), 0) }) {
                    PassphraseInputField(
                        value = enteredPhrase,
                        onValueChange = { enteredPhrase = it },
                        placeholder = stringResource(R.string.pin_passphrase_placeholder),
                        fieldTag = "passphrase_field",
                        enabled = pendingSubmission == null,
                        isError = dotErrorFlash,
                    )
                }
                // Meter + enforced floor only where a NEW passphrase is chosen.
                // Confirm/verify steps take whatever was typed.
                val chooseStep = step == ChangeStep.CHOOSE_NEW
                if (chooseStep) {
                    Spacer(Modifier.height(12.dp))
                    PassphraseStrengthMeter(enteredPhrase)
                }
                Spacer(Modifier.height(16.dp))
                val floorOk = !chooseStep || CredentialPolicy.meetsFloor(enteredPhrase)
                TextButton(
                    onClick = {
                        if (enteredPhrase.isNotEmpty() && pendingSubmission == null) {
                            pendingSubmission = enteredPhrase
                        }
                    },
                    enabled = enteredPhrase.isNotEmpty() && floorOk && pendingSubmission == null,
                    modifier = Modifier.testTag("credential_continue"),
                ) {
                    Text(
                        text = stringResource(R.string.common_continue),
                        color = if (enteredPhrase.isNotEmpty() && floorOk) RunWhite else RunGrey
                    )
                }
                Spacer(Modifier.weight(1f))
            } else {
                PinDotRow(
                    filledCount = enteredPin.length,
                    errorFlash = dotErrorFlash,
                    shakeOffset = shakeOffset
                )

                Spacer(Modifier.weight(1f))

                PinKeypad(
                    onDigit = { digit ->
                        if (enteredPin.length < PIN_LENGTH) {
                            enteredPin += digit
                        }
                    },
                    onDelete = {
                        if (enteredPin.isNotEmpty()) {
                            enteredPin = enteredPin.dropLast(1)
                        }
                    },
                    enabled = enteredPin.length < PIN_LENGTH && pendingSubmission == null
                )
            }

            Spacer(Modifier.height(24.dp))
        }
    }
}

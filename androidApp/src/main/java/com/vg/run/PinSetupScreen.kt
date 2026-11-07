package com.vg.run

import androidx.compose.animation.core.Animatable
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.text.TextAutoSize
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.viewModelScope
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vg.run.ui.theme.RunBlack
import com.vg.run.ui.theme.RunGrey
import com.vg.run.ui.theme.RunWhite
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private enum class SetupPhase {
    CHOOSE_LEVEL,   // threat-level slider — bare-forced choice
    ENTER_CRED,     // choose PIN / passphrase
    CONFIRM_CRED,   // re-enter it
    SHOW_RECOVERY,  // display the Lever B recovery code (Private)
}

@OptIn(androidx.compose.ui.ExperimentalComposeUiApi::class)
@Composable
fun PinSetupScreen(
    viewModel: RunViewModel,
    onSetupComplete: (openedRealVault: Boolean) -> Unit,
) {
    val scope = rememberCoroutineScope()

    var phase by remember { mutableStateOf(SetupPhase.CHOOSE_LEVEL) }
    var level by remember { mutableStateOf(ProtectionLevel.CASUAL) }
    var recoveryCode by remember { mutableStateOf("") }

    // PIN path state (Casual / Private).
    var enteredPin by remember { mutableStateOf("") }
    var chosenPin by remember { mutableStateOf("") }
    // Passphrase path state (Maximum).
    var enteredPhrase by remember { mutableStateOf("") }
    var chosenPhrase by remember { mutableStateOf("") }

    val shakeOffset = remember { Animatable(0f) }
    var dotErrorFlash by remember { mutableStateOf(false) }
    var processing by remember { mutableStateOf(false) }
    // Set when a chosen PRIVATE tier could not get its Lever B hardware key: the
    // vault is completed at the honest base tier and we tell the user, rather than
    // silently finishing as "Private" over a plain key.
    var leverBFailedNotice by remember { mutableStateOf(false) }
    // Set when provisioning returned false because the device key (Android Keystore
    // super key / iOS keybag) was transiently unavailable — see
    // VaultSelector.lastProvisionWasDeviceKeyUnavailable. Without this the generic
    // "provision failed" branch below shakes the dots and resets to ENTER_CRED with
    // no explanation, and — because the device key stays unavailable until the
    // phone is locked and unlocked again — that repeats forever on every retry.
    var deviceKeyBusyNotice by remember { mutableStateOf(false) }

    // recoveryCode is the SECOND independent full-vault-decrypt
    // path (docs/vault-relay-internals.md) — a 160-bit secret equal in power to the
    // credential — so it gets the same lifetime discipline as the credential fields
    // above: dropped as soon as it's used (SHOW_RECOVERY's onDone, below) and again
    // here on screen teardown, in case the user backs out without ever reaching
    // "Continue". NOTE: Kotlin String is immutable and can't be zeroed in place —
    // clearing the var only drops the reference and shortens the window, it does not
    // remove the value from the heap (same accepted "unwipeable immutable String"
    // residual as ProtectionLevelSettingsScreen's recoveryCode; a CharArray-backed
    // holder would close that gap but is a separate refactor, not undertaken here).
    DisposableEffect(Unit) {
        onDispose { recoveryCode = "" }
    }

    // Provision with the chosen level, open the vault, and (Private)
    // enable Lever B + mint a recovery code. All heavy crypto off the main thread.
    suspend fun provisionAndFinish(credential: String) {
        // SDD-tier-atomicity: a hardened tier (PRIVATE ⇒ Lever B) is honest ONLY once
        // the auth-bound key actually engages. Provision at the HONEST BASE the plain
        // key backs (PRIVATE → CASUAL; MAXIMUM/CASUAL unchanged) and advance to the
        // chosen tier only AFTER the Lever B enable succeeds — so a cancelled biometric
        // or a failed enable can never leave "PRIVATE persisted + plain key". Every
        // failure below settles in the under-claiming (safe) direction.
        val baseLevel = honestPersistedLevel(level, leverBEnabled = false)
        val opened = withContext(Dispatchers.IO) {
            val ok = viewModel.vaultSelector.setRealCredential(credential, level.usesPassphrase, baseLevel)
            if (!ok) null else viewModel.vaultSelector.unlock(credential)
        }
        // The provision guard refused because a vault database already exists —
        // i.e. we should never have been on this screen (a transient
        // "not configured" store read routed a provisioned install to setup).
        // Retrying setup here would loop forever against a guard that is doing its
        // job, so send the user where they actually needed to go: unlock.
        // onSetupComplete(false) is exactly that route (MainActivity → "pin").
        if (opened == null && withContext(Dispatchers.IO) { viewModel.vaultSelector.vaultFileExists() }) {
            LogBuffer.append("W", "Setup",
                "provision refused — vault already present; routing to unlock instead of setup")
            onSetupComplete(false)
            return
        }
        // KeyUnavailableException from provisionCredentialAndVault's FIRST statement
        // (a Keystore super-key eviction is the confirmed real-world trigger, e.g.
        // "keystore2: Required super decryption key is not in memory") — nothing was
        // ever written, so this is still the pure DEFER selectorWriteGuard always
        // was, never a tamper/wipe signal. But it does not self-resolve on a bare
        // retry — the key only reloads after a lock/unlock cycle — so the generic
        // silent shake-and-reset below looped this user forever with no explanation.
        // Distinguish it and say so instead.
        if (opened == null && viewModel.vaultSelector.lastProvisionWasDeviceKeyUnavailable()) {
            LogBuffer.append("W", "Setup", "provision deferred — device key unavailable; telling the user")
            enteredPin = ""; chosenPin = ""; enteredPhrase = ""; chosenPhrase = ""
            deviceKeyBusyNotice = true
            phase = SetupPhase.ENTER_CRED
            return
        }
        if (opened !is VaultSelector.UnlockResult.Opened) {
            // Provision failed (weak passphrase shouldn't reach here — the button
            // gates the floor — or a storage/SQLCipher error): shake + restart.
            dotErrorFlash = true
            scope.launch { playShakeAnimation(shakeOffset) }
            delay(500)
            enteredPin = ""; chosenPin = ""; enteredPhrase = ""; chosenPhrase = ""
            dotErrorFlash = false
            phase = SetupPhase.ENTER_CRED
            return
        }
        // Private: enable the hardware auth-bound key + mint the recovery code, then
        // advance the persisted tier to the chosen (hardened) level — the key now
        // backs it. On any non-Enabled result the vault stays at the honest base tier
        // we provisioned; we surface that instead of silently finishing as "Private".
        if (level.usesLeverB) {
            val result = if (viewModel.vaultSelector.supportsDbKeyAuthBinding()) {
                withContext(Dispatchers.IO) {
                    viewModel.vaultSelector.enableDbKeyAuthBindingWithRecovery(credential)
                }
            } else {
                VaultSelector.RecoveryEnableResult.Unsupported
            }
            if (result is VaultSelector.RecoveryEnableResult.Enabled) {
                // Two-phase: the strict key is only PREPARED (held; DB key still
                // plain). Leave the vault at the honest BASE tier it was provisioned at;
                // promote to PRIVATE atomically only when the user acknowledges the
                // recovery code (finalizeDbKeyAuthBinding, SHOW_RECOVERY onDone). A death
                // with the code on screen leaves a working base PIN vault — never
                // PRIVATE-over-plain, never a lost-code brick.
                recoveryCode = result.recoveryCode
                viewModel.onVaultOpened(opened.vault)
                phase = SetupPhase.SHOW_RECOVERY
                return
            }
            LogBuffer.append("W", "PinSetup", "Lever B enable at onboarding failed — completing at ${baseLevel.storageValue}")
            viewModel.onVaultOpened(opened.vault)
            leverBFailedNotice = true
            return
        }
        viewModel.onVaultOpened(opened.vault)
        onSetupComplete(true)
    }

    // Auto-advance the PIN path on the 6th digit (matches the returning-user UX).
    LaunchedEffect(enteredPin, phase, level) {
        if (level.usesPassphrase || enteredPin.length < PIN_LENGTH || processing) return@LaunchedEffect
        if (phase != SetupPhase.ENTER_CRED && phase != SetupPhase.CONFIRM_CRED) return@LaunchedEffect
        processing = true
        delay(150)
        try {
            when (phase) {
                SetupPhase.ENTER_CRED -> {
                    chosenPin = enteredPin; enteredPin = ""; phase = SetupPhase.CONFIRM_CRED
                }
                SetupPhase.CONFIRM_CRED -> {
                    if (enteredPin == chosenPin) {
                        val pin = chosenPin
                        // Drop the credential buffers the moment they are consumed:
                        // provisionAndFinish can return with this screen still alive
                        // (SHOW_RECOVERY, or the Lever-B-failed notice), and iOS already
                        // clears at the equivalent point. Immutable String — this shortens
                        // the exposure window, it does not zero the heap.
                        try { provisionAndFinish(pin) } finally { chosenPin = ""; enteredPin = "" }
                    } else {
                        dotErrorFlash = true
                        scope.launch { playShakeAnimation(shakeOffset) }
                        delay(500)
                        chosenPin = ""; enteredPin = ""; dotErrorFlash = false
                        phase = SetupPhase.ENTER_CRED
                    }
                }
                else -> {}
            }
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            LogBuffer.append("E", "PinSetup", "provision failed: ${e::class.simpleName}")
            dotErrorFlash = true
            scope.launch { playShakeAnimation(shakeOffset) }
            delay(500)
            chosenPin = ""; enteredPin = ""; dotErrorFlash = false
            phase = SetupPhase.ENTER_CRED
        } finally {
            processing = false
        }
    }

    when (phase) {
        SetupPhase.CHOOSE_LEVEL -> ProtectionLevelScreen(
            viewModel = viewModel,
            currentLevel = null,
            confirmLabel = stringResource(R.string.common_continue),
            onConfirm = { chosen -> level = chosen; phase = SetupPhase.ENTER_CRED },
        )
        SetupPhase.SHOW_RECOVERY -> RecoveryCodeScreen(
            code = recoveryCode,
            onDone = {
                // Code acknowledged: commit the prepared auth-bound key + promote to the
                // chosen (PRIVATE) tier atomically. A failure leaves a working base PIN
                // vault (safe, re-hardenable from Settings) — complete setup either way.
                //
                // Clear AFTER the finalize
                // settles, not before — clearing first was a Compose state write that
                // blanked the code on screen while the async finalize was still in
                // flight. onSetupComplete(true) runs either way (see comment above), so
                // the code is genuinely no longer needed by the time this runs.
                viewModel.viewModelScope.launch {
                    withContext(Dispatchers.IO) { viewModel.vaultSelector.finalizeDbKeyAuthBinding(level) }
                    recoveryCode = ""
                    onSetupComplete(true)
                }
            },
        )
        SetupPhase.ENTER_CRED, SetupPhase.CONFIRM_CRED -> {
            val confirming = phase == SetupPhase.CONFIRM_CRED
            if (level.usesPassphrase) {
                PassphraseSetupBody(
                    confirming = confirming,
                    phrase = if (confirming) enteredPhrase else enteredPhrase,
                    onPhraseChange = { enteredPhrase = it },
                    processing = processing,
                    onSubmit = {
                        scope.launch {
                            if (!confirming) {
                                chosenPhrase = enteredPhrase; enteredPhrase = ""
                                phase = SetupPhase.CONFIRM_CRED
                            } else if (enteredPhrase == chosenPhrase) {
                                processing = true
                                try { provisionAndFinish(chosenPhrase) }
                                // Same as the PIN path above — clear once consumed.
                                finally { processing = false; chosenPhrase = ""; enteredPhrase = "" }
                            } else {
                                enteredPhrase = ""; phase = SetupPhase.ENTER_CRED
                            }
                        }
                    },
                )
            } else {
                PinSetupBody(
                    level = level,
                    confirming = confirming,
                    enteredPin = enteredPin,
                    dotErrorFlash = dotErrorFlash,
                    shakeOffset = shakeOffset,
                    processing = processing,
                    onDigit = { d -> if (enteredPin.length < PIN_LENGTH) enteredPin += d },
                    onDelete = { if (enteredPin.isNotEmpty()) enteredPin = enteredPin.dropLast(1) },
                )
            }
        }
    }

    if (leverBFailedNotice) {
        RuneDialog(
            onDismissRequest = { leverBFailedNotice = false; onSetupComplete(true) },
            title = stringResource(R.string.pin_hardware_lock_not_enabled_title),
            message = stringResource(R.string.pin_hardware_lock_not_enabled_message),
            actions = listOf(
                RuneDialogAction(label = stringResource(R.string.common_continue), onClick = { leverBFailedNotice = false; onSetupComplete(true) }),
            ),
        )
    }

    // Nothing was written (see the deviceKeyBusyNotice comment above) — dismissing
    // just returns the user to ENTER_CRED, already set before this flag went up.
    if (deviceKeyBusyNotice) {
        RuneDialog(
            onDismissRequest = { deviceKeyBusyNotice = false },
            testTag = "device_key_busy_notice",
            title = stringResource(R.string.pin_device_key_busy_title),
            message = stringResource(R.string.pin_device_key_busy_message),
            actions = listOf(
                RuneDialogAction(label = stringResource(R.string.common_ok), onClick = { deviceKeyBusyNotice = false }, testTag = "device_key_busy_dismiss"),
            ),
        )
    }
}

@OptIn(androidx.compose.ui.ExperimentalComposeUiApi::class)
@Composable
private fun PinSetupBody(
    level: ProtectionLevel,
    confirming: Boolean,
    enteredPin: String,
    dotErrorFlash: Boolean,
    shakeOffset: Animatable<Float, *>,
    processing: Boolean,
    onDigit: (Char) -> Unit,
    onDelete: () -> Unit,
) {
    Box(
        Modifier.fillMaxSize().semantics { testTagsAsResourceId = BuildConfig.DEBUG }.background(RunBlack),
    ) {
        Image(
            painter = painterResource(id = RunestoneArt.dim(level)),
            contentDescription = null,
            contentScale = ContentScale.FillWidth,
            modifier = Modifier.fillMaxWidth().align(Alignment.TopCenter),
        )
        Column(
            Modifier.fillMaxSize().statusBarsPadding().navigationBarsPadding().imePadding().padding(horizontal = 32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Spacer(Modifier.height(24.dp))
            Text(
                text = if (confirming) stringResource(R.string.pin_setup_confirm_pin) else stringResource(R.string.pin_setup_choose_pin),
                style = MaterialTheme.typography.bodyLarge,
                color = RunWhite,
                textAlign = TextAlign.Center,
                modifier = Modifier.testTag("pin_prompt"),
            )
            Spacer(Modifier.height(16.dp))
            PinDotRow(filledCount = enteredPin.length, errorFlash = dotErrorFlash, shakeOffset = shakeOffset)
            Spacer(Modifier.weight(1f))
            PinKeypad(
                onDigit = onDigit,
                onDelete = onDelete,
                enabled = enteredPin.length < PIN_LENGTH && !processing,
            )
            Spacer(Modifier.height(24.dp))
        }
    }
}

@OptIn(androidx.compose.ui.ExperimentalComposeUiApi::class)
@Composable
private fun PassphraseSetupBody(
    confirming: Boolean,
    phrase: String,
    onPhraseChange: (String) -> Unit,
    processing: Boolean,
    onSubmit: () -> Unit,
) {
    val meetsFloor = remember(phrase) { CredentialPolicy.meetsFloor(phrase) }
    val canSubmit = if (confirming) phrase.isNotEmpty() else meetsFloor
    Box(
        Modifier.fillMaxSize().semantics { testTagsAsResourceId = BuildConfig.DEBUG }.background(RunBlack),
    ) {
        Column(
            Modifier.fillMaxSize().statusBarsPadding().navigationBarsPadding().imePadding().padding(horizontal = 28.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Spacer(Modifier.height(40.dp))
            Text(
                text = if (confirming) stringResource(R.string.pin_setup_confirm_passphrase) else stringResource(R.string.pin_setup_choose_passphrase),
                style = MaterialTheme.typography.headlineSmall,
                color = RunWhite,
                textAlign = TextAlign.Center,
                modifier = Modifier.testTag("pin_prompt"),
            )
            Spacer(Modifier.height(6.dp))
            Text(
                text = stringResource(R.string.pin_setup_passphrase_hint),
                style = MaterialTheme.typography.bodySmall.copy(fontSize = 12.5.sp),
                color = RunGrey,
                textAlign = TextAlign.Center,
            )
            Spacer(Modifier.height(24.dp))
            PassphraseInputField(
                value = phrase,
                onValueChange = onPhraseChange,
                placeholder = if (confirming) stringResource(R.string.pin_passphrase_placeholder_reenter) else stringResource(R.string.pin_passphrase_placeholder),
                fieldTag = "passphrase_field",
                enabled = !processing,
                onDone = { if (canSubmit && !processing) onSubmit() },
            )
            if (!confirming) {
                Spacer(Modifier.height(12.dp))
                PassphraseStrengthMeter(passphrase = phrase)
            }
            Spacer(Modifier.weight(1f))
            Button(
                onClick = onSubmit,
                enabled = canSubmit && !processing,
                modifier = Modifier.fillMaxWidth().testTag("passphrase_continue"),
                colors = ButtonDefaults.buttonColors(
                    containerColor = RunWhite,
                    contentColor = RunBlack,
                    disabledContainerColor = Color(0xFF20262F),
                    disabledContentColor = RunGrey,
                ),
            ) {
                // ONE line, never a mid-word break.
                // iOS sibling: PinSetupView.swift's submit button.
                Text(
                    if (confirming) stringResource(R.string.pin_confirm_button) else stringResource(R.string.common_continue),
                    maxLines = 1,
                    softWrap = false,
                    autoSize = TextAutoSize.StepBased(minFontSize = 10.sp, maxFontSize = 16.sp, stepSize = 0.5.sp),
                )
            }
            Spacer(Modifier.height(24.dp))
        }
    }
}

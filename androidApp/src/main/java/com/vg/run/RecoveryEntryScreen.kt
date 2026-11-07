package com.vg.run

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
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.TextAutoSize
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTag
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vg.run.ui.theme.RunBlack
import com.vg.run.ui.theme.RunError
import com.vg.run.ui.theme.RunGrey
import com.vg.run.ui.theme.RunSurface
import com.vg.run.ui.theme.RunWhite
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

// ---------------------------------------------------------------------------
// RecoveryEntryScreen — the escape hatch when Lever B locks a user out (a
// biometric re-enroll / device-passcode change invalidated the hardware key).
// Recovery needs BOTH the recovery code AND the PIN/passphrase; on success the
// vault re-provisions at plain (Lever B off) and opens. Reached from a "Can't
// unlock?" affordance on the lock screen when a recovery code exists.
// ---------------------------------------------------------------------------

@OptIn(androidx.compose.ui.ExperimentalComposeUiApi::class)
@Composable
fun RecoveryEntryScreen(
    viewModel: RunViewModel,
    onRecovered: () -> Unit,
    onCancel: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    val passphraseMode = remember { viewModel.vaultSelector.isPassphraseMode() }
    // Error copy resolved HERE, in composition scope, not inside the
    // scope.launch below: `stringResource` is @Composable and a coroutine body
    // is not, and reading resources off `LocalContext.current` instead is not
    // configuration-aware (lint LocalContextGetResourceValueCall) — after a
    // locale change it hands back the value from the stale Configuration.
    // These are constant for a given composition, so hoisting costs nothing and
    // changes no behaviour.
    val attemptRecordFailedError = stringResource(R.string.protection_recovery_attempt_record_failed)
    val credWord = stringResource(
        if (passphraseMode) R.string.protection_credential_type_passphrase else R.string.protection_credential_type_pin,
    )
    val wrongCredentialError = stringResource(R.string.protection_recovery_wrong_credential, credWord)
    val genericRecoveryError = stringResource(R.string.protection_recovery_generic_error)
    var code by remember { mutableStateOf("") }
    var credential by remember { mutableStateOf("") }
    var processing by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var isWiped by remember { mutableStateOf(false) }
    val maxAttempts = remember {
        CredentialPolicy.maxConsecutiveAttempts(viewModel.vaultSelector.protectionLevelForEnforcement())
    }
    // Launch-time interrupted-wipe threshold, exactly as on the lock screen: the
    // recovery code is a SECOND full-vault-decrypt path sharing the same durable
    // counter, so it carries the same composition-time exposure — and Compose
    // restores this route directly after process death, so it is reachable
    // without PinEntryScreen re-composing. Never [maxAttempts]: that budget may
    // have shrunk retroactively below a counter accumulated under the
    // older, larger one. See VaultSelector.interruptedWipeAttemptThreshold.
    val interruptedWipeAttempts = remember {
        viewModel.vaultSelector.maxConsecutiveAttemptsForInterruptedWipe()
    }
    // This screen is a
    // full pre-unlock credential sink — recoverWithCode() evaluates the PIN/passphrase
    // and opens the vault — so its wrong-attempt budget MUST be DURABLE, not
    // per-composition RAM. The old RAM budget reset on Back, and recording the
    // attempt only AFTER recoverWithCode's ~5 s enforced floor let a force-quit inside
    // that window hand out free, uncounted guesses. So it shares the lock
    // screen's durable consecutive counter (PinAttemptsStore) and write the increment
    // SYNCHRONOUSLY *before* the evaluation — the same
    // approach PinEntryScreen already carries. Back re-reads the persisted count; a force-quit
    // leaves it durably incremented; the shared 30/day rolling window is the second
    // cap. Either cap trips the emergency wipe.
    // While the durable count can't be read (transient device-key outage) we DEFER:
    // never write a fresh low count (that would roll back the real value) and never
    // misclassify the outage as tamper.
    var counterDeferred by remember { mutableStateOf(false) }
    var failedAttempts by remember {
        mutableStateOf(
            try {
                val persisted = viewModel.pinAttempts.read()
                // A persisted count already at/over budget means a previous wipe was
                // interrupted (force-quit mid-wipe, or a force-quit after a pre-eval
                // increment maxed it): re-trigger the wipe and never render the form.
                if (persisted >= interruptedWipeAttempts || viewModel.pinAttempts.windowLimitReached()) {
                    viewModel.performEmergencyWipe()
                    isWiped = true
                }
                persisted
            } catch (_: KeyUnavailableException) {
                counterDeferred = true
                0
            } catch (_: PinAttemptsStore.TamperException) {
                viewModel.performEmergencyWipe()
                isWiped = true
                0
            },
        )
    }
    // Same durable-count backoff as the lock screen (re-served on every open; the
    // counter is shared, so recovery entry must not be a backoff-free side door).
    val backoff = rememberUnlockBackoff(if (isWiped) 0L else CredentialPolicy.launchBackoffMs(failedAttempts))

    fun attempt() {
        if (processing || backoff.active || code.isBlank() || credential.isBlank()) return
        processing = true
        error = null
        scope.launch {
            // Persist the incremented consecutive counter
            // SYNCHRONOUSLY *before* recoverWithCode runs — its enforceChangePinDelay
            // floors every attempt at ~5 s, so a force-quit inside that window would
            // otherwise discard the attempt. Writing first makes every guess cost a
            // durable increment regardless of when the app is killed, and navigating
            // Back re-reads it (no reset). Skip the write while deferred (key outage):
            // recoverWithCode needs the same key and fails closed anyway, and a fresh
            // low count would roll back the durable value.
            val attempt = failedAttempts + 1
            failedAttempts = attempt
            if (!counterDeferred) {
                val wrote = withContext(Dispatchers.IO) { viewModel.pinAttempts.tryWrite(attempt) }
                if (!wrote) {
                    counterDeferred = true
                    failedAttempts = attempt - 1
                    error = attemptRecordFailedError
                    processing = false
                    return@launch
                }
            }
            val outcome = withContext(Dispatchers.IO) {
                viewModel.vaultSelector.recoverWithCode(code.trim(), credential)
            }
            when (outcome) {
                is VaultSelector.UnlockResult.Opened -> {
                    viewModel.pinAttempts.reset()
                    viewModel.onVaultOpened(outcome.vault)
                    onRecovered()
                }
                VaultSelector.UnlockResult.Denied -> {
                    // Consecutive counter already incremented pre-eval. Also record in
                    // the shared 24h rolling window (fail-open; never throws) — the cap
                    // no successful open can reset.
                    val windowExhausted = withContext(Dispatchers.IO) {
                        try {
                            viewModel.pinAttempts.recordWrongAttemptInWindowAndCheckLimit()
                        } catch (_: KeyUnavailableException) {
                            false   // transient key outage: can't record → never wipe on a glitch
                        }
                    }
                    if (attempt >= maxAttempts || windowExhausted) {
                        viewModel.performEmergencyWipe()
                        isWiped = true
                        return@launch
                    }
                    error = wrongCredentialError
                    val waitMs = CredentialPolicy.unlockBackoffMs(attempt)
                    backoff.start(waitMs)
                    delay(waitMs)
                    processing = false
                }
                VaultSelector.UnlockResult.Error,
                    // Recovery IS the escape hatch from a dead hardware key, so
                    // there is nowhere further to route the user — surface it as the
                    // same retryable error rather than pointing back at this screen.
                VaultSelector.UnlockResult.RecoveryRequired -> {
                    // Correct-credential path could not complete (no recovery code on
                    // file, or a transient device-key outage) — NOT a wrong guess, so
                    // roll the pre-eval increment back off the wipe budget (mirrors
                    // PinEntryScreen's Error/RecoveryRequired handling; tryWrite so a
                    // key outage here can't crash the coroutine).
                    if (!counterDeferred) {
                        withContext(Dispatchers.IO) { viewModel.pinAttempts.tryWrite(attempt - 1) }
                    }
                    failedAttempts = attempt - 1
                    error = genericRecoveryError
                    processing = false
                }
            }
        }
    }

    if (isWiped) {
        // This screen-local cover is no longer the SOLE
        // gate — MainActivity now renders a process-lifetime black cover as a
        // sibling of (and ahead of) the whole NavHost the moment
        // RunViewModel.wipedThisSession flips, which drops this composable
        // (and the "recover" back-stack entry under it) entirely. Kept as
        // defense-in-depth for the single frame before that recomposition
        // lands, so it still needs its own BackHandler: without one, BACK
        // popped this destination off the NavHost back stack and re-revealed
        // the "pin" keypad underneath — a live, interactive screen the user
        // must never see again this process (ProcessWipeCover's invariant).
        androidx.activity.compose.BackHandler(enabled = true) { /* swallow */ }
        Box(Modifier.fillMaxSize().background(RunBlack))
        return
    }

    Box(
        Modifier.fillMaxSize().semantics { testTagsAsResourceId = BuildConfig.DEBUG }.background(RunBlack),
    ) {
        Column(
            Modifier.fillMaxSize().statusBarsPadding().navigationBarsPadding().imePadding().padding(horizontal = 28.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Spacer(Modifier.height(40.dp))
            Text(
                stringResource(R.string.protection_recovery_entry_title),
                style = MaterialTheme.typography.headlineSmall,
                color = RunWhite,
                textAlign = TextAlign.Center,
                modifier = Modifier.testTag("recovery_entry_title"),
            )
            Spacer(Modifier.height(8.dp))
            Text(
                stringResource(
                    R.string.protection_recovery_entry_subtitle,
                    stringResource(if (passphraseMode) R.string.protection_credential_type_passphrase else R.string.protection_credential_type_pin),
                ),
                style = MaterialTheme.typography.bodySmall.copy(fontSize = 12.5.sp),
                color = RunGrey,
                textAlign = TextAlign.Center,
            )
            Spacer(Modifier.height(24.dp))
            NoPersonalizedLearning {
                OutlinedTextField(
                    value = code,
                    onValueChange = { code = it },
                    placeholder = { Text(stringResource(R.string.protection_recovery_code_placeholder), color = RunGrey) },
                    singleLine = false,
                    isError = error != null,
                    textStyle = MaterialTheme.typography.bodyLarge.copy(fontFamily = FontFamily.Monospace),
                    keyboardOptions = KeyboardOptions(
                        autoCorrectEnabled = false,
                        capitalization = KeyboardCapitalization.Characters,
                        // Password type puts the IME in a private,
                        // no-personalized-learning mode so the keyboard can't learn or
                        // cloud-sync the recovery code (the one secret this field handles).
                        // No VisualTransformation is set, so the code stays VISIBLE for
                        // typing off paper.
                        keyboardType = KeyboardType.Password,
                    ),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedTextColor = RunWhite,
                        unfocusedTextColor = RunWhite,
                        focusedContainerColor = RunSurface.copy(alpha = 0.4f),
                        unfocusedContainerColor = RunSurface.copy(alpha = 0.4f),
                        cursorColor = RunWhite,
                        focusedBorderColor = RunGrey,
                        unfocusedBorderColor = RunGrey.copy(alpha = 0.5f),
                        errorBorderColor = RunError,
                    ),
                    modifier = Modifier.fillMaxWidth().semantics { testTag = "recovery_code_input" },
                )
            }
            Spacer(Modifier.height(14.dp))
            PassphraseInputField(
                value = credential,
                onValueChange = { credential = it },
                placeholder = if (passphraseMode) stringResource(R.string.pin_passphrase_placeholder) else stringResource(R.string.protection_credential_type_pin),
                fieldTag = "recovery_credential_input",
                enabled = !processing && !backoff.active,
                isError = error != null,
                onDone = { attempt() },
            )
            if (error != null) {
                Spacer(Modifier.height(10.dp))
                Text(error!!, color = RunError, fontSize = 12.sp, textAlign = TextAlign.Center)
            }
            if (backoff.active) {
                Spacer(Modifier.height(10.dp))
                Text(
                    stringResource(R.string.pin_backoff_hint, backoff.secondsLeft),
                    color = RunGrey,
                    fontSize = 12.sp,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.testTag("pin_backoff_hint"),
                )
            }
            Spacer(Modifier.weight(1f))
            Button(
                onClick = { attempt() },
                enabled = !processing && !backoff.active && code.isNotBlank() && credential.isNotBlank(),
                modifier = Modifier.fillMaxWidth().testTag("recovery_submit_button"),
                colors = ButtonDefaults.buttonColors(
                    containerColor = RunWhite,
                    contentColor = RunBlack,
                    disabledContainerColor = Color(0xFF20262F),
                    disabledContentColor = RunGrey,
                ),
            ) {
                // ONE line, never a mid-word break.
                // iOS sibling: ProtectionLevelView.swift's recovery_submit_button.
                Text(
                    if (processing) stringResource(R.string.protection_recovery_button_recovering) else stringResource(R.string.protection_recovery_button_recover),
                    maxLines = 1,
                    softWrap = false,
                    autoSize = TextAutoSize.StepBased(minFontSize = 10.sp, maxFontSize = 16.sp, stepSize = 0.5.sp),
                )
            }
            TextButton(onClick = onCancel, modifier = Modifier.testTag("recovery_cancel_button")) {
                Text(stringResource(R.string.common_back), color = RunGrey)
            }
            Spacer(Modifier.height(24.dp))
        }
    }
}

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
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
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
import androidx.compose.ui.platform.LocalContext
import com.vg.run.ui.theme.RunBlack
import com.vg.run.ui.theme.RuneDanger
import com.vg.run.ui.theme.RunGrey
import com.vg.run.ui.theme.RunWhite
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlin.math.roundToInt

// Maximum wrong attempts before emergency wipe is now PER-LEVEL (threat-level
// slider) — computed inside the composable from the chosen ProtectionLevel, with
// the commonMain CredentialPolicy default for a legacy vault that has no level.

@OptIn(androidx.compose.ui.ExperimentalComposeUiApi::class)
@Composable
fun PinEntryScreen(
    viewModel: RunViewModel,
    onUnlocked: () -> Unit,
    onUseRecoveryCode: () -> Unit = {},
    onVaultErased: () -> Unit = {}
) {
    val scope = rememberCoroutineScope()
    val context = LocalContext.current

    // Dead-end escape hatch: a vault FILE with no credential stored for it. The
    // provision guard routes this user here instead of letting setup destroy the
    // file, so this screen owes them a way out — otherwise the app is a PIN
    // prompt that rejects every PIN forever.
    //
    // Gated on the device being UNLOCKED as well as the confirmed-absent
    // credential (VaultSelector.orphanedVaultFile fails toward "not orphaned" on
    // a transient read): between them, a healthy vault can never be offered an
    // erase button. Computed once per screen entry — this must not appear
    // mid-session because a background read blinked.
    val orphanedVault = remember {
        !InactivityWipe.isDeviceCurrentlyLocked(context) &&
            viewModel.vaultSelector.orphanedVaultFile()
    }
    var confirmErase by remember { mutableStateOf(false) }

    // High-risk mode (hardening plan Lever A): a passphrase credential renders
    // a secure text field instead of the 6-digit keypad. The evaluation,
    // attempt counting, backoff and wipe logic below are IDENTICAL for both —
    // the credential is just a string to VaultSelector.
    val passphraseMode = remember { viewModel.vaultSelector.isPassphraseMode() }
    // Per-level wrong-tries wipe threshold for a NEW attempt (threat-level
    // slider); a legacy vault with no chosen level keeps the current
    // CredentialPolicy default, an UNREADABLE stored level (transient device-key
    // outage) gets the most lenient tier's budget, and an unauthenticated or
    // damaged level fails secure to MAXIMUM's. Shared decision with iOS
    // (IosAppController.maxConsecutiveAttempts).
    val maxAttempts = remember {
        CredentialPolicy.maxConsecutiveAttempts(viewModel.vaultSelector.protectionLevelForEnforcement())
    }
    // Threshold for the LAUNCH-TIME interrupted-wipe re-trigger below — NOT for a
    // new attempt. [maxAttempts] is allowed to shrink retroactively (an
    // unauthenticated tier or a damaged blob falls to MAXIMUM's 5), and firing the
    // composition-time wipe on a counter accumulated under the OLD, larger budget
    // destroys a vault whose owner entered nothing wrong — a legacy-cleartext
    // CASUAL vault stranded at 5–9 failures would go up on first launch after the
    // upgrade. This threshold falls back to the most lenient tier's budget
    // wherever the read can't prove the budget didn't shrink, so it can only ever
    // DELAY the re-trigger. Shared decision with iOS (PinEntryView.readAttempts).
    val interruptedWipeAttempts = remember {
        viewModel.vaultSelector.maxConsecutiveAttemptsForInterruptedWipe()
    }
    // Lever B recovery escape hatch — only offered when a recovery code exists.
    val hasRecovery = remember { viewModel.vaultSelector.hasRecoveryCode() }

    var enteredPin by remember { mutableStateOf("") }
    var passphrase by remember { mutableStateOf("") }
    // The credential currently being evaluated. Non-null disables input; the
    // PIN path sets it automatically on the 6th digit, the passphrase path on
    // the Unlock button / IME Done.
    var pendingCredential by remember { mutableStateOf<String?>(null) }
    var isWiped by remember { mutableStateOf(false) }
    // True if the durable wrong-PIN counter could not be read this session
    // because the device key was transiently unavailable. While deferred we must
    // NOT write a fresh (low) count — that would clobber/rollback the real
    // durable count and reset the brute-force budget.
    var counterDeferred by remember { mutableStateOf(false) }
    // Latched once an unlock returns RecoveryRequired — the credential is
    // correct but the Lever-B hardware key is permanently invalidated, so only the
    // recovery code can open this vault. Drives the explanatory notice below.
    var permanentKeyLoss by remember { mutableStateOf(false) }
    var failedAttempts by remember {
        mutableIntStateOf(
            try {
                val persisted = viewModel.pinAttempts.read()
                // A persisted count that already meets the budget
                // means the previous wipe was interrupted (e.g. force-quit
                // after the pre-evaluation write but before the wipe
                // finished). Re-trigger the wipe immediately and never
                // render the keypad — this is what closes the
                // force-quit-mid-wipe brute-force loop. Compared against
                // [interruptedWipeAttempts], never [maxAttempts]: the counter
                // was accumulated under whatever budget was in force AT THE
                // TIME, so a budget that shrank since must not condemn
                // it retroactively. See the property there.
                // ALSO re-check the 24h wrong-PIN WINDOW cap at
                // launch (was only checked on a live Denied), so a force-quit
                // that stranded an already-maxed window (using the
                // 1-correct/4-wrong evasion that keeps the consecutive counter
                // low) wipes on next launch instead of granting a free guess.
                // That cap never shrank, so it is compared as-is.
                // Short-circuits: the window read is skipped when already maxed.
                if (persisted >= interruptedWipeAttempts || viewModel.pinAttempts.windowLimitReached()) {
                    viewModel.performEmergencyWipe()
                    isWiped = true
                }
                persisted
            } catch (_: KeyUnavailableException) {
                // Device key transiently unavailable (device locked / Keystore
                // glitch) — the persisted counter may be intact, so DEFER rather
                // than misclassify it as tampering and wipe the vault (parity
                // with iOS PinEntryView's locked-key guard). 0
                // for this session; the durable count is re-read once the key is
                // available again. counterDeferred suppresses the pre-eval write
                // so we don't clobber the durable count with this 0-based value.
                counterDeferred = true
                0
            } catch (_: PinAttemptsStore.TamperException) {
                // Tampered counter — treat as adversarial, wipe everything.
                viewModel.performEmergencyWipe()
                isWiped = true
                0
            }
        )
    }
    // Wrong-attempt backoff gate: seeded from the DURABLE count so a force-quit +
    // relaunch re-serves the wait (the in-session delay below alone would reset).
    // Monotonic clock, nothing persisted. iOS sibling: PinEntryView.backoffUntil.
    val backoff = rememberUnlockBackoff(if (isWiped) 0L else CredentialPolicy.launchBackoffMs(failedAttempts))
    val shakeOffset = remember { Animatable(0f) }
    var dotErrorFlash by remember { mutableStateOf(false) }

    if (isWiped) {
        Box(Modifier.fillMaxSize().background(RunBlack))
        return
    }

    // Confirmation for the orphaned-vault erase. Deliberately explicit about
    // permanence: this is the one place the app deletes a vault on a plain tap,
    // so the consequence is named in the dialog rather than implied by a label.
    // Destructive action LAST, per the ordering rule in RuneDialog.kt.
    if (confirmErase) {
        RuneDialog(
            onDismissRequest = { confirmErase = false },
            testTag = "erase_orphaned_vault_alert",
            title = stringResource(R.string.pin_erase_vault_title),
            message = stringResource(R.string.pin_erase_vault_message),
            actions = listOf(
                runeSecondary(stringResource(R.string.common_cancel), testTag = "erase_orphaned_vault_cancel") {
                    confirmErase = false
                },
                runeDestructive(stringResource(R.string.pin_erase_vault_confirm), testTag = "erase_orphaned_vault_confirm") {
                    confirmErase = false
                    LogBuffer.append("W", "Vault", "user erased an orphaned vault from the unlock screen")
                    // deniable = false: this user chose to START OVER and must land
                    // on setup (note the absence of `isWiped = true` here, unlike
                    // every other wipe call site in this file). Arming the black
                    // cover would black-screen them on the next Activity recreate.
                    // iOS sibling: AppState.eraseOrphanedVault() → emergencyWipe(deniable: false).
                    viewModel.performEmergencyWipe(deniable = false)
                    onVaultErased()
                },
            ),
        )
    }

    // PIN mode auto-submits on the 6th digit (after a beat so the dot paints).
    LaunchedEffect(enteredPin) {
        if (passphraseMode || enteredPin.length < PIN_LENGTH || pendingCredential != null || backoff.active) return@LaunchedEffect
        delay(150)
        pendingCredential = enteredPin
    }

    LaunchedEffect(pendingCredential) {
        val credential = pendingCredential ?: return@LaunchedEffect

        // Persist the incremented counter SYNCHRONOUSLY *before*
        // evaluating the credential. unlock() is slow KDF work off-thread
        // (CR-1); if the write happened after, an attacker could force-quit
        // during evaluation and the attempt would never be recorded —
        // unlimited brute force. Writing first (to the counter-only prefs
        // file, so it cannot resurrect credential hashes) makes every attempt
        // cost a durable increment regardless of when the app is killed.
        val attempt = failedAttempts + 1
        failedAttempts = attempt
        // Skip the durable write while the counter is deferred (transient key
        // unavailability): writing a fresh low count would roll back the real
        // durable count. Unlock needs the same key, so it fails closed this
        // session anyway; the count is re-read once the key returns.
        if (!counterDeferred) {
            try {
                withContext(Dispatchers.IO) { viewModel.pinAttempts.write(attempt) }
            } catch (_: KeyUnavailableException) {
                // pinAttempts.write is @Throws. If the Keystore
                // became unavailable AFTER the launch-time read (counterDeferred was
                // false here), this threw inside the LaunchedEffect and CRASHED the lock
                // screen. Fail closed instead: mark the counter deferred, roll back the
                // in-memory increment, and abort this attempt — unlock needs the same
                // key and would fail anyway. Mirrors the tryWrite guard on the Error path.
                counterDeferred = true
                failedAttempts = attempt - 1
                enteredPin = ""
                passphrase = ""
                pendingCredential = null
                return@LaunchedEffect
            }
        }

        // unlock() does KDF + AEAD + SQLCipher open — keep it off the
        // main thread so the keypad/backoff UI stays responsive (CR-1).
        val result = withContext(Dispatchers.IO) {
            viewModel.vaultSelector.unlock(credential)
        }
        when (result) {
            is VaultSelector.UnlockResult.Opened -> {
                // Correct credential within budget (incl. the MAX-th attempt) —
                // clear the counter and open.
                viewModel.pinAttempts.reset()
                viewModel.onVaultOpened(result.vault)
                onUnlocked()
            }
            is VaultSelector.UnlockResult.Denied -> {
                // A successful unlock resets the 5-consecutive
                // budget above, so an attacker could reset-and-retry the PIN
                // without bound. Enforce a rolling-24h cap on total wrong
                // entries that no unlock can reset. Either cap trips the wipe.
                val windowExhausted = withContext(Dispatchers.IO) {
                    viewModel.pinAttempts.recordWrongAttemptInWindowAndCheckLimit()
                }
                if (attempt >= maxAttempts || windowExhausted) {
                    // Budget exhausted. The counter is already durably at
                    // >= MAX, so even if this wipe is interrupted the
                    // launch-time check above re-triggers it.
                    viewModel.performEmergencyWipe()
                    isWiped = true
                    return@LaunchedEffect
                }
                dotErrorFlash = true
                scope.launch { playShakeAnimation(shakeOffset) }

                // B6a: exponential backoff (1s, 2s, 4s, 8s) — single-sourced from
                // commonMain so both platforms slow brute force identically.
                val waitMs = CredentialPolicy.unlockBackoffMs(failedAttempts)
                backoff.start(waitMs)
                delay(waitMs)
                enteredPin = ""
                passphrase = ""
                dotErrorFlash = false
                pendingCredential = null
            }
            is VaultSelector.UnlockResult.Error -> {
                // Transient failure to OPEN the matched vault (corrupt/locked
                // SQLCipher file or sidecar) — the credential was CORRECT, so this
                // is NOT a wrong-PIN attempt. Never wipe and never count it toward
                // either budget: roll back the durable increment written above
                // (so transient I/O can't drift the counter toward the launch-time
                // wipe) and let the user retry.
                // Best-effort: Error can now be caused by device-key unavailability
                // even when counterDeferred was false at load, so this
                // rollback write may be unable to encrypt — tryWrite skips it rather
                // than raising KeyUnavailableException in the coroutine. A stale
                // increment is re-evaluated on next launch by readAttempts().
                if (!counterDeferred) withContext(Dispatchers.IO) { viewModel.pinAttempts.tryWrite(attempt - 1) }
                failedAttempts = attempt - 1
                dotErrorFlash = true
                scope.launch { playShakeAnimation(shakeOffset) }
                delay(500)
                enteredPin = ""
                passphrase = ""
                dotErrorFlash = false
                pendingCredential = null
            }
            is VaultSelector.UnlockResult.RecoveryRequired -> {
                // Correct credential, permanently destroyed auth-bound key. Roll
                // the counter back exactly like Error (the PIN was RIGHT — this must
                // never consume the wipe budget) but latch a message instead of
                // inviting another identical attempt that cannot possibly succeed.
                if (!counterDeferred) withContext(Dispatchers.IO) { viewModel.pinAttempts.tryWrite(attempt - 1) }
                failedAttempts = attempt - 1
                permanentKeyLoss = true
                enteredPin = ""
                passphrase = ""
                pendingCredential = null
            }
        }
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .semantics { testTagsAsResourceId = BuildConfig.DEBUG }
            .background(RunBlack)
    ) {
        // Dim runestone background matching the protection level — the level
        // marker is device-key readable pre-unlock (same read the enforcement
        // sites use), and the credential UI reveals the tier anyway.
        Image(
            painter = painterResource(id = RunestoneArt.dim(viewModel.vaultSelector.displayProtectionLevel())),
            contentDescription = null,
            contentScale = ContentScale.FillWidth,
            modifier = Modifier
                .fillMaxWidth()
                .align(Alignment.TopCenter)
        )

        // Credential UI overlaid on top.
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
            Spacer(Modifier.height(32.dp))

            if (passphraseMode) {
                Text(
                    text = stringResource(R.string.pin_prompt_passphrase),
                    style = MaterialTheme.typography.bodyLarge,
                    color = RunWhite,
                    modifier = Modifier.testTag("pin_prompt")
                )
                Spacer(Modifier.height(16.dp))
                Box(Modifier.offset { IntOffset(shakeOffset.value.roundToInt(), 0) }) {
                    PassphraseInputField(
                        value = passphrase,
                        onValueChange = { passphrase = it },
                        placeholder = stringResource(R.string.pin_passphrase_placeholder),
                        fieldTag = "passphrase_field",
                        enabled = pendingCredential == null && !backoff.active,
                        isError = dotErrorFlash,
                        onDone = {
                            if (passphrase.isNotEmpty() && pendingCredential == null && !backoff.active) {
                                pendingCredential = passphrase
                            }
                        },
                    )
                }
                Spacer(Modifier.height(16.dp))
                androidx.compose.material3.TextButton(
                    onClick = {
                        if (passphrase.isNotEmpty() && pendingCredential == null && !backoff.active) {
                            pendingCredential = passphrase
                        }
                    },
                    enabled = passphrase.isNotEmpty() && pendingCredential == null && !backoff.active,
                    modifier = Modifier.testTag("unlock_button"),
                ) {
                    Text(stringResource(R.string.pin_unlock_button), color = if (pendingCredential == null && !backoff.active) RunWhite else RunGrey)
                }
                Spacer(Modifier.weight(1f))
            } else {
                // Dots above the stone.
                PinDotRow(
                    filledCount = enteredPin.length,
                    errorFlash = dotErrorFlash,
                    shakeOffset = shakeOffset
                )

                // Stone fills the middle.
                Spacer(Modifier.weight(1f))

                // Keypad at the bottom.
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
                    enabled = enteredPin.length < PIN_LENGTH && pendingCredential == null && !backoff.active
                )
            }

            if (backoff.active) {
                Text(
                    stringResource(R.string.pin_backoff_hint, backoff.secondsLeft),
                    color = RunGrey,
                    style = MaterialTheme.typography.bodySmall,
                    textAlign = TextAlign.Center,
                    modifier = Modifier
                        .padding(horizontal = 8.dp, vertical = 8.dp)
                        .testTag("pin_backoff_hint"),
                )
            }

            // The credential was right but the Lever-B hardware key is gone for
            // good (lock screen removed / biometrics re-enrolled). Say so plainly —
            // the old behaviour surfaced this as a generic transient error, so the
            // user retried the correct PIN forever with no hint that the recovery
            // code is the ONLY way back in.
            if (permanentKeyLoss) {
                Text(
                    if (hasRecovery) {
                        stringResource(R.string.pin_permanent_key_loss_lockscreen_has_recovery)
                    } else {
                        stringResource(R.string.pin_permanent_key_loss_lockscreen_no_recovery)
                    },
                    color = RunGrey,
                    style = MaterialTheme.typography.bodySmall,
                    textAlign = TextAlign.Center,
                    modifier = Modifier
                        .padding(horizontal = 8.dp)
                        .testTag("permanent_key_loss_notice"),
                )
                Spacer(Modifier.height(8.dp))
            }

            if (hasRecovery) {
                androidx.compose.material3.TextButton(
                    onClick = onUseRecoveryCode,
                    modifier = Modifier.testTag("use_recovery_code_button"),
                ) {
                    Text(
                        if (permanentKeyLoss) stringResource(R.string.pin_use_recovery_code)
                        else stringResource(R.string.pin_use_recovery_code_prompt),
                        color = RunGrey,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }

            // The dead end described at [orphanedVault]. Explain the state before
            // offering the only action that resolves it, and never dress the
            // erase up as a fix — it destroys the vault, which is exactly why the
            // app refused to do it silently.
            if (orphanedVault) {
                Text(
                    stringResource(R.string.pin_orphaned_vault_notice),
                    color = RunGrey,
                    style = MaterialTheme.typography.bodySmall,
                    textAlign = TextAlign.Center,
                    modifier = Modifier
                        .padding(horizontal = 8.dp)
                        .testTag("orphaned_vault_notice"),
                )
                Spacer(Modifier.height(8.dp))
                androidx.compose.material3.TextButton(
                    onClick = { confirmErase = true },
                    modifier = Modifier.testTag("erase_orphaned_vault_button"),
                ) {
                    Text(
                        stringResource(R.string.pin_erase_start_over),
                        color = RuneDanger,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }

            Spacer(Modifier.height(24.dp))
        }
    }
}

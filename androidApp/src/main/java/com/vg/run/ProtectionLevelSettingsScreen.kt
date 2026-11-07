package com.vg.run

import android.content.Intent
import android.provider.Settings
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.TextAutoSize
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewModelScope
import com.vg.run.ui.theme.RunBlack
import com.vg.run.ui.theme.RunError
import com.vg.run.ui.theme.RunGrey
import com.vg.run.ui.theme.RunSurfaceAlt
import com.vg.run.ui.theme.RunWhite
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

// ---------------------------------------------------------------------------
// ProtectionLevelSettingsScreen — change the protection level after onboarding.
// This is now the SINGLE control for security: it drives the credential type
// (PIN ↔ passphrase) and the hardware auth-bound key (Lever B) inline, mirroring
// the onboarding flow (PinSetupScreen.provisionAndFinish).
//
// Applying a level:
//   1. Persist the TIMER tier immediately (setProtectionLevel — safe, the user is
//      already unlocked). A DOWNGRADE first shows a "this reduces your protection"
//      confirm.
//   2. Drop Lever B first when the target doesn't use it (Maximum).
//   3. Rotate the credential inline via ChangeCredentialScreen when the level
//      implies a different credential type — or, for Casual→Private, re-enter the
//      SAME PIN to obtain the plaintext the recovery-enable needs.
//   4. Enable Lever B + display the recovery code (RecoveryCodeScreen) last, since
//      the enable binds to the FINAL credential.
//
// Fail-safe (mirrors onboarding): a Lever B enable that fails leaves the vault
// working at plain — the level's timers still apply and nothing is bricked.
// ---------------------------------------------------------------------------

private enum class LevelChangePhase {
    PICK,           // the protection-level chooser
    CHANGE_CRED,    // rotate credential / re-enter PIN (ChangeCredentialScreen)
    ENABLING,       // Lever B enable in flight (KDF + system screen-lock prompt)
    SHOW_RECOVERY,  // display the Lever B recovery code (Private enable)
}

// Display tier name (Decent / Secure / Maximum) — single-sourced with iOS in
// shared ProtectionLevelContent so the rename stays consistent across every
// surface (chooser, downgrade dialog, migration).
private fun displayName(level: ProtectionLevel): String =
    ProtectionLevelContent.displayName(level)

/**
 * The protection tier that HONESTLY reflects the key actually backing the vault,
 * given the [chosen] tier and whether its Lever B auth-binding actually engaged.
 *
 * A hardened tier (PRIVATE ⇒ Lever B / hardware auth-bound DB key) is honest ONLY
 * when Lever B is really on; otherwise the DB key is plain-wrapped and the honest
 * tier is CASUAL. MAXIMUM does not use Lever B (its strength is the passphrase), so
 * it is always honest regardless of [leverBEnabled]. Persisting THIS — rather than
 * the chosen tier — keeps "persisted tier ≤ what the key backs" (SDD-tier-atomicity):
 * a cancelled biometric or a failed enable settles in the under-claiming (safe)
 * direction, never the dangerous PRIVATE-labelled-but-plain-keyed over-claim. Shared
 * by the onboarding (PinSetupScreen) and settings (this screen) flows.
 */
internal fun honestPersistedLevel(chosen: ProtectionLevel, leverBEnabled: Boolean): ProtectionLevel =
    if (chosen.usesLeverB && !leverBEnabled) ProtectionLevel.CASUAL else chosen

@Composable
fun ProtectionLevelSettingsScreen(
    viewModel: RunViewModel,
    onBack: () -> Unit,
    /** Entered from the forced route (this device has no lock screen, so the
     *  vault must move up to MAXIMUM — DeviceLockPolicy). The chooser offers no
     *  Back and neither does the credential step
     *  it drives ([ChangeCredentialScreen]'s `cancellable`): leaving would drop
     *  the user into the app at a tier this device cannot honour, and this is a
     *  GATE, not a nag. [onBack] is therefore a REQUEST to leave, not a
     *  guarantee — the caller (MainActivity's "protection_forced" route)
     *  re-evaluates [DeviceLockPolicy.needsForcedMigration] and stays put while
     *  the floor still applies, mirroring iOS. The way out is finishing the
     *  migration or setting a device passcode, which retires the forcing on the
     *  next unlock — named in the chooser's own stop-reason copy and in the
     *  explainer's "Open security settings" button. */
    forced: Boolean = false,
) {
    val vs = viewModel.vaultSelector
    val current = remember { vs.currentProtectionLevel() }
    // The vault's Lever B key can be on the legacy
    // device-credential-openable scheme that unlock-time reconcile couldn't
    // upgrade — VaultSelector.needsLeverBReharden() is the signal, but it had
    // no UI consumer on either platform. Reached (and therefore evaluated)
    // only once the vault is unlocked, since this screen requires that; also
    // gated on Lever B actually being on, since the notice's remedy (disable
    // → enable) is meaningless otherwise. Computed once per screen entry —
    // a fresh remember on re-entry after the reharden cycle re-evaluates it.
    val showLeverBRehardenNotice = remember { vs.isDbKeyAuthBound() && vs.needsLeverBReharden() }

    var phase by remember { mutableStateOf(LevelChangePhase.PICK) }
    var pendingDowngrade by remember { mutableStateOf<ProtectionLevel?>(null) }
    var persistFailed by remember { mutableStateOf(false) }
    // Set when a requested Lever B enable did not engage — we committed the honest
    // (lower) tier and must tell the user instead of silently finishing "Private".
    var leverBFailed by remember { mutableStateOf(false) }

    // Set while an inline credential / Lever B flow runs for the chosen level.
    var credentialTarget by remember { mutableStateOf<CredentialChangeTarget?>(null) }
    var enableLeverB by remember { mutableStateOf(false) }
    var stashedCredential by remember { mutableStateOf("") }
    var recoveryCode by remember { mutableStateOf("") }
    /** Tier chosen but NOT yet persisted — committed only once its credential /
     *  Lever-B chain succeeds. Cancelling anywhere leaves it unwritten. */
    var pendingLevel by remember { mutableStateOf<ProtectionLevel?>(null) }
    var dropLeverBOnCommit by remember { mutableStateOf(false) }
    /** True while [ChangeCredentialScreen] is EVALUATING a submitted value (the
     *  verify, the KDF, the atomic changeCredential* write), and true from a
     *  successful rotation onward — that screen deliberately never re-arms
     *  input after SUCCESS. */
    var credentialBusy by remember { mutableStateOf(false) }
    /** True while the post-rotation commit coroutine (drop / Lever-B enable /
     *  tier persist) is in flight. It runs on the ViewModel scope, so it
     *  OUTLIVES this composition — which is why BACK must not be allowed to
     *  reset the phase underneath it, and why the coroutine re-reads this flag
     *  before it navigates. */
    var commitInFlight by remember { mutableStateOf(false) }

    // recoveryCode is the SECOND independent full-vault-decrypt
    // path (docs/vault-relay-internals.md) — a 160-bit secret equal in power to the
    // credential — so it gets the same lifetime discipline as stashedCredential above:
    // dropped as soon as it's used (SHOW_RECOVERY's onDone, below) and again here on
    // screen teardown, in case the user backs out without ever reaching "Continue".
    // NOTE: Kotlin String is immutable and can't be zeroed in place — clearing the var
    // only drops the reference and shortens the window, it does not remove the value
    // from the heap (same "unwipeable immutable String" limitation as
    // stashedCredential; a CharArray-backed holder would close that gap but is a
    // separate refactor, not undertaken here).
    DisposableEffect(Unit) {
        onDispose { recoveryCode = "" }
    }

    // Apply the chosen level: persist timers, drop Lever B when unused, then run the
    // credential change and/or Lever B enable inline. Credential change happens
    // BEFORE Lever B enable (the enable binds to the final credential). All heavy
    // calls run off the main thread.
    fun apply(level: ProtectionLevel) {
        // The level persist used
        // to run FIRST, so picking Maximum and then CANCELLING the passphrase screen
        // left the vault persisted as Maximum — maximum art, maximum timers,
        // isMaximumLevel()==true — while still protected by the OLD 6-digit PIN. The
        // UI then OVERSTATES protection, the dangerous direction. So a level whose
        // credential/Lever-B chain has yet to run is persisted only once that chain
        // SUCCEEDS (see commitLevel below); cancel now leaves the old level intact.
        //
        // The same holds for the no-chain case: when nothing follows,
        // the persist is the only mutation and a failure aborts with nothing written.
        //
        // The UPGRADE half asks for PROOF, not for the
        // fail-OPEN widget reader. isPassphraseMode() answers `true` for a DAMAGED
        // vlt_m (the keypad would hard-lock a passphrase user out), so ≥28
        // bytes of base64 garbage planted in that slot used to make "upgrade to
        // Maximum" a pure metadata write: an AUTHENTICATED vlt_lvl=maximum over the
        // unchanged 6-digit PIN, which permanently satisfies the lock-less floor.
        // Only credentialKindProven() == true may skip the rotation; unproven
        // routes through it, which also heals vlt_m. The DOWNGRADE half below keeps
        // the fail-open reader deliberately: there "cannot tell" means "rotate to a
        // PIN anyway", i.e. it already fails toward doing the work, and refusing it
        // would leave a passphrase under a CASUAL label instead.
        //
        // The `level.usesPassphrase &&` prefix is not redundant: it SHORT-CIRCUITS
        // the accessor, so exactly ONE `vlt_m` AEAD decrypt happens per apply —
        // this one for a passphrase target, isPassphraseMode()'s for a PIN target.
        // Without it a PIN target paid two decrypts of the same slot and discarded
        // the first. [ProtectionUpgradePlan.needsCredentialChange] answers `false`
        // for a non-passphrase target anyway, so the guard changes no decision.
        val needPassphrase = level.usesPassphrase &&
            ProtectionUpgradePlan.needsCredentialChange(level, vs.credentialKindProven())
        val needPin = !level.usesPassphrase && vs.isPassphraseMode()
        val doEnableLeverB = level.usesLeverB && !vs.isDbKeyAuthBound()
        val dropLeverB = !level.usesLeverB && vs.isDbKeyAuthBound()

        // Casual→Private keeps the PIN, but we still re-enter it (target SAME) to
        // obtain the plaintext the recovery-enable needs.
        val target = when {
            needPassphrase -> CredentialChangeTarget.TO_PASSPHRASE
            needPin -> CredentialChangeTarget.TO_PIN
            doEnableLeverB -> CredentialChangeTarget.SAME
            else -> null
        }
        enableLeverB = doEnableLeverB
        credentialTarget = target
        pendingLevel = level
        dropLeverBOnCommit = dropLeverB

        if (target != null) {
            // Chain first; the level is committed only when it completes.
            // Lever B is dropped as part of the commit, not before it, so a
            // cancel can't leave the tier weakened either.
            phase = LevelChangePhase.CHANGE_CRED
        } else {
            // Nothing follows — this persist IS the whole apply. Run it on the
            // ViewModel scope, NOT the composition scope: onBack() disposes this
            // screen, and a composition-scoped launch would be cancelled mid-way,
            // able to tear a half-done drop-then-persist.
            viewModel.viewModelScope.launch {
                if (dropLeverB) withContext(Dispatchers.IO) { vs.setDbKeyAuthBinding(false) }
                if (!withContext(Dispatchers.IO) { vs.setProtectionLevel(level) }) {
                    LogBuffer.append("W", "ProtectionLevel", "level persist failed (transient) — apply aborted")
                    persistFailed = true
                    return@launch
                }
                onBack()
            }
        }
    }

    /** Persists [level] AFTER its credential/Lever-B chain settled. Callers pass the
     *  HONEST tier ([honestPersistedLevel]) for what the key now backs, so a failed
     *  Lever B enable commits the lower tier, never PRIVATE-over-a-plain-key. A
     *  failure here leaves the OLD level with the NEW (stronger) credential —
     *  under-claiming protection, the safe direction. Returns false if the persist
     *  failed. */
    fun commitLevel(level: ProtectionLevel): Boolean {
        if (!vs.setProtectionLevel(level)) {
            LogBuffer.append("W", "ProtectionLevel", "level persist failed after credential chain — level unchanged")
            return false
        }
        pendingLevel = null
        return true
    }

    /** Drop an in-flight credential / Lever-B chain and return to the chooser,
     *  writing nothing (an unfinished chain never persists its tier).
     *
     *  On the FORCED route this is the ONLY in-screen step back. The
     *  credential step there shows no Cancel, but system BACK must not strand the
     *  user mid-flow either — the chooser it returns to is where the "Open
     *  security settings" escape lives, and returning to it escapes nothing (the
     *  gate is still up). Unforced, Cancel closes the screen as before.
     *
     *  Callers must first prove nothing is IN FLIGHT ([credentialBusy] /
     *  [commitInFlight]) — this resets composition state a running write does
     *  not read, but it also DISOWNS a commit coroutine (clearing
     *  [commitInFlight]) so that coroutine will not navigate on top of the
     *  chooser it just returned to. It is also used by the two failure branches
     *  that return to PICK, so "chain over, nothing persisted" is expressed in
     *  exactly one place. */
    fun abandonCredentialChange() {
        stashedCredential = ""
        credentialTarget = null
        pendingLevel = null
        enableLeverB = false
        dropLeverBOnCommit = false
        credentialBusy = false
        commitInFlight = false
        phase = LevelChangePhase.PICK
    }

    when (phase) {
        LevelChangePhase.PICK -> {
            // Forced-only: the explainer sits ABOVE the chooser, not inside the
            // shared ProtectionLevelScreen — onboarding's own bare-forced pick
            // (PinSetupScreen) and the post-unlock migration screen
            // (ProtectionLevelMigrationScreen) reuse that same composable and must
            // not gain this card too; only this Settings/forced route does. A
            // Column + weight(1f) Box (not a bare Box wrap — see the NavHost
            // Box-wrap lesson) keeps ProtectionLevelScreen's own
            // fillMaxSize()/verticalScroll a bounded height to measure into.
            Column(modifier = Modifier.fillMaxSize()) {
                if (forced) {
                    ForcedProtectionExplainer()
                }
                if (showLeverBRehardenNotice) {
                    LeverBRehardenNotice()
                }
                Box(modifier = Modifier.weight(1f)) {
                    ProtectionLevelScreen(
                        viewModel = viewModel,
                        currentLevel = current,
                        confirmLabel = stringResource(R.string.protection_apply_button),
                        onConfirm = { newLevel ->
                            when {
                                newLevel == current -> onBack()
                                newLevel.ordinal < current.ordinal -> pendingDowngrade = newLevel  // weaker → confirm
                                else -> apply(newLevel)
                            }
                        },
                        onBack = if (forced) null else onBack,
                    )
                }
            }

            pendingDowngrade?.let { level ->
                RuneDialog(
                    onDismissRequest = { pendingDowngrade = null },
                    title = stringResource(R.string.protection_downgrade_title),
                    message = stringResource(R.string.protection_downgrade_message_android, displayName(level)),
                    // Destructive LAST (safety rule, RuneDialog.kt): the reflex
                    // leftmost tap must land on "Keep current", not the downgrade.
                    actions = listOf(
                        runeSecondary(stringResource(R.string.protection_downgrade_keep)) { pendingDowngrade = null },
                        RuneDialogAction(
                            label = stringResource(R.string.protection_downgrade_reduce),
                            color = com.vg.run.ui.theme.RuneDanger,
                            onClick = { pendingDowngrade = null; apply(level) },
                        ),
                    ),
                )
            }

            if (persistFailed) {
                RuneDialog(
                    onDismissRequest = { persistFailed = false },
                    title = stringResource(R.string.protection_persist_failed_title),
                    message = stringResource(R.string.protection_persist_failed_message),
                    actions = listOf(RuneDialogAction(label = stringResource(R.string.common_ok), onClick = { persistFailed = false })),
                )
            }
        }

        LevelChangePhase.CHANGE_CRED -> {
            // On the FORCED route this step carries the
            // gate, so it must not offer the one-tap escape it used to — Cancel
            // is not rendered (`cancellable = false`) and system BACK returns to
            // the chooser rather than to the app. Unforced, both behave exactly
            // as before.
            //
            // …but BACK must never land MID-WRITE. Disposing
            // this subtree cancels the credential screen's own coroutine, and the
            // atomic changeCredential* write it is inside does not observe
            // cancellation: the rotation LANDS on disk while onDone never fires,
            // so the app believes nothing changed and the stashed plaintext is
            // dropped. Likewise the commit coroutine below outlives this
            // composition. So while either is in flight the press is SWALLOWED
            // (handler stays enabled — letting it fall through to the route-level
            // handler would finish the Activity mid-write, which is worse), and
            // that swallow applies UNFORCED too, where BACK would otherwise pop
            // the whole destination out from under the same write.
            //
            // Both flags clear once the work settles, which matters on the forced
            // route: if [onBack] there declines to navigate (the floor still
            // applies) the phase stays CHANGE_CRED over a finished, input-disabled
            // credential screen, and BACK returning to the chooser is the only way
            // off it. A permanently-"busy" gate would make that a dead end.
            val credentialChangeInFlight = credentialBusy || commitInFlight
            androidx.activity.compose.BackHandler(enabled = forced || credentialChangeInFlight) {
                if (credentialChangeInFlight) {
                    LogBuffer.append("W", "ProtectionLevel",
                        "back ignored — a credential change is in flight")
                } else {
                    abandonCredentialChange()
                }
            }
            ChangeCredentialScreen(
                viewModel = viewModel,
                target = credentialTarget!!,
                cancellable = !forced,
                onBusyChanged = { busy -> credentialBusy = busy },
                onCredentialSet = { cred -> stashedCredential = cred },
                onDone = {
                    // The credential rotation finished. Everything that follows — dropping
                    // or enabling the hardware auth-bound key (Lever B) and committing the
                    // tier — MUST outlive this screen. The old code committed the tier on a
                    // composition-scoped coroutine and then called onBack() synchronously,
                    // whose disposal CANCELLED the still-running drop+commit (Private→Maximum
                    // could persist neither the drop nor the tier), and it committed the tier
                    // UNCONDITIONALLY of the Lever B enable (a cancelled biometric left
                    // PRIVATE persisted over a plain key). Fix: ONE sequential job on the
                    // ViewModel scope; commit the HONEST tier for what the key actually backs
                    // ([honestPersistedLevel]); navigate only once it settles.
                    //
                    // Hand the stash to the enable and drop our
                    // copy immediately — the rotated plaintext must not sit in composition
                    // state until disposal.
                    val credential = stashedCredential
                    stashedCredential = ""
                    val doDrop = dropLeverBOnCommit
                    val doEnable = enableLeverB
                    val chosen = pendingLevel ?: current
                    // Leave CHANGE_CRED before any async key work so the finished credential
                    // screen can't linger interactively while the system prompt is up.
                    if (doDrop || doEnable) phase = LevelChangePhase.ENABLING
                    // A plain MAXIMUM pick has no drop and no enable, so the phase
                    // STAYS on CHANGE_CRED for the whole commit below. That is the
                    // second BACK window: without this flag a press would reset the
                    // phase to PICK and the coroutine would then navigate away from
                    // the chooser it had just returned to. Armed before the launch
                    // (main thread, so it is visible to the BackHandler on the very
                    // next frame) and cleared by the coroutine or by an abandon.
                    commitInFlight = true
                    viewModel.viewModelScope.launch {
                        if (doDrop) withContext(Dispatchers.IO) { vs.setDbKeyAuthBinding(false) }
                        val enableResult = if (doEnable) {
                            withContext(Dispatchers.IO) { vs.enableDbKeyAuthBindingWithRecovery(credential) }
                        } else null
                        // For a hardened target we only advance the tier if Lever B is on:
                        // true means "the key backs it" (freshly enabled, or already bound
                        // when no enable was requested).
                        // Two-phase: a successful enable is only PREPARED here
                        // (the ab: key is HELD, the DB key still plain) — the strict key
                        // isn't live until finalizeDbKeyAuthBinding at the code ack. So
                        // commit the HONEST BASE now (leverBActive=false → Casual over the
                        // plain key); PRIVATE is promoted atomically at finalize
                        // (SHOW_RECOVERY onDone), never persisted over a plain key.
                        val leverBActive = if (doEnable) false else true
                        val commitOk = withContext(Dispatchers.IO) {
                            commitLevel(honestPersistedLevel(chosen, leverBActive))
                        }
                        // Did this coroutine still own the screen when it finished?
                        // An abandon clears the flag, and then the ONLY thing that
                        // must not happen is navigating on top of the chooser the
                        // user is already on. The recovery-code branch stays
                        // unconditional on purpose: that code is a second full-vault
                        // decrypt path and MUST be shown once it exists.
                        val stillOurs = commitInFlight
                        commitInFlight = false
                        when {
                            enableResult is VaultSelector.RecoveryEnableResult.Enabled -> {
                                recoveryCode = enableResult.recoveryCode
                                phase = LevelChangePhase.SHOW_RECOVERY
                            }
                            doEnable -> {
                                // Requested Lever B but it never engaged; we committed the
                                // honest (lower) tier. Surface it rather than silently
                                // finishing at "Private".
                                LogBuffer.append("W", "ProtectionLevel", "Lever B enable at settings failed — committed honest tier")
                                leverBFailed = true
                            }
                            !commitOk -> {
                                persistFailed = true
                                // The chain is over and nothing was persisted — drop
                                // its whole state, not just the phase.
                                abandonCredentialChange()
                            }
                            stillOurs -> onBack()
                        }
                    }
                },
                // Unreachable while `forced`: no Cancel is rendered there. Kept as the
                // plain unforced path rather than a `forced` special case, because the
                // forced route's own [onBack] already re-evaluates the floor and
                // refuses to leave while it applies — so even a reachable Cancel could
                // not escape the gate.
                onCancel = { stashedCredential = ""; onBack() },
            )
        }

        LevelChangePhase.ENABLING -> {
            LeverBEnablingScreen()
            if (leverBFailed) {
                RuneDialog(
                    onDismissRequest = { leverBFailed = false; onBack() },
                    title = stringResource(R.string.pin_hardware_lock_not_enabled_title),
                    message = stringResource(R.string.protection_lever_b_failed_message),
                    actions = listOf(RuneDialogAction(label = stringResource(R.string.common_ok), onClick = { leverBFailed = false; onBack() })),
                )
            }
        }

        LevelChangePhase.SHOW_RECOVERY -> RecoveryCodeScreen(
            code = recoveryCode,
            onDone = {
                // Code acknowledged: commit the prepared auth-bound key + promote to
                // PRIVATE atomically (finalizeDbKeyAuthBinding). Until now the vault was
                // a working base PIN vault, so a death on this screen never bricked and
                // never over-claimed. A finalize failure keeps that safe base vault and
                // surfaces the retry dialog on the chooser.
                //
                // Only clear on the SUCCESS
                // path, once finalize truly settles — clearing unconditionally before
                // starting the async work both blanked the code on screen while
                // finalize was still running and, on the failure branch, discarded a
                // code the user might still need before they ever left this screen. A
                // failed finalize leaves recoveryCode in composition state (still the
                // safe base PIN vault) until the user backs out and the DisposableEffect
                // teardown above clears it.
                viewModel.viewModelScope.launch {
                    if (withContext(Dispatchers.IO) { vs.finalizeDbKeyAuthBinding(ProtectionLevel.PRIVATE) }) {
                        recoveryCode = ""
                        onBack()
                    } else {
                        LogBuffer.append("W", "ProtectionLevel", "Lever B finalize failed — vault stays at base tier")
                        persistFailed = true
                        // Same "chain over, nothing more persisted" reset as the
                        // commit-failure branch. Deliberately does NOT touch
                        // recoveryCode: a failed finalize may have left a code
                        // the user still needs, and only the DisposableEffect
                        // teardown clears it.
                        abandonCredentialChange()
                    }
                }
            },
        )
    }
}

// Compact, non-blocking notice that the vault's Lever B
// key is on the legacy device-credential-openable scheme and needs a disable→
// enable cycle to re-harden. It only points at the existing chooser below —
// no automatic re-mint runs from here.
@Composable
private fun LeverBRehardenNotice() {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 6.dp)
            .background(RunSurfaceAlt, RoundedCornerShape(10.dp))
            .padding(horizontal = 14.dp, vertical = 10.dp)
            .testTag("lever_b_reharden_notice"),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = stringResource(R.string.protection_lever_b_reharden_notice),
            style = MaterialTheme.typography.bodyLarge.copy(fontSize = 13.sp),
            color = RunError,
        )
    }
}

// Shown while the Lever B enable runs after the credential rotation (a full
// credential re-verification plus keystore work, then the system screen-lock
// prompt from the auth-bound round-trip verify). Replaces the finished
// credential screen so nothing interactive lingers, and tells the user why
// the system prompt is about to appear.
@Composable
private fun LeverBEnablingScreen() {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(RunBlack)
            .padding(horizontal = 32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Text(
            text = stringResource(R.string.protection_enabling_title),
            style = MaterialTheme.typography.bodyLarge,
            color = RunWhite,
            textAlign = TextAlign.Center,
            modifier = Modifier.testTag("level_enabling"),
        )
        Spacer(Modifier.height(12.dp))
        Text(
            text = stringResource(R.string.protection_enabling_body_android),
            style = MaterialTheme.typography.bodyLarge.copy(fontSize = 13.sp),
            color = RunGrey,
            textAlign = TextAlign.Center,
        )
    }
}

// ---------------------------------------------------------------------------
// Proactive "why + what now" explanation shown ABOVE the chooser ONLY on the
// forced route (this device has no lock screen — DeviceLockPolicy). Before
// this, the only place that named the lock-screen escape hatch was the LAST
// sentence of the acknowledgment dialog you only reach by tapping Apply
// (ProtectionLevelContent.forcedNoticeBody) — App Store / Play users churned
// on a screen that reappeared every launch with no visible way out. This
// surfaces both paths up front; the dialog (and the rule it enforces) is
// unchanged.
//
// Unlike iOS, Android has a public, Play-safe deep link straight to the lock
// screen settings page (Settings.ACTION_SECURITY_SETTINGS) — no private API
// risk — so the primary path here is a real button, not just instructions.
// ---------------------------------------------------------------------------
@Composable
private fun ForcedProtectionExplainer() {
    val context = LocalContext.current
    Column(
        modifier = Modifier
            .fillMaxWidth()
            // DropdownMenu/Dialog-style Popups don't inherit the NavHost root's
            // testTagsAsResourceId (separate window composition) — this isn't one,
            // but every screen composable in this app sets it locally too rather
            // than relying on inheritance, so this follows that same convention.
            .semantics { testTagsAsResourceId = BuildConfig.DEBUG }
            .background(RunBlack)
            .padding(horizontal = 24.dp)
            .padding(top = 20.dp, bottom = 4.dp),
    ) {
        // Reuses the single-sourced shared title verbatim (same wording as the
        // acknowledgment dialog below) rather than inventing new copy that could
        // drift from it.
        Text(
            text = ProtectionLevelContent.forcedNoticeTitle,
            style = MaterialTheme.typography.titleMedium,
            color = RunWhite,
        )
        Spacer(Modifier.height(6.dp))
        Text(
            text = stringResource(R.string.protection_forced_explainer_intro),
            style = MaterialTheme.typography.bodySmall.copy(fontSize = 13.sp),
            color = RunGrey,
        )
        Spacer(Modifier.height(14.dp))

        // Primary path — visually first and heaviest (same light-card treatment as
        // the main confirm button below). Once this phone has a lock screen,
        // DeviceLockPolicy stops forcing Maximum and every level is selectable
        // again the moment you come back to this screen.
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .background(RunWhite, RoundedCornerShape(12.dp))
                .padding(14.dp),
        ) {
            Text(
                text = stringResource(R.string.protection_forced_explainer_cta_title_android),
                style = MaterialTheme.typography.bodyLarge.copy(fontSize = 15.sp, fontWeight = FontWeight.SemiBold),
                color = RunBlack,
            )
            Spacer(Modifier.height(4.dp))
            Text(
                text = stringResource(R.string.protection_forced_explainer_cta_body_android),
                style = MaterialTheme.typography.bodySmall.copy(fontSize = 12.5.sp),
                color = Color(0xFF2A2A2A),
            )
            Spacer(Modifier.height(10.dp))
            Button(
                onClick = {
                    val intents = listOf(
                        Intent(Settings.ACTION_SECURITY_SETTINGS),
                        Intent(Settings.ACTION_SETTINGS),
                    )
                    for (intent in intents) {
                        try {
                            context.startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                            break
                        } catch (_: Exception) { /* try the next fallback */ }
                    }
                },
                modifier = Modifier.fillMaxWidth().testTag("forced_set_passcode_button"),
                colors = ButtonDefaults.buttonColors(containerColor = RunBlack, contentColor = RunWhite),
            ) {
                // ONE line, never a mid-word break.
                Text(
                    stringResource(R.string.protection_forced_open_settings_button),
                    maxLines = 1,
                    softWrap = false,
                    autoSize = TextAutoSize.StepBased(minFontSize = 10.sp, maxFontSize = 16.sp, stepSize = 0.5.sp),
                )
            }
        }
        Spacer(Modifier.height(12.dp))
        Text(
            text = stringResource(R.string.protection_forced_explainer_outro_android),
            style = MaterialTheme.typography.bodySmall.copy(fontSize = 13.sp),
            color = RunGrey,
        )
    }
}

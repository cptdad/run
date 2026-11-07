package com.vg.run

import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import com.vg.run.ui.theme.RunWhite

// ---------------------------------------------------------------------------
// ProtectionLevelMigrationScreen — shown ONCE, right after a legacy vault is
// unlocked, when no threat level has ever been configured (vaults provisioned
// before the threat-level slider shipped: protectionLevelOrNull() == null).
//
// First-run picks the level BEFORE the PIN (PinSetupScreen.CHOOSE_LEVEL); an
// EXISTING vault has no level yet, so we ask right after unlock instead. A
// choice is required (no cancel) — same bare-forced stance as onboarding — and
// the pick is ALWAYS persisted (even Casual), so the prompt never reappears.
//
// The TIMER tier applies immediately (setProtectionLevel — safe, already
// unlocked). If the chosen level also implies a credential-type (passphrase)
// change that isn't in effect yet, that lever is NOT re-implemented here — a
// one-time note points to Settings › Protection level (which drives the
// credential change inline), mirroring ProtectionLevelSettingsScreen. Two
// tiers have an unmet precondition at migration time and must never be
// persisted raw over it: PRIVATE's hardware key (Lever B) can silently fail
// (cancelled biometric, Keystore outage) with no user-visible step in
// between, and MAXIMUM's passphrase (Lever A) is simply never rotated here —
// the credential is still whatever PIN the legacy vault already had
// (the migration screen was
// persisting MAXIMUM over a live PIN). So — same as onboarding/Settings
// (SDD-tier-atomicity, [honestPersistedLevel]) — we never persist PRIVATE
// unless Lever B is ALREADY bound, and never persist MAXIMUM unless the
// credential is ALREADY a passphrase; see [migrationPersistedLevel]. This
// also keeps the "finish in Settings" note a REAL remediation instead of a
// dead end: ProtectionLevelSettingsScreen no-ops when the new pick equals the
// CURRENT persisted level, so persisting the raw (over-claimed) PRIVATE or
// MAXIMUM here would make that follow-up trip do nothing.
// ---------------------------------------------------------------------------

/**
 * The tier the one-time migration chooser should PERSIST for [chosen], given
 * whether the DB key is already Lever-B auth-bound ([leverBEnabled]) and
 * whether the credential is already a passphrase ([passphraseAlreadySet]).
 * Migration never runs the interactive Lever B enable OR an interactive
 * credential rotation (no credential re-entry happens on this screen — see
 * the file header), so PRIVATE and MAXIMUM each have exactly one unmet
 * precondition here: PRIVATE needs Lever B already bound, MAXIMUM needs the
 * credential already rotated to a passphrase. Either pick can only be honest
 * when its precondition already holds; otherwise this falls back to the same
 * honest base onboarding/Settings persist — CASUAL — so the vault never
 * claims a hardware-bound key, or a passphrase, it doesn't actually have.
 * (MAXIMUM was persisting raw
 * over a live 6-digit PIN — a stronger-tier over-claim than PRIVATE's own
 * round-2 fix, [honestPersistedLevel], ever had to handle.) CASUAL always
 * persists as chosen — it has no precondition to fail.
 *
 * [passphraseAlreadySet] must be PROOF
 * ([VaultSelector.credentialKindProven] == true, via
 * [ProtectionUpgradePlan.needsCredentialChange]), never
 * `VaultSelector.isPassphraseMode()` — that reader fails OPEN to `true` on a
 * damaged/planted `vlt_m`, which turned this screen back into the MAXIMUM-over-PIN over-claim.
 */
internal fun migrationPersistedLevel(
    chosen: ProtectionLevel,
    leverBEnabled: Boolean,
    passphraseAlreadySet: Boolean,
): ProtectionLevel =
    if (chosen.usesPassphrase && !passphraseAlreadySet) {
        ProtectionLevel.CASUAL
    } else {
        honestPersistedLevel(chosen, leverBEnabled)
    }

// Display tier name (Decent / Secure / Maximum) — single-sourced with iOS in
// shared ProtectionLevelContent so the rename stays consistent across surfaces.
private fun displayLevelName(level: ProtectionLevel): String =
    ProtectionLevelContent.displayName(level)

@Composable
fun ProtectionLevelMigrationScreen(
    viewModel: RunViewModel,
    onDone: () -> Unit,
) {
    val vs = viewModel.vaultSelector
    // Chosen tier the user tapped + the tier actually persisted for it — they
    // diverge when PRIVATE was chosen but Lever B isn't on yet, or MAXIMUM was
    // chosen but the credential isn't a passphrase yet (see
    // [migrationPersistedLevel]).
    var finishNoteFor by remember { mutableStateOf<Pair<ProtectionLevel, ProtectionLevel>?>(null) }
    var persistFailed by remember { mutableStateOf(false) }

    ProtectionLevelScreen(
        viewModel = viewModel,
        currentLevel = null,               // bare-forced — a first, explicit choice
        confirmLabel = stringResource(R.string.common_continue),
        onConfirm = { level ->
            // The THIRD consumer of the fail-OPEN mode
            // reader, reached when vlt_lvl is damaged too (floor check → null →
            // this chooser). `isPassphraseMode()` answers `true` for a damaged
            // vlt_m, so a planted pair let this screen persist an AUTHENTICATED
            // `maximum` over a live 6-digit PIN — re-opening exactly the
            // MAXIMUM-over-PIN over-claim the honesty rule below closes, and retiring
            // DeviceLockPolicy's forced migration permanently. Require PROOF: only
            // an AEAD-authenticated `phrase` counts as "passphrase already set"
            // ([ProtectionUpgradePlan]); anything unproven persists the honest
            // CASUAL and points at Settings, whose credential chain heals vlt_m.
            val mustRotateCredential =
                ProtectionUpgradePlan.needsCredentialChange(level, vs.credentialKindProven())
            val persistedLevel = migrationPersistedLevel(
                level,
                leverBEnabled = vs.isDbKeyAuthBound(),
                // Only consulted for a passphrase tier, where it is the exact
                // negation of the plan's answer.
                passphraseAlreadySet = !mustRotateCredential,
            )
            // The persist must be checked — a transient
            // device-key outage writes nothing, and dismissing the one-time
            // chooser anyway would leave the old-tier timers silently in force.
            // Abort and keep the chooser up so the user retries (it would also
            // re-appear next unlock, but never silently proceed).
            if (!vs.setProtectionLevel(persistedLevel)) {
                LogBuffer.append("W", "ProtectionLevel", "migration level persist failed (transient) — staying on chooser")
                persistFailed = true
            } else {
                // Same rule as the iOS chooser's finish-note (ProtectionUpgradePlan).
                val needsLever = ProtectionUpgradePlan.needsFinishInSettings(level, persistedLevel, mustRotateCredential)
                if (needsLever) finishNoteFor = level to persistedLevel else onDone()
            }
        },
        onBack = null,                     // a choice is required to continue
    )

    if (persistFailed) {
        RuneDialog(
            onDismissRequest = { persistFailed = false },
            title = stringResource(R.string.protection_persist_failed_title),
            message = stringResource(R.string.protection_persist_failed_message),
            actions = listOf(RuneDialogAction(label = stringResource(R.string.common_ok), onClick = { persistFailed = false })),
        )
    }

    finishNoteFor?.let { (chosen, persisted) ->
        val chosenName = displayLevelName(chosen)
        // Honest copy: when the hardware key didn't engage, or the passphrase
        // was never rotated, say what's ACTUALLY set now (the lower, persisted
        // tier) — never imply the chosen tier's timings/protection already
        // apply when they don't. The two divergence causes need different
        // copy: MAXIMUM's is "we never rotate the credential here" (this
        // screen deliberately defers it, not a failed attempt), while
        // PRIVATE's is "the hardware key didn't engage" (an attempted-and-
        // failed Lever B enable).
        val message = if (persisted != chosen) {
            val persistedName = displayLevelName(persisted)
            if (chosen.usesPassphrase) {
                stringResource(R.string.protection_migration_finish_maximum, chosenName, persistedName)
            } else {
                stringResource(R.string.protection_migration_finish_private, chosenName, persistedName)
            }
        } else {
            stringResource(R.string.protection_migration_finish_same, chosenName)
        }
        RuneDialog(
            onDismissRequest = { finishNoteFor = null; onDone() },
            title = stringResource(R.string.protection_migration_almost_there_title),
            message = message,
            actions = listOf(
                RuneDialogAction(label = stringResource(R.string.common_got_it), onClick = { finishNoteFor = null; onDone() }),
            ),
        )
    }
}

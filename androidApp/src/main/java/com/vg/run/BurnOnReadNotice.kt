package com.vg.run

import androidx.compose.runtime.Composable
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource

// One-time "burn on read" onboarding, shared by the 1:1 and group conversation
// screens so the copy and the durable latch live in ONE place. Shown on the
// very first conversation ever opened per vault (whichever type opens first),
// then never again: BurnOnReadNotice — the CONCEPT (messages show once, never
// stored). iOS mirrors it in ConversationView.swift.

/** Encrypted per-vault meta key latching that the notice has been shown. */
private const val BURN_NOTICE_META_KEY = "onboard_burn_notice_v1"

/**
 * Returns true exactly once per vault — the first call finds the meta absent,
 * writes it, and returns true; every later call (this vault) returns false.
 * Durable across relaunch/lock, cleared with the vault on wipe. Best-effort: a
 * meta read/write failure returns false (never crash a conversation for
 * onboarding; the notice simply re-offers on the next open). Mirrors the
 * add-contacts prompt latch (904f478).
 */
fun consumeBurnNoticeOnce(vault: VaultDatabase): Boolean =
    try {
        if (vault.getMeta(BURN_NOTICE_META_KEY) == null) {
            vault.putMeta(BURN_NOTICE_META_KEY, "1")
            true
        } else {
            false
        }
    } catch (_: Exception) {
        false
    }

/**
 * Step 1: the burn-on-read CONCEPT. Simple, pedagogical, no jargon — messages
 * show once and are never stored.
 */
@OptIn(ExperimentalComposeUiApi::class)
@Composable
fun BurnOnReadNotice(onClose: () -> Unit) {
    RuneDialog(
        onDismissRequest = onClose,
        title = stringResource(R.string.burn_notice_title),
        message = stringResource(R.string.burn_notice_message),
        actions = listOf(
            RuneDialogAction(label = stringResource(R.string.common_got_it), testTag = "burn_notice_ok", onClick = onClose),
        ),
        testTag = "burn_notice",
    )
}

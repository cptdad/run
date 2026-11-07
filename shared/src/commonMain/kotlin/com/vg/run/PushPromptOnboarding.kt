package com.vg.run

// ---------------------------------------------------------------------------
// First-open push-notification prompt — "Do you want to enable push
// notifications?" shown exactly once per vault. Since 2026-09-11 (user
// directive) it is NOT raised at unlock but the first time the RELAY answers
// in a session ([pushPromptDueOnRelayContact]): enabling push needs a live
// relay transport (Android's toggle-ON path reverts with "check your
// connection" without one), so asking while "Connecting…" is still on screen
// invited the user into a failure. The latch below is consumed only at that
// moment, so a session that never reaches the relay keeps the one-shot for
// the next one.
// Same encrypted-per-vault-meta latch shape as consumeBurnNoticeOnce
// (androidApp/BurnOnReadNotice.kt): consume-on-first-read, so it can never
// loop, and a wipe/new vault naturally re-arms it (fresh `_meta` table).
// Existing users get it once on their next unlock after upgrading — that is
// the intended behaviour, not a bug.
//
// Kept in commonMain (ONE implementation) rather than duplicated per
// platform like the burn notice — the platform layers only render the
// dialog; RunViewModel / IosAppController each expose a zero-arg
// `consumePushPromptOnce()` wrapper over the vault they currently hold open.
// ---------------------------------------------------------------------------

/** Encrypted per-vault meta key latching that the prompt has been shown. */
private const val PUSH_PROMPT_META_KEY = "onboard_push_prompt_v1"

/**
 * Returns true exactly once per vault — the first call finds the meta absent,
 * writes it, and returns true; every later call (this vault) returns false.
 * Durable across relaunch/lock, cleared with the vault on wipe. Never throws:
 * a transient meta read/write failure returns false (never crash unlock for
 * onboarding; the prompt simply re-offers on the next unlock).
 */
fun consumePushPromptOnce(vault: VaultDatabase): Boolean =
    try {
        if (vault.getMeta(PUSH_PROMPT_META_KEY) == null) {
            vault.putMeta(PUSH_PROMPT_META_KEY, "1")
            true
        } else {
            false
        }
    } catch (_: Exception) {
        false
    }

/**
 * Pure gate for WHEN the one-shot prompt may be raised this session — evaluated
 * by the platform session layer on every relay-reachability change once the
 * vault is open (Android `RunViewModel.armPushPromptForFirstRelayContact`, iOS
 * `AppState.checkRelayReachability`), and [consumePushPromptOnce] runs only when
 * this returns true:
 *  - [relayReachable]: the relay has answered — the contact list is revealed and
 *    the switch the prompt leads to can actually register.
 *  - [alreadyOfferedThisSession]: the gate fired once already (the latch decided
 *    then; a later reachability flap must not re-ask).
 *  - [reviewSheetRequestedThisSession]: the native store-review sheet was
 *    requested — the two must never stack, and that one cannot be deferred, so
 *    the push prompt yields and (latch untouched) asks in the next session.
 */
fun pushPromptDueOnRelayContact(
    relayReachable: Boolean,
    alreadyOfferedThisSession: Boolean,
    reviewSheetRequestedThisSession: Boolean,
): Boolean = relayReachable && !alreadyOfferedThisSession && !reviewSheetRequestedThisSession

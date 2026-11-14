package com.vg.run

/**
 * The two per-session managers plus their cross-wiring, assembled in ONE
 * commonMain place. Both platforms built GroupManager + ReferralManager and then
 * wired `groupManager.onReferralControl = referral.handleControl` by hand
 * (RunViewModel.onVaultOpened ≡ IosAppController unlock) — a platform that forgot
 * the wiring would silently drop referral control messages arriving on the group
 * channel. Now impossible to forget: the factory does it once.
 */
class SessionManagers(
    val groupManager: GroupManager,
    val referralManager: ReferralManager,
    /** The Maximum shield (null when the platform wired no level probe). */
    val maximumShield: MaximumShield? = null,
)

/**
 * Build the group + referral managers for an opened [vault] and wire the referral
 * control bridge (referral offers/accepts that arrive on the group control channel
 * are routed to the ReferralManager). [messageManagerProvider] is read lazily —
 * the MessageManager is (re)created as Tor connects — matching both managers' own
 * provider parameter.
 */
fun createSessionManagers(
    vault: VaultDatabase,
    // Runs the EAGER group-inbox establishment OFF the critical path (durability
    // half of the group unread-dot fix): the platform hands a background-coroutine
    // launcher cancelled with the session (Android `viewModelScope`, iOS
    // `sessionWorkScope`). Wired HERE for the same "can't forget on one platform"
    // reason as the two bridges below; the DEFAULT is a NO-OP, so the JVM unit
    // suite (non-thread-safe InMemoryVault) never runs it on a background thread and
    // an unwired build simply falls back to the lazy control-sweep backfill.
    groupBackfillLauncher: (() -> Unit) -> Unit = { },
    // The Maximum shield's "am I at MAXIMUM" read ([VaultSelector.maximumShieldLevel]);
    // null = the feature is not wired (JVM tests that do not exercise it). Wired HERE,
    // like the bridges below, so a platform cannot ship the sender without the receiver.
    maximumLevelProbe: (() -> MaximumShieldLevel)? = null,
    messageManagerProvider: () -> MessageManager?,
): SessionManagers {
    // "Move to new device" FREEZE GATE (docs/device-move.md D2). Both managers ask
    // for the transport at the top of every operation that touches the relay —
    // GroupManager.transport() gates pollAllControls / pollGroup / pollDirect /
    // every send and the control-sweep hook below; ReferralManager gates its
    // handshake sends and redrives the same way — so wrapping the PROVIDER is the
    // single cheapest point that makes all of them no-op while this device is the
    // OLD phone of a move. One `_meta` read per transport lookup, no network.
    //
    // Belt and braces: the platform layer also quiesces (MoveSessionControl.quiesce)
    // and the old phone's UI never reaches these screens. This gate is what survives
    // a platform that forgot, or a poll loop that outlived the teardown — and what it
    // prevents is not cosmetic: a single poll RECEIVES, which advances the Double
    // Ratchet and orphans the new phone's chain into a legacy re-bootstrap
    // (docs/device-move.md fact 5).
    //
    // It is NOT sufficient on its own, and never was: this wrapper only covers the
    // managers built HERE. The plain 1:1 paths hold the MessageManager directly
    // (RunViewModel.sendMessageInBackground, AppState.sendMessage, the iOS unread
    // sweep), so the SAME check also lives inside MessageManager itself, on every
    // contact-facing send/poll/peek. See its freeze-gate section; this one stays
    // because it also stops the loops from spinning against that gate.
    //
    // [isMoveFrozen] fails toward FROZEN on a vault read error, so the failure mode
    // is a paused poll cycle, never an un-gated one.
    val gatedProvider: () -> MessageManager? = {
        if (isMoveFrozen(vault)) null else messageManagerProvider()
    }
    val groupManager = GroupManager(vault, gatedProvider)
    groupManager.groupBackfillLauncher = groupBackfillLauncher
    val maximumShield = maximumLevelProbe?.let { MaximumShield(vault, it) }
    val referralManager = ReferralManager(vault, gatedProvider)
    groupManager.onReferralControl = { sender, kind, body ->
        referralManager.handleControl(sender, kind, body)
    }
    // Second bridge, same reason as the first: the referral handshake's TTL GC and
    // its two bounded redrive obligations (an accept whose delivery was never
    // confirmed; an accept the introducer could not forward) need a cadence with a
    // live transport, and the control sweep is it. Wiring it here means neither
    // platform can forget it — a forgotten hookup would silently reinstate the
    // "failed forward is swallowed forever" behaviour.
    //
    // The persisted screenshot notices ride the same hook, for the same reason and
    // with the same "no timer of its own" discipline: their 24 h expiry needs a
    // cadence, the sweep's first pass runs seconds after unlock, and both calls are
    // cheap local reads that never throw (GroupManager catches; the sweep catches
    // again). Order is irrelevant — they share no state.
    groupManager.onControlSweep = {
        referralManager.runMaintenance()
        groupManager.pruneExpiredScreenshotNotices()
        // Invite rate-window rows whose stamps have all aged out (the referral
        // offer twin is pruned inside runMaintenance above).
        groupManager.pruneStaleInviteRateWindows()
        // Membership rosters/leaves the relay refused (or
        // that could not be sent while Tor was down) are redriven here, bounded by
        // attempts + a 7-day ceiling — the same shape as the referral redrives.
        // The same redrive now also carries the ACK-GATED
        // obligations — a roster the RELAY accepted but whose recipient has never
        // since echoed our membership hash.
        groupManager.redriveUndeliveredMembershipControl()
        // The second and independent mechanism: members whose own traffic
        // carries a membership hash that is not ours have positively NOT converged,
        // whatever the relay answered to our appends. Re-send them the current
        // roster, bounded per member and per sweep. Wired here (never inside a poll)
        // so it rides the same live-transport cadence as the redrives beside it.
        groupManager.rerosterUnconvergedMembers()
        // "Move to new device": read-cap rotations that did not land during the
        // NEW phone's post-import "Securing" step. Same rationale as the redrives
        // above — the work needs a cadence with a live transport and must not have a
        // timer of its own. Cheap-gated on one `_meta` read, so a vault that never
        // moved pays a single lookup; never throws (the sweep catches too).
        retryPendingMoveRotations(vault, gatedProvider())
        // Maximum shield: announce a tier change / a new pairing / the session's first
        // pass, and retry what a previous pass could not send. A steady-state pass
        // reads one level + one marker per contact and sends NOTHING. The sends are
        // spread with random delays, so the pass is handed to the platform's background
        // launcher instead of delaying this sweep's drain (and never touches unlock or
        // connect). The default launcher is a no-op (JVM suite), like the backfill's.
        maximumShield?.let { shield ->
            groupBackfillLauncher {
                val mgr = gatedProvider()
                if (mgr != null) {
                    val blocked = try { groupManager.blockedContacts() } catch (_: Exception) { null }
                    // A throwing block-list provider skips the pass: never announce to a
                    // contact we cannot prove is not blocked.
                    if (blocked != null) shield.reconcile(blocked) { cid, max -> mgr.sendMaximumAnnouncement(cid, max) }
                }
            }
        }
    }
    return SessionManagers(groupManager, referralManager, maximumShield)
}

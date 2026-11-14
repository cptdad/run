package com.vg.run

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Pins the move allowlist to the ratchet purge list: every per-contact ratchet key the
 * codebase knows (`ratchetMetaKeysForContact`) must travel with a move, or the new phone
 * silently loses a per-contact security flag (`ib-bound-seen/` was
 * once missing).
 */
class MoveMetaPolicyPinTest {
    @Test
    fun everyRatchetMetaKeyIsAllowed() {
        val missing = ratchetMetaKeysForContact("c-pin")
            .filterNot { MoveMetaPolicy.isAllowedKey(it) || it in DELIBERATELY_NOT_CARRIED }
        assertTrue(missing.isEmpty(), "ratchet keys not covered by MoveMetaPolicy: $missing")
    }

    /**
     * The ONE purge-list key that deliberately does NOT travel: the persisted group
     * unread attribution (a ≤ 24 h display hint; the new phone falls back to the
     * presence bump). Pinned both ways — it IS purged with the contact, and a bundle
     * never carries it — so the exemption above cannot quietly grow.
     */
    @Test
    fun theGroupUnreadAttributionIsPurgedButNeverCarried() {
        val k = GroupUnreadMarkerStore.keyFor("c-pin")
        assertTrue(k in ratchetMetaKeysForContact("c-pin"), "it must die with the contact")
        assertFalse(MoveMetaPolicy.isAllowedKey(k), "it must not travel in a move bundle")
        assertFalse(k.startsWith("grp_"), "the hyphen keeps the `grp_` allow prefix off it")
        assertTrue(DELIBERATELY_NOT_CARRIED == setOf(k), "the exemption list is exactly this one key")
    }

    private companion object {
        val DELIBERATELY_NOT_CARRIED = setOf(GroupUnreadMarkerStore.keyFor("c-pin"))
    }

    /**
     * The two role-collision keys by name. The generic pin above already
     * covers them through `ratchetMetaKeysForContact`, but they are the newest members
     * of that list and the failure mode is silent (a bundle that quietly drops the
     * refusal hands the new phone a fresh window of no-forward-secrecy traffic), so
     * they are named here too.
     */
    @Test
    fun roleCollisionKeysTravelWithTheRatchetState() {
        assertTrue(MoveMetaPolicy.isAllowedKey(MessageManager.drRatUnackedKey("c-pin")))
        assertTrue(MoveMetaPolicy.isAllowedKey(MessageManager.drRefusedKey("c-pin")))
        // …and so does the ratchet state they describe, or the verdict would arrive
        // without the role that produced it.
        assertTrue(MoveMetaPolicy.isAllowedKey("dr/c-pin/${MessageManager.RATCHET_TEXT_CHANNEL}"))
    }

    /**
     * The two role INPUTS by name, for the same reason — the failure
     * mode is silent and one-sided. A bundle that drops them leaves the new phone on
     * the id-order rule, so the first `onCorruptReinit` there can pick the OPPOSITE
     * role from the peer, which is the collision the role-binding exists to remove.
     */
    @Test
    fun roleRuleInputsTravelWithTheRatchetState() {
        assertTrue(MoveMetaPolicy.isAllowedKey(MessageManager.drRoleOrderKey("c-pin")))
        assertTrue(MoveMetaPolicy.isAllowedKey(MessageManager.drPeerRoleRuleV2Key("c-pin")))
    }

    /**
     * The anti-eclipse tombstone travels.
     *
     * It is the only `group_`-prefixed key in the vault — every other group key is
     * `grp_` — so the allowlist's `"grp_"` entry did NOT cover it and a move dropped
     * it silently. The consequence is one-sided and invisible: the tombstone is what
     * makes a later invite to a group the user already LEFT, from a DIFFERENT contact
     * than the original admin, show the eclipse warning. Losing it on a move re-opens
     * that attack for every group the old phone ever left.
     *
     * Pinned in BOTH directions — the allowlist entry and the `grp_` near-miss that
     * hid it — plus the import-side re-filter, which is a second, independent call to
     * the same predicate (`MigrationBundle.decode` and `VaultSnapshotIo.import` both
     * re-filter, so an export-only fix would still be dropped on arrival).
     */
    @Test
    fun antiEclipseAdminTombstoneTravels() {
        assertTrue(
            MoveMetaPolicy.isAllowedKey("group_admin:g-pin"),
            "the M2 anti-eclipse tombstone must survive a device move",
        )
        assertTrue(
            MoveMetaPolicy.isAllowedKey("group_admin:${"g".repeat(40)}"),
            "any groupId suffix, not just a short one",
        )
        // The near-miss that produced the bug: `grp_` does not match `group_admin:`.
        assertFalse(
            "group_admin:g-pin".startsWith("grp_"),
            "if this ever becomes true the explicit prefix above is redundant — check the key name",
        )
        // A group-scoped key that is NOT the tombstone must still travel via `grp_`,
        // so the new entry is additive and did not replace anything.
        assertTrue(MoveMetaPolicy.isAllowedKey("grp_ctl_pend:g-pin:c-pin"))
        assertTrue(MoveMetaPolicy.isAllowedKey("grp_declined"))
    }

    /**
     * v10: the GROUP inbox pair adds a third OWNED read direction, and
     * `cap-pend/<id>/<direction>` is per direction. That marker holds a live inbox
     * OWNER capability mid-rotation, so a move that dropped it would leave the new
     * phone unable to finish a rotation it inherited (the "union {record cap,
     * pending marker}" invariant spans the move). The generic pin above already
     * covers it through `ratchetMetaKeysForContact`; named here because the
     * direction list is the coupling that is easy to forget.
     */
    @Test
    fun theGroupInboxPendingCapMarkerTravels() {
        assertTrue(
            MoveMetaPolicy.isAllowedKey(
                MessageManager.capPendingKey("c-pin", MessageManager.DIR_INBOUND_GRP)
            ),
            "cap-pend/<id>/inbound-grp must survive a device move",
        )
        // The rows themselves are table rows, not `_meta`, so there is nothing else
        // to allow: every direction travels through VaultSnapshotIo's getAllInboxIds.
        assertTrue(MessageManager.DIR_INBOUND_GRP in MessageManager.OWNED_READ_DIRECTIONS)
    }

    /**
     * The group-inbox BACKFILL THROTTLE travels, and it is spelled with a
     * HYPHEN so the `grp_` group-manager prefix cannot swallow it by accident.
     *
     * It is a BOUND, not a cache: `grp-ann/<contactId>` records how much of a
     * per-contact budget of PoW mints + inbox announces has been spent, and only a
     * RE-PAIR (the key dies with the contact) or the pairing actually CONVERGING
     * re-arms it. A move is neither — so a bundle that dropped it would hand the
     * new phone a full fresh budget for every contact that never converged, i.e. a
     * burst of 20-bit grinds and control appends on exactly the launch that is
     * already paying for the read-cap rotations.
     */
    @Test
    fun theGroupInboxBackfillThrottleTravels() {
        assertTrue(
            MoveMetaPolicy.isAllowedKey(MessageManager.groupBackfillKey("c-pin")),
            "grp-ann/<id> is a spent-budget record; a move must not re-arm it",
        )
        // The near-miss that made this need its own entry.
        assertFalse(
            MessageManager.groupBackfillKey("c-pin").startsWith("grp_"),
            "if this ever becomes true the explicit prefix is redundant — check the key name",
        )
        // …and it dies with the contact, which IS one of the two legitimate re-arms.
        assertTrue(MessageManager.groupBackfillKey("c-pin") in ratchetMetaKeysForContact("c-pin"))
    }

    @Test
    fun moveOwnKeysAndSelectorKeysNeverTravel() {
        listOf(
            MoveMetaKeys.FROZEN, MoveMetaKeys.HANDLE, MoveMetaKeys.IMPORTED, "mig_rotate_pending",
            "vlt_a", "vlt_c", "vlt_rc", "pin_failed_attempts_v2", "inactivity_armed_v1",
            "review_prompt_v1", "update_nudge_v1", "onboard_push_prompt_v1",
            // The one-time push-consent migration latch. It must NOT
            // travel — the new phone has no legacy plaintext level to migrate,
            // so carrying the latch would only stop it establishing its own.
            NotificationLevelStore.VAULT_MARKER_KEY,
        ).forEach { assertFalse(MoveMetaPolicy.isAllowedKey(it), "must not travel: $it") }
    }
}

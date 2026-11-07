package com.vg.run.fuzz

import com.code_intelligence.jazzer.api.FuzzedDataProvider
import com.code_intelligence.jazzer.junit.FuzzTest
import com.vg.run.GroupInvite
import com.vg.run.GroupInviteStore
import com.vg.run.GroupManager
import com.vg.run.GroupMemberRecord
import com.vg.run.GroupRecord
import com.vg.run.decodeDeclinedInvites
import com.vg.run.encodeDeclinedInvites
import org.junit.jupiter.api.Test

/**
 * Group CONTROL bodies (invite / join / roster / leave / activity / screenshot)
 * and the parked-invite store.
 *
 * A group control body arrives inside the 1:1 AEAD envelope of a PAIRED contact,
 * so the attacker here is a malicious (or compromised) group member — squarely in
 * scope: the whole point of the epoch/roster/tag machinery is that a member
 * cannot rewrite the group.
 *
 * DOCUMENTED CONTRACTS:
 *  - `handleControl` — an unknown kind is "DROPPED SILENTLY … no throw, no vault
 *    mutation"; every handler bails with `return` on a field it does not like.
 *    So: NOTHING may escape it.
 *  - `GroupInviteStore.decode` — "a corrupt row is 'no parked invite', never an
 *    error and never a throw".
 *  - `decodeDeclinedInvites` — drops non-conforming lines; never throws.
 */
class GroupControlFuzzTest {

    @FuzzTest(maxDuration = "60s")
    fun fuzzGroupControlBody(data: FuzzedDataProvider) {
        val body = data.consumeRemainingAsString()

        for (kind in CONTROL_KINDS) {
            // A fresh world per kind: handlers mutate the vault, and a harness
            // whose Nth input depends on the N-1th is not reproducible from a
            // single crash file.
            val (vault, groups) = freshGroupWorld()
            bounded("handleControl($kind)") {
                groups.handleControl(FuzzIds.CONTACT, FuzzIds.GROUP, kind, body, timestampMs = 1L)
            }
            // A handler that BAILED must not have half-written the group: the
            // epoch may only ever move forward.
            val after = vault.getGroup(FuzzIds.GROUP)
            if (after != null) {
                check(after.epoch >= SEED_EPOCH) { "control body moved the group epoch BACKWARDS" }
                check(after.epoch <= GroupManager.MAX_GROUP_EPOCH) {
                    "control body pushed the epoch past MAX_GROUP_EPOCH: ${after.epoch}"
                }
            }
        }

        // An UNKNOWN kind must be inert — no throw and no vault write at all.
        val (vault2, groups2) = freshGroupWorld()
        val before = vault2.metaKeys().toSet()
        groups2.handleControl(FuzzIds.CONTACT, FuzzIds.GROUP, "kind-$body".take(64), body)
        check(vault2.metaKeys().toSet() == before) { "an UNKNOWN control kind wrote to the vault" }
    }

    @FuzzTest(maxDuration = "60s")
    fun fuzzParkedInviteRow(data: FuzzedDataProvider) {
        val value = data.consumeRemainingAsString()

        // The KEY is attacker-influenced too: it embeds the groupId and the
        // inviter contact id, both `:`-delimited into the _meta key.
        val keys = listOf(
            GroupInviteStore.keyFor(FuzzIds.GROUP, FuzzIds.CONTACT),
            GroupInviteStore.keyFor(value.take(64), FuzzIds.CONTACT),
            GroupInviteStore.keyFor(FuzzIds.GROUP, value.take(64)),
            value.take(128),
        )
        for (key in keys) {
            val decoded = bounded("GroupInviteStore.decode") { GroupInviteStore.decode(key, value) }
            if (decoded != null) {
                // Everything decode returns must satisfy the same rules handleInvite
                // enforces on the wire — that equivalence is the whole point of the
                // "STRICT decode" comment, and it is what stops a tampered _meta row
                // parking an invite the receive path would have refused.
                check(decoded.epoch in 1..GroupManager.MAX_GROUP_EPOCH) { "decoded epoch out of range" }
                check(GroupManager.isValidMemberId(decoded.adminMemberId)) { "decoded admin id invalid" }
                check(GroupManager.isValidMemberId(decoded.myMemberId)) { "decoded self id invalid" }
                check(decoded.adminMemberId != decoded.myMemberId) { "decoded admin == self" }
                check(decoded.memberIds.isNotEmpty()) { "decoded empty roster" }
                check(decoded.memberIds.size <= GroupManager.MAX_GROUP_MEMBERS) { "decoded roster over cap" }
                check(decoded.memberIds.all { GroupManager.isValidMemberId(it) }) { "decoded member id invalid" }
                check(decoded.adminMemberId in decoded.memberIds) { "decoded admin not in roster" }
                check(decoded.myMemberId in decoded.memberIds) { "decoded self not in roster" }
                check(decoded.receivedAt > 0L) { "decoded non-positive timestamp" }
                check(decoded.groupName.isNotBlank()) { "decoded blank group name" }
            }
        }

        // The declined-token list is a newline-delimited _meta blob with its own
        // scanner; same contract (drop what does not conform, never throw).
        val declined = bounded("decodeDeclinedInvites") { decodeDeclinedInvites(value, 32) }
        check(declined.size <= 32) { "decodeDeclinedInvites exceeded its cap: ${declined.size}" }
        // Re-encoding what it accepted must be a fixed point.
        val reencoded = encodeDeclinedInvites(declined, 32)
        check(decodeDeclinedInvites(reencoded, 32) == declined) { "declined-invite codec is not idempotent" }
    }

    // ------------------------------------------------------------------
    // Fixed regression tests.
    // ------------------------------------------------------------------

    /** The store's encode → decode round trip must be lossless for a legal invite. */
    @Test
    fun parkedInviteRoundTrips() {
        val invite = GroupInvite(
            groupId = FuzzIds.GROUP,
            inviterContactId = FuzzIds.CONTACT,
            inviterAlias = "Inviter",
            groupName = "Fuzz Group",
            epoch = 3L,
            adminMemberId = FuzzIds.MEMBER_PEER,
            myMemberId = FuzzIds.MEMBER_SELF,
            memberIds = listOf(FuzzIds.MEMBER_PEER, FuzzIds.MEMBER_SELF),
        )
        val key = GroupInviteStore.keyFor(invite.groupId, invite.inviterContactId)
        val decoded = GroupInviteStore.decode(key, GroupInviteStore.encode(invite, 42L))
        check(decoded != null) { "a legal invite failed to round trip" }
        check(decoded.epoch == 3L && decoded.memberIds.size == 2 && decoded.receivedAt == 42L)
    }

    /** A `:` smuggled into the groupId must degrade to "not storable", never split the key. */
    @Test
    fun colonInIdsIsRefusedRatherThanSplittingTheKey() {
        val key = GroupInviteStore.keyFor("gro:up", FuzzIds.CONTACT)
        check(GroupInviteStore.decode(key, """{"n":"x","ep":"1"}""") == null)
    }

    private companion object {
        const val SEED_EPOCH = 1L

        val CONTROL_KINDS = listOf(
            GroupManager.KIND_INVITE,
            GroupManager.KIND_JOIN,
            GroupManager.KIND_ROSTER,
            GroupManager.KIND_LEAVE,
            GroupManager.KIND_ACTIVITY,
            GroupManager.KIND_SCREENSHOT,
        )

        /**
         * A vault where we are an ordinary member of a group whose ADMIN is the
         * contact sending the fuzzed control — the state in which roster/leave
         * bodies are actually acted on rather than dropped for lack of standing.
         */
        fun freshGroupWorld(): Pair<InMemoryVault, GroupManager> {
            val vault = InMemoryVault()
            vault.insertContact(seededContact())
            vault.insertGroup(
                GroupRecord(
                    groupId = FuzzIds.GROUP,
                    name = "Fuzz Group",
                    epoch = SEED_EPOCH,
                    adminMemberId = FuzzIds.MEMBER_PEER,
                    myMemberId = FuzzIds.MEMBER_SELF,
                    createdAt = 1L,
                ),
            )
            vault.insertGroupMember(
                GroupMemberRecord(FuzzIds.GROUP, FuzzIds.MEMBER_SELF, null, 1L),
            )
            vault.insertGroupMember(
                GroupMemberRecord(FuzzIds.GROUP, FuzzIds.MEMBER_PEER, FuzzIds.CONTACT, 1L),
            )
            // No live MessageManager: the parse paths must not need the network,
            // and a null provider proves they do not reach for it.
            return vault to GroupManager(vault) { null }
        }
    }
}

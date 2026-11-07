package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The FOURTH arming condition for the FAST control-poll cadence: "a group
 * conversation is open in the foreground" (product decision 2026-10-01).
 *
 * Measured on the test phones (cross-multi3, 2026-09-30): a passive member that never
 * sent anything learned of a kick / admin handoff / re-add only on its next IDLE
 * sweep — waitForAdminAffordance 210 s, waitForGroupInfoMemberCount 81 s.
 *
 * Both platform loops compute, per cycle,
 * `received || hasUnresolvedMembers() || isGroupConversationForeground()` and pass
 * it as `convergingNow`; they sleep the delay in 1 s slices and ask
 * `controlPollIdleWaitShouldEnd(delay, fastWantedNow = isGroupConversationForeground())`
 * each slice. These tests pin the shared halves of that contract:
 *  (a) flag on ⇒ FAST, with the persistent window NOT armed (peek-before-drain stays on);
 *  (b) flag off ⇒ IDLE, and the flag ends with the screen (keys, scrub);
 *  (c) the flag never changes [GroupManager.hasUnresolvedMembers] (the join-window bound and the admin-handoff guard);
 *  (d) an IDLE sleep ends within one slice of the flag turning on; a FAST one is never cut.
 *
 * (d) is pinned at the PREDICATE the slice loop consults, plus a mirror of the
 * loop below: the loops themselves are a `viewModelScope` coroutine
 * (RunViewModel.startControlPoll) and a Swift `Task` (AppState.startControlPoll),
 * neither of which is reachable from commonTest.
 */
class GroupConversationForegroundCadenceTest {

    private var clock = 1_000_000_000L

    private fun manager(vault: VaultDatabase = InMemoryVault()): MessageManager =
        MessageManager(vault, "http://relay.test", FakeRelayHttp.allVerbs(HttpResult(code = 503, body = null, isSuccess = false))).also { it.controlConvergenceClockMs = { clock } }

    private fun groupManager(vault: VaultDatabase = InMemoryVault()): GroupManager =
        GroupManager(vault) { null }.also { it.clockMs = { clock } }

    /** The exact per-cycle expression both platform loops evaluate. */
    private fun cycleConverging(received: Boolean, gm: GroupManager): Boolean =
        received || gm.hasUnresolvedMembers() || gm.isGroupConversationForeground()

    private fun memberId(seed: Int) = bytesToHex(ByteArray(8) { (seed + it).toByte() })

    // ---- (a) flag on ⇒ FAST, window NOT armed ---------------------------------

    @Test
    fun flagOn_picksFast_withoutArmingThePersistentWindow() {
        val mgr = manager()
        val gm = groupManager()
        gm.setGroupConversationForeground("conv:g1", open = true)
        assertTrue(gm.isGroupConversationForeground())

        repeat(20) {
            val delay = mgr.controlPollDelayMs(cycleConverging(received = false, gm = gm))
            assertTrue(
                delay >= MessageManager.CONTROL_POLL_FAST_BASE_MS &&
                    delay < MessageManager.CONTROL_POLL_FAST_BASE_MS + MessageManager.CONTROL_POLL_FAST_JITTER_MS,
                "an open group conversation must poll the control channel at the FAST cadence (was $delay)",
            )
        }
        // The persistent window is untouched, so the sweep keeps its peek-before-drain
        // (GroupManager.pollAllControls reads isControlConverging, not the flag).
        assertFalse(mgr.isControlConverging(), "the flag must never arm the convergence window")
        // …and nothing lingers: a cycle that does NOT pass the flag is IDLE at once.
        assertTrue(mgr.controlPollDelayMs(convergingNow = false) >= MessageManager.CONTROL_POLL_IDLE_BASE_MS)
    }

    // ---- (b) flag off ⇒ IDLE; ends with the screen ----------------------------

    @Test
    fun flagOff_picksIdle_andEndsWithTheScreen() {
        val mgr = manager()
        val gm = groupManager()
        assertFalse(gm.isGroupConversationForeground(), "default is off")
        assertTrue(mgr.controlPollDelayMs(cycleConverging(false, gm)) >= MessageManager.CONTROL_POLL_IDLE_BASE_MS)

        gm.setGroupConversationForeground("conv:g1", open = true)
        gm.setGroupConversationForeground("conv:g1", open = false)
        assertFalse(gm.isGroupConversationForeground(), "leaving the screen ends the condition — no timer")
        assertTrue(mgr.controlPollDelayMs(cycleConverging(false, gm)) >= MessageManager.CONTROL_POLL_IDLE_BASE_MS)
        assertFalse(mgr.isControlConverging())
    }

    @Test
    fun overlappingScreens_departingScreenDoesNotClearItsSuccessor() {
        // Android: conversation → group info composes "info:" BEFORE the conversation
        // disposes; SwiftUI may deliver a duplicate onAppear. Neither may desync the flag.
        val gm = groupManager()
        gm.setGroupConversationForeground("conv:g1", open = true)
        gm.setGroupConversationForeground("conv:g1", open = true)  // duplicate appear
        gm.setGroupConversationForeground("info:g1", open = true)
        gm.setGroupConversationForeground("conv:g1", open = false) // late dispose
        assertTrue(gm.isGroupConversationForeground(), "group info is still on screen")
        gm.setGroupConversationForeground("info:g1", open = false)
        assertFalse(gm.isGroupConversationForeground())
        // Removing a key that was never added is a no-op, not an underflow.
        gm.setGroupConversationForeground("conv:g2", open = false)
        assertFalse(gm.isGroupConversationForeground())
    }

    @Test
    fun scrubInMemory_clearsTheFlag() {
        // Lock / wipe / teardown call scrubInMemory before dropping the GroupManager;
        // a screen whose onDispose/onDisappear never ran must not survive that.
        val gm = groupManager()
        gm.setGroupConversationForeground("conv:g1", open = true)
        gm.scrubInMemory()
        assertFalse(gm.isGroupConversationForeground())
    }

    // ---- (c) never changes the join-window / handoff-guard outcome -----------------------------

    @Test
    fun flag_neverChangesHasUnresolvedMembers_sc2() {
        val window = GroupManager.UNRESOLVED_MEMBER_FAST_WINDOW_MS
        val self = memberId(1); val peer = memberId(2)
        for (age in listOf(0L, window - 1, window, window * 3)) {
            val v = InMemoryVault()
            val gm = groupManager(v)
            v.insertGroup(GroupRecord("g1", "crew", epoch = 1L, adminMemberId = peer, myMemberId = self, createdAt = 0L))
            v.insertGroupMember(GroupMemberRecord("g1", self, contactId = null, addedAt = clock))
            v.insertGroupMember(GroupMemberRecord("g1", peer, contactId = null, addedAt = clock - age)) // unresolved
            val off = gm.hasUnresolvedMembers()
            gm.setGroupConversationForeground("conv:g1", open = true)
            val on = gm.hasUnresolvedMembers()
            assertEquals(off, on, "the group-join outcome at age=$age must not depend on the screen")
            assertEquals(age < window, on, "the group-join bound itself is unchanged at age=$age")
        }
    }

    @Test
    fun flag_neverChangesHasUnresolvedMembers_sc3() {
        val window = GroupManager.UNRESOLVED_MEMBER_FAST_WINDOW_MS
        val self = memberId(1); val added = memberId(2)
        for (age in listOf(0L, window - 1, window, window * 3)) {
            val v = InMemoryVault()
            val gm = groupManager(v)
            // We are ADMIN; a member added by contact whose join has not landed (no tags).
            v.insertGroup(GroupRecord("g1", "crew", epoch = 1L, adminMemberId = self, myMemberId = self, createdAt = 0L))
            v.insertGroupMember(GroupMemberRecord("g1", self, contactId = null, addedAt = clock))
            v.insertGroupMember(GroupMemberRecord("g1", added, contactId = "M", addedAt = clock - age, tags = ""))
            val off = gm.hasUnresolvedMembers()
            gm.setGroupConversationForeground("conv:g1", open = true)
            gm.setGroupConversationForeground("info:g1", open = true)
            val on = gm.hasUnresolvedMembers()
            assertEquals(off, on, "the handoff outcome at age=$age must not depend on the screen")
            assertEquals(age < window, on, "the handoff bound itself is unchanged at age=$age")
        }
        // No groups at all: the flag still cannot manufacture an unresolved member.
        val gm = groupManager()
        gm.setGroupConversationForeground("conv:g1", open = true)
        assertFalse(gm.hasUnresolvedMembers())
    }

    // ---- (d) the sliced idle sleep wakes within one slice ----------------------

    @Test
    fun idleWait_endsWhenTheFlagTurnsOn_fastWaitIsNeverCut() {
        val mgr = manager()
        val gm = groupManager()
        val idle = mgr.controlPollDelayMs(cycleConverging(false, gm))
        assertTrue(idle >= MessageManager.CONTROL_POLL_IDLE_BASE_MS)
        assertFalse(
            mgr.controlPollIdleWaitShouldEnd(idle, fastWantedNow = gm.isGroupConversationForeground()),
            "a quiet idle wait runs its course",
        )
        gm.setGroupConversationForeground("conv:g1", open = true)
        assertTrue(
            mgr.controlPollIdleWaitShouldEnd(idle, fastWantedNow = gm.isGroupConversationForeground()),
            "opening a group conversation must end the idle wait",
        )
        assertFalse(mgr.isControlConverging(), "ending the wait must not arm the window either")

        // The next cycle picks FAST; that wait must never be cut (no 1 s busy loop).
        val fast = mgr.controlPollDelayMs(cycleConverging(false, gm))
        assertTrue(fast < MessageManager.CONTROL_POLL_IDLE_BASE_MS)
        assertFalse(mgr.controlPollIdleWaitShouldEnd(fast, fastWantedNow = gm.isGroupConversationForeground()))
        // The pre-existing one-argument form is unchanged (Android default arg).
        assertFalse(mgr.controlPollIdleWaitShouldEnd(idle))
    }

    @Test
    fun slicedSleepMirror_breaksOnTheSliceAfterTheFlagFlips() {
        // Mirror of the platform loop's slice structure (1 s slices, predicate asked
        // after each). The user opens the conversation 37 s into an idle wait; the
        // loop must leave on that same slice rather than sleep out the remainder.
        val mgr = manager()
        val gm = groupManager()
        val delay = mgr.controlPollDelayMs(cycleConverging(false, gm))
        val openAtSlice = 37
        var remaining = delay
        var slices = 0
        while (remaining > 0) {
            val slice = minOf(1_000L, remaining)
            remaining -= slice
            slices++
            if (slices == openAtSlice) gm.setGroupConversationForeground("conv:g1", open = true)
            if (mgr.controlPollIdleWaitShouldEnd(delay, fastWantedNow = gm.isGroupConversationForeground())) break
        }
        assertEquals(openAtSlice, slices, "the idle sleep must end within one slice of the screen opening")
        assertTrue(remaining > 0, "it ended EARLY, not by running out")
    }
}

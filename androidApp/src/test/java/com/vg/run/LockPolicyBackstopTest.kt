package com.vg.run

import com.vg.run.LockPolicyBackstop.Action
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The ViewModel-side lock backstop (security review it3, S2 F1). The decision is
 * pure; the source pins below tie it to RunViewModel: it runs on viewModelScope
 * from init (no Activity needed), calls lockForReauth, and no lock cancels it.
 */
class LockPolicyBackstopTest {

    private val idle = 60_000L

    @Test
    fun noVault_nothingFires() {
        val d = LockPolicyBackstop.decide(1_000_000L, vaultOpen = false, reauthDeadlineElapsedMs = 1L,
            idleTimeoutMs = idle, lastInteractionElapsedMs = 0L)
        assertEquals(Action.NONE, d.action)
    }

    @Test
    fun aPassedReauthDeadline_firesWithNoActivity() {
        val d = LockPolicyBackstop.decide(10_000L, vaultOpen = true, reauthDeadlineElapsedMs = 10_000L,
            idleTimeoutMs = null, lastInteractionElapsedMs = 9_999L)
        assertEquals(Action.REAUTH_LOCK, d.action)
    }

    @Test
    fun aRotatingAttackerCannotOutrunIt_theClockIsNotResetByRecreation() {
        // Rotations do not touch the VM clock: the deadline passes and fires.
        var now = 0L
        val deadline = 180_000L
        var fired = false
        while (now <= deadline + LockPolicyBackstop.MAX_CHECK_INTERVAL_MS && !fired) {
            val d = LockPolicyBackstop.decide(now, true, deadline, null, 0L)
            if (d.action == Action.REAUTH_LOCK) fired = true else now += d.nextCheckInMs
        }
        assertTrue("re-auth must fire", fired)
        assertTrue("…no later than one MIN interval after the deadline", now <= deadline + LockPolicyBackstop.MIN_CHECK_INTERVAL_MS)
    }

    @Test
    fun leverC_waitsTheActivityGrace_thenFires() {
        val last = 0L
        val atDeadline = LockPolicyBackstop.decide(idle, true, null, idle, last)
        assertEquals("the attached Activity owns the lock at the deadline itself", Action.NONE, atDeadline.action)
        val after = LockPolicyBackstop.decide(idle + LockPolicyBackstop.ACTIVITY_GRACE_MS, true, null, idle, last)
        assertEquals(Action.IDLE_LOCK, after.action)
    }

    @Test
    fun leverC_offInDebug_meansNoIdleLock() {
        val d = LockPolicyBackstop.decide(10_000_000L, true, null, idleTimeoutMs = null, lastInteractionElapsedMs = 0L)
        assertEquals(Action.NONE, d.action)
        assertEquals(LockPolicyBackstop.MAX_CHECK_INTERVAL_MS, d.nextCheckInMs)
    }

    @Test
    fun anInteractionPushesLeverCOut() {
        val d = LockPolicyBackstop.decide(100_000L, true, null, idle, lastInteractionElapsedMs = 99_000L)
        assertEquals(Action.NONE, d.action)
    }

    @Test
    fun theSleepTracksTheNearerDeadline_andIsBounded() {
        val d = LockPolicyBackstop.decide(0L, true, 3_000L, idle, 0L)
        assertEquals(3_000L, d.nextCheckInMs)
        val far = LockPolicyBackstop.decide(0L, true, 10_000_000L, idle, 0L)
        assertEquals(LockPolicyBackstop.MAX_CHECK_INTERVAL_MS, far.nextCheckInMs)
        val near = LockPolicyBackstop.decide(0L, true, 1L, null, 0L)
        assertEquals(LockPolicyBackstop.MIN_CHECK_INTERVAL_MS, near.nextCheckInMs)
    }

    // ---- source pins: the VM runs it without an Activity ---------------------

    private val vm: String by lazy { SourcePins.stripped(SourcePins.RUN_VIEW_MODEL) }

    @Test
    fun theViewModelRunsTheBackstopOnItsOwnScope_fromInit() {
        val body = vm.bodyOf("    private fun startLockPolicyBackstop() {")
        assertTrue(body.contains("lockPolicyBackstopJob = viewModelScope.launch {"))
        assertTrue(body.contains("LockPolicyBackstop.decide("))
        assertTrue(body.contains("LockPolicyBackstop.Action.REAUTH_LOCK -> {") && body.contains("lockForReauth()"))
        assertTrue("Lever C stays release-only", body.contains("!BuildConfig.DEBUG"))
        val init = vm.bodyOf("    init {")
        assertTrue("init must start the backstop", init.contains("startLockPolicyBackstop()"))
    }

    @Test
    fun noTeardownCancelsTheBackstop() {
        for (sig in listOf("    private fun lockSession(stopTor: Boolean) {", "    fun performEmergencyWipe(deniable: Boolean = true) {")) {
            assertTrue(!vm.bodyOf(sig).contains("lockPolicyBackstopJob"))
        }
        assertTrue(
            "the backstop must not be a session slot",
            !vm.contains("var lockPolicyBackstopJob: Job? by sessionJobs.slot()"),
        )
    }

    @Test
    fun theIdleClockLivesInTheViewModel_andUnlockResetsIt() {
        assertTrue(vm.contains("fun noteUserInteraction() {"))
        assertTrue(vm.contains("fun markConfigurationChangeRecreation() {"))
        assertTrue(vm.contains("fun consumeConfigurationChangeRecreation(): Boolean {"))
        val opened = vm.bodyOf("    fun onVaultOpened(openedVault: VaultDatabase) {")
        assertTrue(opened.contains("noteUserInteraction()"))
    }

    private fun String.bodyOf(signature: String): String {
        val start = indexOf(signature)
        assertTrue("precondition: `$signature` must exist", start >= 0)
        val open = indexOf('{', start)
        var depth = 0
        var i = open
        while (i < length) {
            when (this[i]) {
                '{' -> depth++
                '}' -> { depth--; if (depth == 0) break }
            }
            i++
        }
        return substring(open, i + 1)
    }
}

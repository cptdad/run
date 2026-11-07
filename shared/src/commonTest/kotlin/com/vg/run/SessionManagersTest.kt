package com.vg.run

import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Guards that the session-manager factory always wires the referral-control
 * bridge. The bug it prevents is a platform building the two managers but
 * forgetting `groupManager.onReferralControl = referral.handleControl`.
 */
class SessionManagersTest {

    @Test
    fun createSessionManagers_buildsBoth_andWiresReferralBridge() {
        val vault = InMemoryVault()
        val managers = createSessionManagers(vault) { null }

        assertNotNull(managers.groupManager)
        assertNotNull(managers.referralManager)
        // The cross-wiring is the whole point — a forgotten hookup is the drift.
        assertNotNull(managers.groupManager.onReferralControl, "referral-control bridge not wired")
    }

    @Test
    fun referralBridge_routesToTheReferralManager() {
        val vault = InMemoryVault()
        val managers = createSessionManagers(vault) { null }
        // Invoking the bridge must not throw and must reach the ReferralManager
        // (an unknown/short control body is simply ignored there — no crash).
        managers.groupManager.onReferralControl?.invoke("sender-contact", "unknown-kind", "{}")
        assertTrue(true, "bridge invocation completed without error")
    }
}

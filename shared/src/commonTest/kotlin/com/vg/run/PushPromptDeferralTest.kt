package com.vg.run

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// 2026-09-11: the first-open push prompt waits for the relay (by design),
// see PushPromptOnboarding.kt. These lock the pure gate both platforms consult.
// ---------------------------------------------------------------------------
class PushPromptDeferralTest {

    @Test
    fun notDueWhileConnecting() {
        assertFalse(pushPromptDueOnRelayContact(relayReachable = false, alreadyOfferedThisSession = false, reviewSheetRequestedThisSession = false))
    }

    @Test
    fun dueOnFirstRelayAnswer() {
        assertTrue(pushPromptDueOnRelayContact(relayReachable = true, alreadyOfferedThisSession = false, reviewSheetRequestedThisSession = false))
    }

    @Test
    fun neverTwiceInASession_reachabilityFlapDoesNotReAsk() {
        assertFalse(pushPromptDueOnRelayContact(relayReachable = true, alreadyOfferedThisSession = true, reviewSheetRequestedThisSession = false))
    }

    @Test
    fun yieldsToTheStoreReviewSheet() {
        assertFalse(pushPromptDueOnRelayContact(relayReachable = true, alreadyOfferedThisSession = false, reviewSheetRequestedThisSession = true))
    }

    @Test
    fun latchIsOneShotPerVault() {
        val vault = InMemoryVault()
        assertTrue(consumePushPromptOnce(vault))
        assertFalse(consumePushPromptOnce(vault))
    }
}

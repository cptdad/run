package com.vg.run

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// C5 WARM-UP ROTATION GATE (MessageManager.shouldFireWarmupNewnym, 2026-10-06).
//
// The pre-unlock rendezvous warm-up's one `SIGNAL NEWNYM` (fired when the
// warm-up burns its whole 25 s budget) used to be refused as soon as the user
// had unlocked. iPhone users unlock at ~t5, so it almost never ran there, and
// the stuck warm-up and the stuck first probe sat on the SAME wedged HS circuits
// until the cold rung fired at ~t45–50. The gate is now "no relay round trip yet
// this session", with the per-session NEWNYM budget SHARED with the cold rung.
//
// Both platforms call this one function (Android RunViewModel.fireWarmupNewnym,
// iOS AppState.rotateAndRetryWarmup via IosAppController.warmupNewnymAllowed),
// so lock state is not an input at all: an unlocked session with no answer yet
// gets exactly the answer a locked one does.
// ---------------------------------------------------------------------------

class WarmupNewnymGateTest {

    private fun allowed(
        transportRoundTrip: Boolean = false,
        sessionAnswered: Boolean = false,
        fired: Int = 0,
    ) = MessageManager.shouldFireWarmupNewnym(
        transportRoundTripCompleted = transportRoundTrip,
        relayAnsweredThisSession = sessionAnswered,
        newnymsFiredThisSession = fired,
    )

    @Test
    fun unlockedWithNoRoundTripYet_isAllowed() {
        // Post-unlock, the transport exists but has not completed a round trip
        // and the session has never seen the relay answer: the case this change
        // is for — fire now instead of waiting for the cold rung at ~t45.
        assertTrue(allowed(transportRoundTrip = false, sessionAnswered = false, fired = 0))
        // …and the second NEWNYM of the session is still available to it when
        // the cold rung happened to spend the first one.
        assertTrue(allowed(fired = MessageManager.EARLY_NEWNYM_MAX_FIRES - 1))
    }

    @Test
    fun preUnlockWithNoTransport_isAllowed() {
        // Pre-unlock there is no MessageManager: both callers pass `false` for the
        // transport input. The original C5 behaviour is unchanged.
        assertTrue(allowed())
    }

    @Test
    fun unlockedAfterAProbeOrPeekAnswer_isRefused() {
        // The current transport latched a round trip (health probe, mint
        // warm-gate, peek / batch-peek prime): circuits are proven working, a
        // rotation now would be churn under a live session.
        assertFalse(allowed(transportRoundTrip = true))
    }

    @Test
    fun sessionAnsweredOnAnEarlierTransport_isRefused() {
        // A re-wire (Tor restart, resume) builds a fresh MessageManager whose own
        // latch reads false again; the platform's set-once session latch must
        // still refuse.
        assertFalse(allowed(transportRoundTrip = false, sessionAnswered = true))
        assertFalse(allowed(transportRoundTrip = true, sessionAnswered = true))
    }

    @Test
    fun sessionNewnymCapReached_isRefused() {
        // The counter is the SAME one the cold rung (shouldFireEarlyNewnym)
        // spends, so the two rungs together never exceed the cap.
        assertFalse(allowed(fired = MessageManager.EARLY_NEWNYM_MAX_FIRES))
        assertFalse(allowed(fired = MessageManager.EARLY_NEWNYM_MAX_FIRES + 1))
        // A corrupt negative counter fails CLOSED.
        assertFalse(allowed(fired = -1))
    }

    @Test
    fun sharedCounter_warmupThenColdRungThenWarmupNeverExceedsTheCap() {
        // Walk one session's budget the way the platform ladders do: a single
        // counter, incremented by whichever rung fires.
        var fired = 0
        assertTrue(allowed(fired = fired)); fired++          // warm-up rotation
        assertTrue(                                           // cold rung, second fire (≥ 80 s)
            MessageManager.shouldFireEarlyNewnym(
                coldTransport = true,
                consecutiveFullBudgetTimeouts = MessageManager.EARLY_NEWNYM_MIN_TIMEOUTS,
                msSinceConnectAnchor = MessageManager.EARLY_NEWNYM_SECOND_MS,
                newnymsFiredThisSession = fired,
            ),
        ); fired++
        assertFalse(allowed(fired = fired), "the warm-up gate must see the cold rung's spend")
        assertFalse(
            MessageManager.shouldFireEarlyNewnym(
                coldTransport = true,
                consecutiveFullBudgetTimeouts = MessageManager.EARLY_NEWNYM_MIN_TIMEOUTS,
                msSinceConnectAnchor = 600_000L,
                newnymsFiredThisSession = fired,
            ),
        )
    }
}

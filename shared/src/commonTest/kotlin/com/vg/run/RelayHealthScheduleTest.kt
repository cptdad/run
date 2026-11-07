package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// COLD-START RELAY HEALTH SCHEDULE — the budget and the cadence of `GET /`.
//
// Tor reaches `Bootstrapped 100%` in ~7 s. The FIRST GET to the .onion then has
// to do the whole rendezvous (descriptor fetch, intro circuit, rendezvous
// circuit) and, when one introduction point is dead, that attempt simply hangs.
// Two numbers decide how long the user stares at "Connecting to Relay…":
//
//   1. the per-attempt BUDGET — how long a hung attempt owns the transport
//      before anything rotates onto a fresh stream; and
//   2. the CADENCE — how long the loop then sleeps before trying again.
//
// Both used to be wrong in the same direction: the probe inherited the 60 s
// message-transport default and then slept the full 8–12 s heartbeat, so ONE bad
// introduction point cost 70+ s. An App Store reviewer saw "Connecting to
// Relay… 95%" and rejected the build.
//
// The rules pinned here:
//   • the reachability GET has its OWN budget (HEALTH_HTTP_TIMEOUT_SECONDS) and
//     nothing else on the transport is affected by it;
//   • that budget stays clear of the ~10 s rendezvous floor below which NO
//     attempt could ever complete (each opens a fresh stream and carries no
//     progress over — b309a44);
//   • until the FIRST completed round-trip the loop retries almost immediately
//     (≤ 2 s), then falls back to the jittered 8–12 s heartbeat;
//   • the fast window is BOUNDED, so a transport that fails instantly cannot
//     spin the loop at ~1 request/s forever;
//   • a fast cycle is always shorter than the counted-miss floor both platform
//     loops apply, which is what keeps the grey-out / NEWNYM / stall
//     escalations anchored to the same wall-clock they always had.
// ---------------------------------------------------------------------------

private const val SCHED_INBOX = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYX"          // 32 chars
private const val SCHED_CAP = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" // 43 chars

/** Records the budget asked for on every GET, keyed by url. Never answers. */
private class BudgetSpyRelay(answer: Int = -1) : FakeRelayHttp() {
    init { HttpResult(code = answer, body = "", isSuccess = false).let { r -> onPost = { r }; onPut = { r }; onGet = { r } } }
    val gets: List<Pair<String, Int>> get() = requestsOf("GET").map { it.url to it.timeoutSeconds }
}

class RelayHealthScheduleTest {

    // -----------------------------------------------------------------------
    // (1) The dedicated budget, and its SCOPE.
    // -----------------------------------------------------------------------

    @Test
    fun theHealthBudgetIsTwentySeconds() {
        // The number itself is the product decision: well clear of the ~10 s
        // rendezvous floor, and small enough that a hung introduction point is
        // abandoned and re-tried twice more inside the minute the reviewer waited.
        assertEquals(20, MessageManager.HEALTH_HTTP_TIMEOUT_SECONDS)
    }

    @Test
    fun coldProbe_asksForTheHealthBudgetOnEveryAttempt() {
        val relay = BudgetSpyRelay()
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", relay)

        assertFalse(mgr.isRelayReachable())
        assertTrue(relay.gets.isNotEmpty(), "the probe must actually hit the transport")
        assertTrue(
            relay.gets.all { it.second == MessageManager.HEALTH_HTTP_TIMEOUT_SECONDS },
            "every cold health GET uses the dedicated budget: ${relay.gets}",
        )
    }

    @Test
    fun theHealthBudgetIsScopedToTheReachabilityGet_everythingElseKeepsItsOwn() {
        // Same transport, same COLD state (nothing has completed a round-trip):
        // an ordinary relay GET must still ask for the 60 s message-transport
        // default. Shortening the probe must never shorten real traffic.
        val relay = BudgetSpyRelay()
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", relay)

        mgr.isRelayReachable()
        val probeBudgets = relay.gets.map { it.second }
        relay.clearRequests()

        mgr.peekMoveInbox(SCHED_INBOX, SCHED_CAP)
        assertEquals(1, relay.gets.size, "the peek must have hit the transport")
        assertEquals(
            DEFAULT_RELAY_HTTP_TIMEOUT_SECONDS, relay.gets[0].second,
            "a non-health relay GET keeps the message-transport default even while cold",
        )
        assertTrue(
            probeBudgets.all { it != DEFAULT_RELAY_HTTP_TIMEOUT_SECONDS },
            "…and the health GET is the one that does not: $probeBudgets",
        )
    }

    // -----------------------------------------------------------------------
    // (2) The cadence: immediate retry until the first success, then the
    //     existing jittered heartbeat.
    // -----------------------------------------------------------------------

    @Test
    fun coldTransport_retriesImmediately_thenFallsBackToTheHeartbeat() {
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", BudgetSpyRelay())
        assertFalse(mgr.hasCompletedRelayRoundTrip(), "a fresh transport has proven nothing")

        val fast = (0 until MessageManager.RELAY_HEALTH_FAST_RETRY_MAX).map { mgr.relayHealthDelayMs() }
        assertTrue(
            fast.all { it in MessageManager.RELAY_HEALTH_FAST_RETRY_BASE_MS..
                (MessageManager.RELAY_HEALTH_FAST_RETRY_BASE_MS + MessageManager.RELAY_HEALTH_FAST_RETRY_JITTER_MS) },
            "every cold retry waits at most ~2 s, never the 8–12 s heartbeat: $fast",
        )
        assertTrue(fast.all { it <= 2_000L }, "the brief's ceiling: ≤ 2 s: $fast")

        // Bounded: a transport that fails INSTANTLY must not spin at ~1 req/s
        // forever (battery, and it would evict the 2000-entry LogBuffer the
        // diagnostics live in). After the burst the loop returns to the heartbeat.
        val after = (0 until 5).map { mgr.relayHealthDelayMs() }
        assertTrue(
            after.all { it in MessageManager.RELAY_HEALTH_BASE_MS..
                (MessageManager.RELAY_HEALTH_BASE_MS + MessageManager.RELAY_HEALTH_JITTER_MS) },
            "the fast window is bounded by RELAY_HEALTH_FAST_RETRY_MAX: $after",
        )
    }

    @Test
    fun warmTransport_usesTheJitteredHeartbeat_fromTheFirstSuccessOn() {
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", FakeRelayHttp.warm())
        assertTrue(mgr.isRelayReachable(), "the relay's by-design 404 is a completed round-trip")

        val delays = (0 until 20).map { mgr.relayHealthDelayMs() }
        assertTrue(
            delays.all { it in MessageManager.RELAY_HEALTH_BASE_MS..
                (MessageManager.RELAY_HEALTH_BASE_MS + MessageManager.RELAY_HEALTH_JITTER_MS) },
            "once reachable the loop is back on the 8–12 s heartbeat: $delays",
        )
        // The heartbeat must stay jittered — a fixed period is a
        // traffic-analysis beacon for the relay / guard node.
        assertTrue(delays.distinct().size > 1, "the heartbeat must not collapse to a fixed period")
    }

    @Test
    fun aSuccessMidBurstEndsTheFastWindow() {
        // A cold transport that is answered on the very next probe must go
        // straight back to the heartbeat — the fast window exists only until the
        // FIRST completed round-trip after a (re)connect.
        val relay = FlipToWarmRelay()
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", relay)

        assertFalse(mgr.isRelayReachable())
        assertTrue(mgr.relayHealthDelayMs() <= 2_000L, "still cold → fast retry")

        relay.warm = true
        assertTrue(mgr.isRelayReachable())
        assertTrue(
            mgr.relayHealthDelayMs() >= MessageManager.RELAY_HEALTH_BASE_MS,
            "the first success ends the burst",
        )
    }

    @Test
    fun theScheduleDecisionIsPure() {
        assertTrue(MessageManager.useFastRelayHealthRetry(roundTripCompleted = false, fastRetriesUsed = 0))
        assertTrue(
            MessageManager.useFastRelayHealthRetry(
                roundTripCompleted = false,
                fastRetriesUsed = MessageManager.RELAY_HEALTH_FAST_RETRY_MAX - 1,
            )
        )
        assertFalse(
            MessageManager.useFastRelayHealthRetry(
                roundTripCompleted = false,
                fastRetriesUsed = MessageManager.RELAY_HEALTH_FAST_RETRY_MAX,
            ),
            "the burst is bounded",
        )
        assertFalse(
            MessageManager.useFastRelayHealthRetry(roundTripCompleted = true, fastRetriesUsed = 0),
            "a proven transport never uses the fast cadence",
        )
        assertEquals(1_000L, MessageManager.relayHealthDelayMsFor(fast = true, jitterRoll = 0))
        assertEquals(1_999L, MessageManager.relayHealthDelayMsFor(fast = true, jitterRoll = 999))
        assertEquals(8_000L, MessageManager.relayHealthDelayMsFor(fast = false, jitterRoll = 0))
        assertEquals(11_999L, MessageManager.relayHealthDelayMsFor(fast = false, jitterRoll = 3_999))
    }

    // -----------------------------------------------------------------------
    // (3) The stall counters must stay anchored to WALL TIME.
    // -----------------------------------------------------------------------

    @Test
    fun aFastCycleCanNeverOutpaceTheCountedMissFloor() {
        // Both platform loops count at most ONE reachability miss per
        // RELAY_HEALTH_BASE_MS of real time (Android RunViewModel
        // MIN_STREAK_BUMP_INTERVAL_MS, iOS AppState.minStreakBumpIntervalMs) — that
        // floor is what keeps "3 misses ≈ 24 s", "8 misses → NEWNYM" and "24 misses
        // → Stalled" meaning the same wall-clock they meant at the old cadence.
        // If a fast cycle could ever be LONGER than that floor, the faster cadence
        // would start advancing the escalation ladder, which it must not.
        val longestFastCycle =
            MessageManager.RELAY_HEALTH_FAST_RETRY_BASE_MS + MessageManager.RELAY_HEALTH_FAST_RETRY_JITTER_MS
        assertTrue(
            longestFastCycle < MessageManager.RELAY_HEALTH_BASE_MS,
            "a fast retry must stay inside one counted-miss window: $longestFastCycle",
        )
        assertEquals(8_000L, MessageManager.RELAY_HEALTH_BASE_MS, "both platforms floor miss counting on this")
    }
}

/** Dead until [warm] is set, then answers `GET /` with the relay's 404. */
private class FlipToWarmRelay : FakeRelayHttp(onPost = { RELAY_DEAD }, onPut = { RELAY_DEAD }) {
    var warm = false
    init { onGet = { if (warm) RELAY_WARM_404 else RELAY_DEAD } }
}

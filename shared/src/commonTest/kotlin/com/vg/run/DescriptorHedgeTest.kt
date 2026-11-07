package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// EARLIER BOUNDED HSDIR HEDGE (DescriptorHedge, 2026-10-12). Hermetic: a
// synthetic clock, no Tor. Both platforms drive the same object, so these pin
// the behaviour of both.
// ---------------------------------------------------------------------------

class DescriptorHedgeTest {

    private val REQ = RelayDescriptorEvent.Action.REQUESTED
    private val GOT = RelayDescriptorEvent.Action.RECEIVED
    private val FAIL = RelayDescriptorEvent.Action.FAILED

    private fun DescriptorHedge.at(now: Long, answered: Boolean = false, enabled: Boolean = true) =
        due(now, relayAnswered = answered, hedgeEnabled = enabled)

    @Test
    fun constants_areTheResearchValues() {
        assertEquals(1_000L, DescriptorHedge.HSDESC_HEDGE_MS)
        assertEquals(4_000L, DescriptorHedge.HSDESC_SECOND_HEDGE_MS)
        assertEquals(2, DescriptorHedge.HSDESC_MAX_IN_FLIGHT)
        assertEquals(4, DescriptorHedge.HSDESC_FETCH_BUDGET)
        assertEquals(1_000L, DescriptorHedge.HSDESC_HEDGE_CONFIRM_MS)
    }

    @Test
    fun cacheMiss_firesTheBareHedgeOnceAfterOneSecond() {
        val h = DescriptorHedge()
        assertNull(h.msUntilNextCheck(0), "nothing armed before a cache miss")
        h.observe(REQ, 0)
        assertEquals(1_000L, h.msUntilNextCheck(0))
        assertNull(h.at(999).stage, "not before 1 s")
        val d = h.at(1_000)
        assertEquals(DescriptorHedge.Stage.FIRST, d.stage)
        assertEquals(1, d.spent)
        assertNull(h.at(1_000).stage, "the 1 s hedge fires ONCE")
        assertNull(h.at(1_500).stage)
        assertEquals(1, h.spentThisSession)
    }

    @Test
    fun descriptorBeforeOneSecond_noHedgeAtAll() {
        val h = DescriptorHedge()
        h.observe(REQ, 0)
        h.observe(GOT, 600)
        assertNull(h.msUntilNextCheck(600))
        assertNull(h.at(5_000).stage)
        assertEquals(0, h.spentThisSession)
    }

    @Test
    fun secondReRequest_fourSecondsAfterTheFirst_whenASlotIsFree() {
        val h = DescriptorHedge()
        h.observe(REQ, 0)
        assertEquals(DescriptorHedge.Stage.FIRST, h.at(1_000).stage)
        h.observe(REQ, 1_010)                 // Tor started our hedge
        h.observe(FAIL, 2_000)                // the original HSDir answered NOT_FOUND
        assertEquals(1, h.inFlight(2_000))
        assertEquals(3_000L, h.msUntilNextCheck(2_000), "second stage at 1 s + 4 s")
        assertNull(h.at(4_999).stage)
        val d = h.at(5_000)
        assertEquals(DescriptorHedge.Stage.SECOND, d.stage)
        assertEquals(2, d.spent)
        h.observe(REQ, 5_010)
        assertNull(h.at(60_000).stage, "two re-requests per episode, no third")
    }

    @Test
    fun atMostTwoInFlight_countedFromRequestedEvents() {
        val h = DescriptorHedge()
        // Android's warm-up HSFETCH + Tor's own fetch: two REQUESTEDs, no outcome.
        h.observe(REQ, 0)
        h.observe(REQ, 50)
        assertEquals(2, h.inFlight(1_000))
        assertEquals(3_000L, h.msUntilNextCheck(1_000), "cap reached: re-checked when the oldest request ages out at 4 s, not before")
        assertNull(h.at(1_000).stage, "deferred by the cap")
        h.observe(FAIL, 1_400)                // a slot frees
        assertEquals(0L, h.msUntilNextCheck(1_400), "the deferred hedge is due at once")
        assertEquals(DescriptorHedge.Stage.FIRST, h.at(1_400).stage)
        assertEquals(2, h.inFlight(1_400), "the unconfirmed hedge counts while young")
        // Both fetches stall: the oldest is presumed dead after 4 s, so the
        // second stage is NOT held by the cap (physical-phone A/B 2026-10-13).
        h.observe(REQ, 1_410)
        assertEquals(DescriptorHedge.Stage.SECOND, h.at(5_400).stage)
        assertEquals(2, h.spentThisSession)
    }

    @Test
    fun bothInFlightHung_theFourSecondReRequestStillFires() {
        // Device run 2026-10-13: original + 1 s hedge both hung; the old
        // cap held the re-request for 24 s.
        val h = DescriptorHedge()
        h.observe(REQ, 0)
        assertEquals(DescriptorHedge.Stage.FIRST, h.at(1_000).stage)
        h.observe(REQ, 1_003)                 // the hedge started — and hangs too
        assertEquals(2, h.inFlight(1_003))
        assertEquals(3_997L, h.msUntilNextCheck(1_003), "a check is armed at the 4 s mark, not left to an event")
        assertEquals(1, h.inFlight(4_000), "the original is presumed dead at 4 s")
        val d = h.at(5_000)
        assertEquals(DescriptorHedge.Stage.SECOND, d.stage)
        assertEquals(2, d.spent)
        assertEquals(DescriptorHedge.HSDESC_SECOND_HEDGE_MS, DescriptorHedge.HSDESC_PRESUMED_DEAD_MS)
    }

    @Test
    fun stageDeadline_requestsNewnymOnce_whenRequestsHang() {
        val h = DescriptorHedge()
        h.observe(REQ, 0)
        assertEquals(DescriptorHedge.Stage.FIRST, h.at(1_000).stage)
        h.observe(REQ, 1_003)
        assertEquals(DescriptorHedge.Stage.SECOND, h.at(5_000).stage)
        h.observe(REQ, 5_004)
        assertEquals(4_996L, h.msUntilNextCheck(5_004), "the 10 s stage deadline is armed")
        assertFalse(h.at(9_999).stageStalled)
        assertTrue(h.at(10_000).stageStalled, "episode open 10 s, 3 requests without an outcome")
        assertFalse(h.at(10_001).stageStalled, "once per episode")
        assertNull(h.msUntilNextCheck(10_001), "and no zero-delay re-check after it")
        assertEquals(10_000L, DescriptorHedge.HSDESC_STAGE_DEADLINE_MS)
    }

    @Test
    fun stageDeadline_notWithOneOpenRequestAndBudgetLeft() {
        val h = DescriptorHedge()
        h.observe(REQ, 0)
        assertEquals(DescriptorHedge.Stage.FIRST, h.at(1_000).stage)
        h.observe(REQ, 1_003)
        h.observe(FAIL, 1_200)                // one answered NOT_FOUND
        assertEquals(DescriptorHedge.Stage.SECOND, h.at(5_000).stage)
        h.observe(REQ, 5_004)
        h.observe(FAIL, 5_300)                // one open request, budget 2/4 left
        assertFalse(h.at(10_000).stageStalled)
    }

    @Test
    fun stageDeadline_refusedWhenAnsweredOrControlArm_andLatched() {
        for (answered in listOf(true, false)) {
            val h = DescriptorHedge()
            h.observe(REQ, 0)
            h.observe(REQ, 10)
            h.at(1_000, answered = answered, enabled = answered)  // answered, or control arm
            assertFalse(h.at(10_000, answered = answered, enabled = answered).stageStalled)
            assertNull(h.msUntilNextCheck(10_000), "a refused stall never spins a zero-delay timer")
        }
    }

    @Test
    fun budget_acrossTheStageNewnym_isNotReplenished() {
        val h = DescriptorHedge()
        h.observe(REQ, 0)
        assertEquals(DescriptorHedge.Stage.FIRST, h.at(1_000).stage)
        h.observe(REQ, 1_003)
        assertEquals(DescriptorHedge.Stage.SECOND, h.at(5_000).stage)
        h.observe(REQ, 5_004)
        assertTrue(h.at(10_000).stageStalled)
        assertFalse(h.stageNewnymFiredThisSession)
        h.noteStageNewnymFired()              // the session's NEWNYM went out …
        h.noteNewnym()                        // … and Tor accepted it
        assertTrue(h.stageNewnymFiredThisSession, "the warm-up rotation now skips its own NEWNYM")
        // A fresh episode with the REMAINING budget (2 of 4), not a new one.
        h.observe(REQ, 11_000)
        val first = h.at(12_000)
        assertEquals(DescriptorHedge.Stage.FIRST, first.stage)
        assertEquals(3, first.spent)
        h.observe(REQ, 12_003)
        assertEquals(4, h.at(16_000).spent)
        h.observe(REQ, 16_004)
        // Budget gone: the stage deadline of this episode still fires (its
        // NEWNYM is the session owner's to refuse — shared cap of 2).
        assertTrue(h.at(21_000).stageStalled)
        h.noteNewnym()
        h.observe(REQ, 22_000)
        val d = h.at(23_000)
        assertNull(d.stage)
        assertTrue(d.budgetSpentNow)
        assertEquals(4, h.spentThisSession)
    }

    @Test
    fun hedgeTorNeverStarted_leavesTheInFlightCountButStaysCharged() {
        val h = DescriptorHedge()
        h.observe(REQ, 0)
        assertEquals(DescriptorHedge.Stage.FIRST, h.at(1_000).stage)
        assertEquals(2, h.inFlight(1_000), "counted while it may still start")
        assertEquals(1_000L, h.msUntilNextCheck(1_000), "the confirmation window's expiry is a check")
        val d = h.at(2_000)                   // no REQUESTED followed
        assertNull(d.stage)
        assertEquals(1, d.notStartedCount, "reported once")
        assertEquals(0, h.at(2_100).notStartedCount, "and only once")
        assertEquals(1, h.inFlight(2_000), "no longer in flight")
        assertEquals(1, h.spentThisSession, "but the budget was charged")
        // The episode's second stage still stands (one fetch in flight, a slot free).
        assertEquals(DescriptorHedge.Stage.SECOND, h.at(5_000).stage)
    }

    @Test
    fun budget_notReplenishedByNewnymOrTorRestart_newSessionStartsFresh() {
        val h = DescriptorHedge()
        var t = 0L
        var sent = 0
        var spentLines = 0
        // A pathological day: every round is a stall, then a NEWNYM (or restart).
        repeat(6) { round ->
            h.observe(REQ, t)
            for (step in 0 until 20) {
                t += 500
                val d = h.at(t)
                if (d.budgetSpentNow) spentLines++
                if (d.stage != null) {
                    sent++
                    h.observe(REQ, t + 5)
                    h.observe(FAIL, t + 10)   // keep a slot free so only the budget binds
                }
            }
            if (round % 2 == 0) h.noteNewnym() else h.resetForNewTorProcess()
        }
        assertEquals(DescriptorHedge.HSDESC_FETCH_BUDGET, sent, "4 per session, whatever NEWNYM/restart did")
        assertEquals(DescriptorHedge.HSDESC_FETCH_BUDGET, h.spentThisSession)
        assertEquals(1, spentLines, "the budget-spent line is written once per session")
        assertFalse(h.tryChargeRetry(), "no plain retry past the budget either")

        val next = DescriptorHedge()          // a new foreground session
        next.observe(REQ, 0)
        assertEquals(DescriptorHedge.Stage.FIRST, next.at(1_000).stage)
    }

    @Test
    fun newnym_restartsTheEpisode_soTheNextMissGetsItsOneSecondHedge() {
        val h = DescriptorHedge()
        h.observe(REQ, 0)
        h.observe(GOT, 500)
        h.noteNewnym()                        // Tor purged the descriptor cache
        h.observe(REQ, 10_000)
        assertEquals(1_000L, h.msUntilNextCheck(10_000))
        assertEquals(DescriptorHedge.Stage.FIRST, h.at(11_000).stage)
    }

    @Test
    fun lateLoser_isIgnored_nothingRetriggers() {
        val h = DescriptorHedge()
        h.observe(REQ, 0)
        assertEquals(DescriptorHedge.Stage.FIRST, h.at(1_000).stage)
        h.observe(REQ, 1_005)                 // the hedge started
        h.observe(GOT, 1_300)                 // the hedge WON
        assertNull(h.msUntilNextCheck(1_300))
        // The slow original now loses either way — and Tor may even answer twice.
        h.observe(FAIL, 25_000)
        h.observe(GOT, 25_100)
        assertNull(h.msUntilNextCheck(25_100), "nothing armed by a late loser")
        assertNull(h.at(30_000).stage)
        assertEquals(1, h.spentThisSession)
        assertEquals(0, h.inFlight(30_000))
    }

    @Test
    fun hedgeRequestedAfterTheWinner_isNotAFreshMiss() {
        val h = DescriptorHedge()
        h.observe(REQ, 0)
        assertEquals(DescriptorHedge.Stage.FIRST, h.at(1_000).stage)
        h.observe(GOT, 1_002)                 // the original landed first …
        h.observe(REQ, 1_004)                 // … then Tor reports our hedge starting
        assertNull(h.msUntilNextCheck(1_004), "our hedge's REQUESTED never opens an episode")
        assertNull(h.at(10_000).stage)
    }

    @Test
    fun torsOwnRefetchAfterAReceived_isAFreshMiss() {
        val h = DescriptorHedge()
        h.observe(REQ, 0)
        h.observe(GOT, 400)
        h.observe(REQ, 30_000)                // e.g. every intro point failed
        assertEquals(DescriptorHedge.Stage.FIRST, h.at(31_000).stage)
    }

    @Test
    fun relayAnswered_neverHedges() {
        val h = DescriptorHedge()
        h.observe(REQ, 0)
        assertNull(h.at(1_000, answered = true).stage)
        assertNull(h.at(10_000).stage, "the episode was closed, not deferred")
        assertEquals(0, h.spentThisSession)
    }

    @Test
    fun controlArm_sendsNothing_andSaysSoOnce() {
        val h = DescriptorHedge()
        h.observe(REQ, 0)
        val d = h.at(1_000, enabled = false)
        assertNull(d.stage)
        assertTrue(d.controlArmNow)
        h.noteNewnym()
        h.observe(REQ, 2_000)
        val d2 = h.at(3_000, enabled = false)
        assertNull(d2.stage)
        assertFalse(d2.controlArmNow, "logged once per session")
        assertEquals(0, h.spentThisSession)
    }

    @Test
    fun pinnedRetry_isChargedAgainstTheSameBudget() {
        val h = DescriptorHedge()
        h.observe(REQ, 0)
        assertEquals(DescriptorHedge.Stage.FIRST, h.at(1_000).stage)
        h.observe(REQ, 1_005)
        h.observe(FAIL, 1_500)
        assertEquals(DescriptorHedge.Stage.SECOND, h.at(5_000).stage)
        assertTrue(h.tryChargeRetry())        // 551/552 → plain retry
        assertEquals(3, h.spentThisSession)
    }

    @Test
    fun phrases_areFixed_andCarryNoIdentifier() {
        val all = listOf(
            DescriptorHedge.NOT_STARTED_PHRASE,
            DescriptorHedge.BUDGET_SPENT_PHRASE,
            DescriptorHedge.CONTROL_PHRASE,
            DescriptorHedge.STAGE_STALLED_PHRASE,
            DescriptorHedge.sentPhrase(DescriptorHedge.Stage.FIRST, 1),
            DescriptorHedge.sentPhrase(DescriptorHedge.Stage.SECOND, 2),
        )
        assertEquals("descriptor stage stalled - requesting fresh circuits", all[3])
        assertEquals("descriptor fetch hedged after 1s (1/4)", all[4])
        assertEquals("descriptor fetch re-requested after 4s more (2/4)", all[5])
        for (p in all) {
            assertFalse(p.contains(".onion"), p)
            assertFalse(p.contains('$'), p)
            assertFalse(p.contains("SERVER", ignoreCase = true), p)
            assertFalse(Regex("[0-9A-Fa-f]{16,}").containsMatchIn(p), p)
            assertFalse(Regex("[a-z2-7]{16,}").containsMatchIn(p), p)
        }
        // toString never renders state that could carry an id.
        assertEquals("DescriptorHedge", DescriptorHedge().toString())
    }
}

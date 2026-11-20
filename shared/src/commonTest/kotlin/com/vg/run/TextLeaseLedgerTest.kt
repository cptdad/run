package com.vg.run

import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// TextLeaseLedger's rules, one by one, on the object itself (the drain-level
// behaviour is in LegacyHealLeaseTest). The ledger is process-wide: every test
// starts and ends scrubbed, with its own clock.
// ---------------------------------------------------------------------------

class TextLeaseLedgerTest {

    private var now = 1_000_000L
    private val c = "contact-1"

    @BeforeTest
    fun setUp() {
        TextLeaseLedger.scrub()
        TextLeaseLedger.clockMs = { now }
    }

    @AfterTest
    fun tearDown() {
        TextLeaseLedger.clockMs = { GroupUnreadTally.monotonicNowMs() }
        TextLeaseLedger.scrub()
    }

    @Test
    fun aLeaseTakenAndSettledSinceTheSweepBegan_blocksThatSweepsHeal() {
        val sweepGen = TextLeaseLedger.generation()
        val m = TextLeaseLedger.beginFetch(c, TextLeaseLedger.sessionEpoch())!!
        TextLeaseLedger.resolveLeased(m, "tok-1")
        TextLeaseLedger.settled("tok-1")
        // Nothing is outstanding any more, but the release may have made a blob
        // visible AFTER this sweep's peek: that sweep must not heal.
        assertTrue(TextLeaseLedger.blocksHeal(c, sweepGen))
        // A sweep that began after the settle may.
        assertFalse(TextLeaseLedger.blocksHeal(c, TextLeaseLedger.generation()))
    }

    @Test
    fun aFetchInFlight_blocksTheHeal_untilACleanAnswerResolvesIt() {
        val m = TextLeaseLedger.beginFetch(c, TextLeaseLedger.sessionEpoch())!!
        assertTrue(TextLeaseLedger.blocksHeal(c, TextLeaseLedger.generation()), "the relay may already have leased")
        TextLeaseLedger.resolveClean(m)
        assertFalse(TextLeaseLedger.blocksHeal(c, TextLeaseLedger.generation()))
    }

    @Test
    fun anUnseenAnswer_blocksForTheGuard_thenLetsGo() {
        TextLeaseLedger.resolveUnseen(TextLeaseLedger.beginFetch(c, TextLeaseLedger.sessionEpoch())!!)
        now += TextLeaseLedger.LEASE_GUARD_MS - 1
        assertTrue(TextLeaseLedger.blocksHeal(c, TextLeaseLedger.generation()))
        now += 1
        assertFalse(TextLeaseLedger.blocksHeal(c, TextLeaseLedger.generation()))
    }

    @Test
    fun aDrainLoopThatKeepsFailing_blocksForAtMostTheGuardAfterItsThirdFailure() {
        repeat(TextLeaseLedger.MAX_UNSEEN_STREAK) { TextLeaseLedger.resolveUnseen(TextLeaseLedger.beginFetch(c, TextLeaseLedger.sessionEpoch())!!) }
        now += 100_000L
        repeat(5) { TextLeaseLedger.resolveUnseen(TextLeaseLedger.beginFetch(c, TextLeaseLedger.sessionEpoch())!!) }
        now += TextLeaseLedger.LEASE_GUARD_MS - 100_000L
        assertFalse(
            TextLeaseLedger.blocksHeal(c, TextLeaseLedger.generation()),
            "failures past the streak bound must not extend the block",
        )
    }

    @Test
    fun aCleanAnswer_resetsTheUnseenStreak() {
        repeat(TextLeaseLedger.MAX_UNSEEN_STREAK) { TextLeaseLedger.resolveUnseen(TextLeaseLedger.beginFetch(c, TextLeaseLedger.sessionEpoch())!!) }
        TextLeaseLedger.resolveClean(TextLeaseLedger.beginFetch(c, TextLeaseLedger.sessionEpoch())!!)
        now += TextLeaseLedger.LEASE_GUARD_MS
        TextLeaseLedger.resolveUnseen(TextLeaseLedger.beginFetch(c, TextLeaseLedger.sessionEpoch())!!)
        assertTrue(TextLeaseLedger.blocksHeal(c, TextLeaseLedger.generation()))
    }

    @Test
    fun aScrub_refusesEveryWriteFromAFetchThatBeganBeforeIt() {
        val m1 = TextLeaseLedger.beginFetch(c, TextLeaseLedger.sessionEpoch())!!
        val m2 = TextLeaseLedger.beginFetch(c, TextLeaseLedger.sessionEpoch())!!
        TextLeaseLedger.scrub()   // lock / wipe while both are in flight
        TextLeaseLedger.resolveLeased(m1, "tok-1")
        TextLeaseLedger.resolveUnseen(m2)
        assertFalse(TextLeaseLedger.blocksHeal(c, Long.MIN_VALUE), "a drain in flight across the lock re-added state")
    }

    @Test
    fun theProcessWideEnd_clearsTheLedger() {
        TextLeaseLedger.resolveLeased(TextLeaseLedger.beginFetch(c, TextLeaseLedger.sessionEpoch())!!, "tok-1")
        TextLeaseLedger.resolveUnseen(TextLeaseLedger.beginFetch(c, TextLeaseLedger.sessionEpoch())!!)
        MessageManager.endProcessReceiveSession()
        assertFalse(TextLeaseLedger.blocksHeal(c, Long.MIN_VALUE))
    }
}

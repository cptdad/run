package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// HUNG ONION-CIRCUIT RUNG (2026-10-08). Field signature (prod Android connects 1 + 7, device runs): `introduction circuit launched`, never `built` for
// 22–30 s (healthy: 0.4–1.0 s); mirror (iOS field run): `introduction complete`,
// no `rendezvous joined` for 26 s. Rung: CLOSECIRCUIT the hung circuit after
// 3 s (first of a kind; 6 s after) / 8 s so Tor retries it itself — no NEWNYM.
// Both platforms run this class.
// ---------------------------------------------------------------------------

class HsCircuitWatchdogTest {

    // Synthetic — NOT any real service.
    private val ours = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx"
    private val other = "zyxwvutsrqponmlkjihgfedcba765432zyxwvutsrqponmlkjihgfedc"
    private val path = "\$0123456789ABCDEF0123456789ABCDEF01234567~Guard"

    private fun w() = HsCircuitWatchdog()

    private fun HsCircuitWatchdog.feed(line: String, at: Long) = observeAt(line, ours, at)

    private fun introLaunched(id: String) = "650 CIRC $id LAUNCHED BUILD_FLAGS=IS_INTERNAL,NEED_CAPACITY,NEED_UPTIME PURPOSE=HS_CLIENT_INTRO HS_STATE=HSCI_CONNECTING TIME_CREATED=2026-10-08T10:00:00.000000"
    private fun introExtended(id: String, q: String = ours) = "650 CIRC $id EXTENDED $path BUILD_FLAGS=IS_INTERNAL PURPOSE=HS_CLIENT_INTRO HS_STATE=HSCI_CONNECTING REND_QUERY=$q"
    private fun introBuilt(id: String) = "650 CIRC $id BUILT $path PURPOSE=HS_CLIENT_INTRO HS_STATE=HSCI_CONNECTING REND_QUERY=$ours"
    private fun introSent(id: String) = "650 CIRC_MINOR $id PURPOSE_CHANGED $path PURPOSE=HS_CLIENT_INTRO HS_STATE=HSCI_INTRO_SENT REND_QUERY=$ours OLD_PURPOSE=HS_CLIENT_INTRO OLD_HS_STATE=HSCI_CONNECTING"
    private fun introDone(id: String) = "650 CIRC_MINOR $id PURPOSE_CHANGED $path PURPOSE=HS_CLIENT_INTRO HS_STATE=HSCI_DONE REND_QUERY=$ours OLD_PURPOSE=HS_CLIENT_INTRO OLD_HS_STATE=HSCI_INTRO_SENT"
    private fun rendLaunched(id: String) = "650 CIRC $id LAUNCHED BUILD_FLAGS=IS_INTERNAL,NEED_CAPACITY PURPOSE=HS_CLIENT_REND HS_STATE=HSCR_CONNECTING TIME_CREATED=2026-10-08T10:00:00.000000"
    private fun rendExtended(id: String) = "650 CIRC $id EXTENDED $path BUILD_FLAGS=IS_INTERNAL PURPOSE=HS_CLIENT_REND HS_STATE=HSCR_CONNECTING REND_QUERY=$ours"
    private fun rendIdle(id: String) = "650 CIRC_MINOR $id PURPOSE_CHANGED $path PURPOSE=HS_CLIENT_REND HS_STATE=HSCR_ESTABLISHED_IDLE REND_QUERY=$ours OLD_PURPOSE=HS_CLIENT_REND OLD_HS_STATE=HSCR_CONNECTING"
    private fun rendBuilt(id: String) = "650 CIRC $id BUILT $path PURPOSE=HS_CLIENT_REND HS_STATE=HSCR_CONNECTING REND_QUERY=$ours"
    private fun rendWaiting(id: String) = "650 CIRC_MINOR $id PURPOSE_CHANGED $path PURPOSE=HS_CLIENT_REND HS_STATE=HSCR_ESTABLISHED_WAITING REND_QUERY=$ours OLD_PURPOSE=HS_CLIENT_REND OLD_HS_STATE=HSCR_ESTABLISHED_IDLE"
    private fun rendJoined(id: String) = "650 CIRC_MINOR $id PURPOSE_CHANGED $path PURPOSE=HS_CLIENT_REND HS_STATE=HSCR_JOINED REND_QUERY=$ours OLD_PURPOSE=HS_CLIENT_REND OLD_HS_STATE=HSCR_ESTABLISHED_WAITING"

    private fun ids(d: HsCircuitWatchdog.Decision) = d.closures.map { it.commandArgument() }
    private fun kinds(d: HsCircuitWatchdog.Decision) = d.closures.map { it.kind }

    @Test
    fun tunedStallThresholdsAndCloseCaps_arePinned() {
        assertEquals(3_000L, HsCircuitWatchdog.HS_CIRCUIT_BUILD_STALL_FIRST_MS)
        assertEquals(6_000L, HsCircuitWatchdog.HS_CIRCUIT_BUILD_STALL_MS)
        assertEquals(8_000L, HsCircuitWatchdog.HS_REND_JOIN_STALL_MS)
        assertEquals(3_000L, HsCircuitWatchdog.HS_REND_ESTABLISH_STALL_MS)
        assertEquals(8_000L, HsCircuitWatchdog.HS_STREAM_CONNECT_STALL_MS)
        assertEquals(4, HsCircuitWatchdog.MAX_CLOSES_PER_TOR)
        assertEquals(2_000L, HsCircuitWatchdog.NEWNYM_GUARD_MS)
        assertEquals(2, HsCircuitWatchdog.CHANNEL_KICK_SAME_HOP_CLOSES)
        assertEquals(1, HsCircuitWatchdog.CHANNEL_KICK_MAX_PER_TOR)
        assertEquals(10_000L, HsCircuitWatchdog.CHANNEL_KICK_NEWNYM_SPACING_MS)
    }

    // --- intro stall ------------------------------------------------------

    @Test
    fun stalledIntro_isClosedAt3s() {
        val wd = w()
        assertEquals(3_000L, wd.feed(introLaunched("41"), at = 1_000))
        assertTrue(wd.dueAt(false, 3_999).closures.isEmpty(), "not yet")
        val d = wd.dueAt(false, 4_000)
        assertEquals(listOf("41"), ids(d))
        assertEquals(listOf(HsCircuitWatchdog.Closure.Kind.INTRO), kinds(d))
        assertTrue(wd.dueAt(false, 30_000).closures.isEmpty(), "never closed twice")
    }

    @Test
    fun extendedWithoutBuilt_alsoArms() {
        val wd = w()
        wd.feed(introExtended("42"), at = 0)
        assertEquals(listOf("42"), ids(wd.dueAt(false, 6_000)))
    }

    @Test
    fun builtAt5_9s_closesNothing() {
        val wd = w()
        wd.feed(introLaunched("43"), at = 0)
        wd.feed(introBuilt("43"), at = 5_900)
        assertTrue(wd.dueAt(false, 6_000).closures.isEmpty())
        assertTrue(wd.dueAt(false, 60_000).closures.isEmpty())
    }

    @Test
    fun introSentImpliesBuilt_closesNothing() {
        val wd = w()
        wd.feed(introLaunched("44"), at = 0)
        wd.feed(introSent("44"), at = 900)
        assertTrue(wd.dueAt(false, 10_000).closures.isEmpty())
    }

    @Test
    fun aFailedIntroIsNotClosedAgain() {
        val wd = w()
        wd.feed(introLaunched("45"), at = 0)
        wd.feed("650 CIRC 45 FAILED PURPOSE=HS_CLIENT_INTRO HS_STATE=HSCI_CONNECTING REASON=TIMEOUT", at = 3_000)
        assertTrue(wd.dueAt(false, 10_000).closures.isEmpty())
    }

    // --- rendezvous BUILD stall (rev b) ------------------

    @Test
    fun stalledRendezvousBuild_isClosedAt3s() {
        val wd = w()
        assertEquals(3_000L, wd.feed(rendLaunched("200"), at = 1_000))
        assertTrue(wd.dueAt(false, 3_999).closures.isEmpty(), "not yet")
        val d = wd.dueAt(false, 4_000)
        assertEquals(listOf("200"), ids(d))
        assertEquals(listOf(HsCircuitWatchdog.Closure.Kind.REND), kinds(d))
        assertTrue(wd.dueAt(false, 30_000).closures.isEmpty(), "never closed twice")
    }

    @Test
    fun rendezvousBuiltAt5_9s_closesNothing() {
        val wd = w()
        wd.feed(rendLaunched("201"), at = 0)
        wd.feed(rendExtended("201"), at = 2_000)   // a hop, not the build
        wd.feed(rendBuilt("201"), at = 5_900)
        wd.feed(rendIdle("201"), at = 6_100)       // acknowledged: the establish rule is satisfied too
        assertTrue(wd.dueAt(false, 6_000).closures.isEmpty())
        assertTrue(wd.dueAt(false, 60_000).closures.isEmpty())
    }

    @Test
    fun rendezvousEstablished_countsAsBuilt() {
        // A cannibalized rendezvous circuit may reach ESTABLISHED_IDLE without a
        // plain CIRC BUILT of its own.
        val wd = w()
        wd.feed(rendLaunched("202"), at = 0)
        wd.feed(rendIdle("202"), at = 800)
        assertTrue(wd.dueAt(false, 60_000).closures.isEmpty())
    }

    @Test
    fun introBuilt_rendezvousStalled_closesTheRendezvousNotTheIntro() {
        // The exact field timeline: descriptor received, rend + intro
        // launched together, intro built in 0.4 s, rend never built.
        val wd = w()
        wd.feed(rendLaunched("210"), at = 0)
        wd.feed(introLaunched("211"), at = 0)
        wd.feed(introBuilt("211"), at = 382)
        val d = wd.dueAt(false, 6_000)
        assertEquals(listOf("210"), ids(d))
        assertEquals(listOf(HsCircuitWatchdog.Closure.Kind.REND), kinds(d))
    }

    @Test
    fun afterTheClose_aNewRendezvousCircuitIsTrackedFresh() {
        val wd = w()
        wd.feed(rendLaunched("220"), at = 0)
        assertEquals(listOf("220"), ids(wd.dueAt(false, 6_000)))
        // Tor's own retry: a fresh rendezvous circuit, its own clock — and the
        // SECOND close of that kind waits the full 6 s (2026-10-26 escalation).
        assertEquals(6_000L, wd.feed(rendLaunched("221"), at = 6_100))
        assertTrue(wd.dueAt(false, 12_000).closures.isEmpty(), "fresh clock, not the old one")
        assertEquals(listOf("221"), ids(wd.dueAt(false, 12_100)))
    }

    // --- build-stall escalation (2026-10-26) -----------------------------------

    @Test
    fun firstBuildClosePerKindIs3s_thenEachKindWaits6s_independently() {
        val wd = w()
        wd.feed(introLaunched("300"), at = 0)
        wd.feed(rendLaunched("301"), at = 0)
        assertTrue(wd.dueAt(false, 2_999).closures.isEmpty(), "not yet")
        // Both kinds' FIRST stall closes at 3 s.
        assertEquals(listOf("300", "301"), ids(wd.dueAt(false, 3_000)))
        // Their replacements each get the full 6 s.
        assertEquals(6_000L, wd.feed(introLaunched("302"), at = 3_100))
        assertEquals(6_000L, wd.feed(rendLaunched("303"), at = 3_100))
        assertTrue(wd.dueAt(false, 9_000).closures.isEmpty(), "6 s clock now")
        assertEquals(listOf("302", "303"), ids(wd.dueAt(false, 9_100)))
    }

    @Test
    fun escalationIsPerKind_anIntroCloseLeavesTheRendezvousFirstCloseAt3s() {
        val wd = w()
        wd.feed(introLaunched("310"), at = 0)
        assertEquals(listOf("310"), ids(wd.dueAt(false, 3_000)))
        assertEquals(3_000L, wd.feed(rendLaunched("311"), at = 3_000), "rendezvous kind untouched")
        assertEquals(6_000L, wd.feed(introLaunched("312"), at = 3_000), "intro kind escalated")
        assertEquals(listOf("311"), ids(wd.dueAt(false, 6_000)))
        assertEquals(listOf("312"), ids(wd.dueAt(false, 9_000)))
    }

    @Test
    fun escalationSurvivesNewnym_butTheClearedCircuitDoesNotCount() {
        val wd = w()
        wd.feed(introLaunched("320"), at = 0)
        wd.noteNewnymAt(1_000)                       // killed it before any close
        assertEquals(3_000L, wd.feed(introLaunched("321"), at = 3_100), "no close happened: still 3 s")
        assertEquals(listOf("321"), ids(wd.dueAt(false, 6_100)))
        wd.noteNewnymAt(7_000)
        assertEquals(6_000L, wd.feed(introLaunched("322"), at = 9_100), "one intro close on record: 6 s")
    }

    @Test
    fun nextDeadline_followsThePerKindThreshold() {
        val wd = w()
        wd.feed(introLaunched("330"), at = 0)
        assertEquals(3_000L, wd.msUntilNextDeadlineAt(0))
        wd.dueAt(false, 3_000)
        wd.feed(introLaunched("331"), at = 3_000)
        assertEquals(6_000L, wd.msUntilNextDeadlineAt(3_000))
    }

    @Test
    fun buildRuleAndJoinRule_shareTheBudget_andNeverCloseTheSameCircuitTwice() {
        val wd = w()
        wd.feed(rendLaunched("230"), at = 0)       // will stall its build
        wd.feed(introDone("231"), at = 0)          // arms the join rule too
        val d = wd.dueAt(false, 8_000)
        assertEquals(listOf("230"), ids(d), "one close for the one hung circuit")
        wd.feed(introLaunched("232"), at = 10_000)
        wd.feed(introLaunched("233"), at = 10_000)
        wd.feed(introLaunched("235"), at = 10_000)
        val d2 = wd.dueAt(false, 16_000)
        assertEquals(3, d2.closures.size, "4 per process in total across every rule")
        wd.feed(rendLaunched("234"), at = 20_000)
        val d3 = wd.dueAt(false, 26_000)
        assertTrue(d3.closures.isEmpty())
        assertTrue(d3.budgetSpentNow)
    }

    // --- rendezvous JOIN stall ----------------------------------------------

    @Test
    fun introCompleteWithoutJoin_closesTheRendezvousCircuitAt8s() {
        val wd = w()
        wd.feed(rendBuilt("50"), at = 0)
        wd.feed(introLaunched("51"), at = 0)
        wd.feed(introBuilt("51"), at = 500)
        wd.feed(introSent("51"), at = 600)
        wd.feed(rendWaiting("50"), at = 600)
        assertEquals(8_000L, wd.feed(introDone("51"), at = 1_000))
        assertTrue(wd.dueAt(false, 8_999).closures.isEmpty())
        val d = wd.dueAt(false, 9_000)
        assertEquals(listOf("50"), ids(d))
        assertEquals(listOf(HsCircuitWatchdog.Closure.Kind.REND), kinds(d))
    }

    @Test
    fun rendezvousJoinedAt7s_closesNothing() {
        val wd = w()
        wd.feed(rendBuilt("52"), at = 0)
        wd.feed(introDone("53"), at = 0)
        wd.feed(rendJoined("52"), at = 7_000)
        assertTrue(wd.dueAt(false, 8_000).closures.isEmpty())
        assertTrue(wd.dueAt(false, 60_000).closures.isEmpty())
    }

    @Test
    fun prefersTheRendezvousCircuitWaitingForTheJoin() {
        val wd = w()
        wd.feed(rendBuilt("60"), at = 0)
        wd.feed(rendBuilt("61"), at = 100)
        wd.feed(rendWaiting("60"), at = 200)
        wd.feed(introDone("62"), at = 300)
        assertEquals(listOf("60"), ids(wd.dueAt(false, 8_300)))
    }

    // --- budget, NEWNYM, answer ------------------------------------------

    @Test
    fun budgetIsFourPerTorProcess_thenStops_reportingItOnce() {
        val wd = w()
        for (i in 1..6) wd.feed(introLaunched("7$i"), at = 0)
        val d = wd.dueAt(false, 6_000)
        assertEquals(4, d.closures.size)
        assertTrue(d.budgetSpentNow, "the first refused close reports the spent budget")
        wd.feed(introLaunched("80"), at = 10_000)
        val later = wd.dueAt(false, 16_000)
        assertTrue(later.closures.isEmpty())
        assertFalse(later.budgetSpentNow, "reported once only")
    }

    @Test
    fun newTorProcess_restoresTheBudget() {
        val wd = w()
        for (i in 1..3) wd.feed(introLaunched("9$i"), at = 0)
        assertEquals(3, wd.dueAt(false, 6_000).closures.size)
        wd.resetForNewTorProcess()
        wd.feed(introLaunched("99"), at = 10_000)
        assertEquals(listOf("99"), ids(wd.dueAt(false, 16_000)))
    }

    @Test
    fun newnymWithin2s_suppresses_andClearsTracking() {
        val wd = w()
        wd.feed(introLaunched("100"), at = 0)
        wd.noteNewnymAt(5_000)
        assertTrue(wd.dueAt(false, 6_000).closures.isEmpty(), "NEWNYM killed it; nothing tracked")
        // A circuit launched right after a NEWNYM fires on its own deadline; only
        // a deadline that lands INSIDE the guard is deferred to the guard's end.
        val wd3 = w()
        wd3.noteNewnymAt(0)
        wd3.feed(introLaunched("103"), at = 0)
        // deadline 6 000 is past the guard (2 000) → fires normally
        assertEquals(listOf("103"), ids(wd3.dueAt(false, 6_000)))
        val wd4 = w()
        wd4.feed(introLaunched("104"), at = 0)
        wd4.noteNewnymAt(5_000)
        wd4.feed(introLaunched("105"), at = 5_100)
        assertTrue(wd4.dueAt(false, 6_500).closures.isEmpty(), "inside the guard")
        assertEquals(listOf("105"), ids(wd4.dueAt(false, 11_100)))
    }

    @Test
    fun guardDeferral_isRescheduledByTheNextDeadline() {
        val wd = w()
        wd.feed(introLaunched("110"), at = 0)
        // A NEWNYM landing just before the deadline clears it (it killed the circuit).
        wd.noteNewnymAt(5_000)
        assertNull(wd.msUntilNextDeadlineAt(5_000), "nothing armed after NEWNYM")
        wd.feed(introLaunched("111"), at = 5_500)
        assertEquals(3_000L, wd.msUntilNextDeadlineAt(5_500))
    }

    @Test
    fun postFirstAnswer_neverFires_andDropsTracking() {
        val wd = w()
        wd.feed(introLaunched("120"), at = 0)
        wd.feed(rendBuilt("121"), at = 0)
        wd.feed(introDone("122"), at = 0)
        assertTrue(wd.dueAt(true, 60_000).closures.isEmpty())
        assertTrue(wd.dueAt(false, 60_000).closures.isEmpty(), "tracking was dropped at the answer")
    }

    // --- matching -----------------------------------------------------------

    @Test
    fun aDifferentOnionsCircuitNeverMatches() {
        val wd = w()
        wd.feed(introExtended("130", q = other), at = 0)
        assertTrue(wd.dueAt(false, 60_000).closures.isEmpty())
        // Accepted at LAUNCHED (no REND_QUERY yet), dropped once it names another service.
        wd.feed(introLaunched("131"), at = 0)
        wd.feed(introExtended("131", q = other), at = 300)
        assertTrue(wd.dueAt(false, 60_000).closures.isEmpty())
        // The `.onion` suffix form is still ours.
        val wd2 = w()
        wd2.feed(introExtended("132", q = "$ours.onion"), at = 0)
        assertEquals(listOf("132"), ids(wd2.dueAt(false, 6_000)))
    }

    @Test
    fun otherPurposesAndEvents_areIgnored() {
        val wd = w()
        assertNull(wd.feed("650 CIRC 140 LAUNCHED PURPOSE=GENERAL", at = 0))
        assertNull(wd.feed("650 CIRC 141 LAUNCHED PURPOSE=HS_CLIENT_HSDIR", at = 0))
        assertNull(wd.feed("650 STREAM 7 SENTCONNECT 12 $other.onion:80", at = 0), "another service's stream")
        assertNull(wd.feed("650 STREAM 8 SENTCONNECT 0 $ours.onion:80", at = 0), "unattached (circuit 0)")
        assertNull(wd.feed("650 STREAM 9 NEW 0 $ours.onion:80", at = 0))
        assertNull(wd.feed("650 HS_DESC REQUESTED $ours NO_AUTH $path", at = 0))
        assertNull(HsCircuitWatchdog().observeAt(introLaunched("142"), null, 0), "no relay address = inert")
        assertTrue(wd.dueAt(false, 60_000).closures.isEmpty())
    }

    @Test
    fun malformedCircuitIds_neverReachTheCommand() {
        val wd = w()
        assertNull(wd.feed(introLaunched("12a"), at = 0))
        assertNull(wd.feed(introLaunched("1\r\nSIGNAL"), at = 0))
        assertNull(wd.feed(introLaunched("12345678901"), at = 0))
        assertTrue(wd.dueAt(false, 60_000).closures.isEmpty())
        assertTrue(HsCircuitWatchdog.isValidCircuitId("1"))
        assertFalse(HsCircuitWatchdog.isValidCircuitId(""))
    }

    @Test
    fun unknownCircuitReply_isNotRetried() {
        // 552 ("Unknown circuit") = already gone. The decision already removed the
        // circuit from tracking and spent the unit when it was handed out, so the
        // platform has nothing to retry with: a second due() returns nothing.
        val wd = w()
        wd.feed(introLaunched("150"), at = 0)
        assertEquals(listOf("150"), ids(wd.dueAt(false, 6_000)))
        // (platform got 552 here)
        assertTrue(wd.dueAt(false, 12_000).closures.isEmpty())
    }

    @Test
    fun renderingCarriesNoCircuitId_andPhrasesAreFixed() {
        val wd = w()
        wd.feed(introLaunched("4242"), at = 0)
        val d = wd.dueAt(false, 6_000)
        for (s in listOf(d.toString(), d.closures.single().toString(), wd.toString())) {
            assertFalse(s.contains("4242"), s)
        }
        for (p in listOf(
            HsCircuitWatchdog.INTRO_PHRASE, HsCircuitWatchdog.REND_PHRASE, HsCircuitWatchdog.STREAM_PHRASE,
            HsCircuitWatchdog.BUDGET_SPENT_PHRASE, HsCircuitWatchdog.CHANNEL_KICK_PHRASE,
            HsCircuitWatchdog.CHANNEL_KICK_SKIP_PHRASE, HsCircuitWatchdog.SOCKS_MOVED_PHRASE,
            HsCircuitWatchdog.SOCKS_LOST_PHRASE,
        )) {
            assertFalse(p.any { it.isDigit() }, p)
        }
        assertEquals("introduction circuit stalled - closing it so Tor retries", HsCircuitWatchdog.INTRO_PHRASE)
        assertEquals("rendezvous circuit stalled - closing it so Tor retries", HsCircuitWatchdog.REND_PHRASE)
        assertEquals("circuit close budget spent", HsCircuitWatchdog.BUDGET_SPENT_PHRASE)
    }
    // --- ESTABLISH rule (2026-10-09) ----------------------

    private val pathA = "\$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA~GuardA,\$1111111111111111111111111111111111111111~Mid"
    private val pathB = "\$BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB~GuardB,\$2222222222222222222222222222222222222222~Mid"
    private fun rendBuiltVia(id: String, p: String) = "650 CIRC $id BUILT $p PURPOSE=HS_CLIENT_REND HS_STATE=HSCR_CONNECTING REND_QUERY=$ours"
    private fun introBuiltVia(id: String, p: String) = "650 CIRC $id BUILT $p PURPOSE=HS_CLIENT_INTRO HS_STATE=HSCI_CONNECTING REND_QUERY=$ours"
    private fun streamSent(sid: String, circ: String, host: String = "$ours.onion") = "650 STREAM $sid SENTCONNECT $circ $host:80"
    private fun streamStatus(sid: String, status: String, circ: String) = "650 STREAM $sid $status $circ $ours.onion:80"

    @Test
    fun builtRendezvousNeverAcknowledged_isClosedAt3s() {
        // The field timeline after NEWNYM 1: rend built (cannibalized, no
        // LAUNCHED), intro built 0.1 s later, no `introduction sent` for 34.8 s.
        val wd = w()
        assertEquals(3_000L, wd.feed(rendBuilt("300"), at = 48_000))
        wd.feed(introBuilt("301"), at = 48_118)
        assertTrue(wd.dueAt(false, 50_999).closures.isEmpty(), "not yet")
        val d = wd.dueAt(false, 51_000)
        assertEquals(listOf("300"), ids(d))
        assertEquals(listOf(HsCircuitWatchdog.Closure.Kind.REND), kinds(d))
        assertTrue(wd.dueAt(false, 90_000).closures.isEmpty(), "never closed twice")
    }

    @Test
    fun acknowledgedWithin3s_closesNothing() {
        val wd = w()
        wd.feed(rendBuilt("310"), at = 0)
        wd.feed(rendIdle("310"), at = 2_900)
        assertTrue(wd.dueAt(false, 60_000).closures.isEmpty())
    }

    @Test
    fun introductionSent_provesSomeRendezvousIsReady_andDisarmsTheEstablishRule() {
        // INTRODUCE1 goes out only over a READY rendezvous circuit, even if its
        // ESTABLISHED_IDLE event was rate-limited or missed.
        val wd = w()
        wd.feed(rendBuilt("320"), at = 0)
        wd.feed(rendBuilt("321"), at = 0)
        wd.feed(introSent("322"), at = 400)
        assertTrue(wd.dueAt(false, 3_000).closures.isEmpty())
        assertTrue(wd.dueAt(false, 60_000).closures.isEmpty())
    }

    @Test
    fun aFailedRendezvousIsNotClosedByTheEstablishRule() {
        val wd = w()
        wd.feed(rendBuilt("330"), at = 0)
        wd.feed("650 CIRC 330 CLOSED $path PURPOSE=HS_CLIENT_REND HS_STATE=HSCR_CONNECTING REASON=TIMEOUT", at = 1_000)
        assertTrue(wd.dueAt(false, 60_000).closures.isEmpty())
        assertNull(wd.msUntilNextDeadlineAt(1_000))
    }

    @Test
    fun establishDeadline_isScheduled() {
        val wd = w()
        wd.feed(rendBuilt("340"), at = 1_000)
        assertEquals(3_000L, wd.msUntilNextDeadlineAt(1_000))
    }

    // --- STREAM rule (2026-10-09) ----------------

    @Test
    fun streamWithoutConnected_closesItsCircuitAt8s() {
        val wd = w()
        assertEquals(8_000L, wd.feed(streamSent("17", "400"), at = 22_000))
        assertTrue(wd.dueAt(false, 29_999).closures.isEmpty(), "not yet")
        val d = wd.dueAt(false, 30_000)
        assertEquals(listOf("400"), ids(d), "the circuit the stream rides, never the stream id")
        assertEquals(listOf(HsCircuitWatchdog.Closure.Kind.STREAM), kinds(d))
        assertTrue(wd.dueAt(false, 60_000).closures.isEmpty(), "never closed twice")
    }

    @Test
    fun streamOutcomes_disarmTheRule() {
        for (status in listOf("SUCCEEDED", "FAILED", "CLOSED", "DETACHED")) {
            val wd = w()
            wd.feed(streamSent("18", "401"), at = 0)
            wd.feed(streamStatus("18", status, "401"), at = 7_900)
            assertTrue(wd.dueAt(false, 60_000).closures.isEmpty(), status)
        }
    }

    @Test
    fun twoStalledStreamsOnOneCircuit_closeItOnce() {
        val wd = w()
        wd.feed(streamSent("19", "402"), at = 0)
        wd.feed(streamSent("20", "402"), at = 100)
        val d = wd.dueAt(false, 8_100)
        assertEquals(listOf("402"), ids(d))
    }

    @Test
    fun streamRule_sharesTheBudget_andStopsAtTheFirstAnswer() {
        val wd = w()
        for (i in 1..5) wd.feed(streamSent("5$i", "50$i"), at = 0)
        val d = wd.dueAt(false, 8_000)
        assertEquals(HsCircuitWatchdog.MAX_CLOSES_PER_TOR, d.closures.size)
        assertTrue(d.budgetSpentNow)
        val wd2 = w()
        wd2.feed(streamSent("60", "600"), at = 0)
        assertTrue(wd2.dueAt(true, 8_000).closures.isEmpty(), "answered: the post-answer ladder owns it")
    }

    @Test
    fun aStreamToAnotherOnionOrAMalformedId_isIgnored() {
        val wd = w()
        assertNull(wd.feed(streamSent("21", "403", host = "$other.onion"), at = 0))
        assertNull(wd.feed(streamSent("x1", "403"), at = 0))
        assertNull(wd.feed(streamSent("22", "4\r\nSIGNAL"), at = 0))
        assertTrue(wd.dueAt(false, 60_000).closures.isEmpty())
    }

    @Test
    fun aNewnymDropsPendingStreams() {
        val wd = w()
        wd.feed(streamSent("23", "404"), at = 0)
        wd.noteNewnymAt(1_000)
        assertTrue(wd.dueAt(false, 60_000).closures.isEmpty())
    }

    // --- guard-channel kick DECISION -----------------------------------------

    @Test
    fun twoClosesOnTheSameFirstHop_makeTheKickDue() {
        val wd = w()
        wd.feed(rendBuiltVia("700", pathA), at = 0)
        val d1 = wd.dueAt(false, 3_000)
        assertEquals(listOf("700"), ids(d1))
        assertFalse(d1.channelKick, "one close is not evidence against a channel")
        wd.feed(rendBuiltVia("701", pathA), at = 3_500)
        val d2 = wd.dueAt(false, 6_500)
        assertEquals(listOf("701"), ids(d2))
        assertTrue(d2.channelKick, "the second close on the same first hop")
        // One kick per Tor process.
        wd.noteChannelKickAt(6_600)
        wd.feed(rendBuiltVia("702", pathA), at = 9_000)
        wd.feed(rendBuiltVia("703", pathA), at = 9_000)
        val d3 = wd.dueAt(false, 12_000)
        assertFalse(d3.channelKick)
    }

    @Test
    fun closesOnDifferentFirstHops_doNotKick() {
        val wd = w()
        wd.feed(rendBuiltVia("710", pathA), at = 0)
        wd.feed(rendBuiltVia("711", pathB), at = 0)
        val d = wd.dueAt(false, 3_000)
        assertEquals(2, d.closures.size)
        assertFalse(d.channelKick)
    }

    @Test
    fun aStreamCloseCountsAgainstItsCircuitsFirstHop() {
        val wd = w()
        wd.feed(introBuiltVia("720", pathA), at = 0)       // remembers hop A for 720
        wd.feed(streamSent("30", "720"), at = 0)
        assertFalse(wd.dueAt(false, 8_000).channelKick)
        wd.feed(rendBuiltVia("721", pathA), at = 8_100)
        assertTrue(wd.dueAt(false, 11_100).channelKick)
    }

    @Test
    fun budgetSpentWithAnotherStall_makesTheKickDue() {
        val wd = w()
        for (i in 1..5) wd.feed(introLaunched("73$i"), at = 0)   // no path: no hop evidence
        val d = wd.dueAt(false, 6_000)
        assertEquals(4, d.closures.size)
        assertTrue(d.budgetSpentNow)
        assertTrue(d.channelKick)
    }

    @Test
    fun theKick_renewsTheCloseBudget_soAStalledPostKickBuildIsClosedAgain() {
        // A20e 2026-10-12 (device-run cycles 152 s / 86 s): budget spent before the
        // kick, then the post-kick rendezvous never reports BUILT.
        val wd = w()
        for (i in 1..5) wd.feed(introLaunched("75$i"), at = 0)
        val spent = wd.dueAt(false, 6_000)
        assertTrue(spent.budgetSpentNow)
        assertTrue(spent.channelKick)
        assertTrue(wd.noteChannelKickAt(6_600), "spent budget renewed → the caller logs the line")
        wd.feed(rendLaunched("760"), at = 9_000)          // the fresh post-kick rendezvous
        val after = wd.dueAt(false, 15_100)
        assertEquals(listOf("760"), ids(after), "the post-kick stall is closed again")
        assertFalse(after.channelKick, "still one kick per Tor process")
        // Bounded: the renewed epoch spends at most MAX_CLOSES_PER_TOR more, then
        // reports spent once, and no second kick can renew it.
        for (i in 1..6) wd.feed(introLaunched("77$i"), at = 16_000)
        val again = wd.dueAt(false, 22_100)
        assertEquals(HsCircuitWatchdog.MAX_CLOSES_PER_TOR - 1, again.closures.size)
        assertTrue(again.budgetSpentNow)
        assertFalse(again.channelKick)
        assertEquals(1, HsCircuitWatchdog.CHANNEL_KICK_MAX_PER_TOR)
    }

    @Test
    fun aKickWithNothingSpent_reportsNoRenewal() {
        assertFalse(w().noteChannelKickAt(1_000))
        assertEquals("circuit close budget renewed after network reopen", HsCircuitWatchdog.BUDGET_RENEWED_PHRASE)
        assertFalse(HsCircuitWatchdog.BUDGET_RENEWED_PHRASE.any { it.isDigit() })
    }

    @Test
    fun theKickWaitsTenSecondsAfterANewnym_andIsRescheduled() {
        val wd = w()
        wd.feed(rendBuiltVia("740", pathA), at = 0)
        assertFalse(wd.dueAt(false, 3_000).channelKick)
        wd.noteNewnymAt(4_000)                               // hop evidence survives a NEWNYM
        wd.feed(rendBuiltVia("741", pathA), at = 6_100)
        val d = wd.dueAt(false, 9_100)
        assertEquals(listOf("741"), ids(d))
        assertFalse(d.channelKick, "only 5.1 s after the NEWNYM")
        assertEquals(4_900L, wd.msUntilNextDeadlineAt(9_100), "re-checked when the spacing ends")
        val later = wd.dueAt(false, 14_000)
        assertTrue(later.channelKick)
        assertTrue(later.closures.isEmpty())
        assertNull(wd.msUntilNextDeadlineAt(14_000))
    }

    @Test
    fun noKickAfterTheFirstAnswer_orAfterAFreshTorProcessResetsTheEvidence() {
        val wd = w()
        wd.feed(rendBuiltVia("750", pathA), at = 0)
        wd.dueAt(false, 3_000)
        wd.resetForNewTorProcess()
        wd.feed(rendBuiltVia("751", pathA), at = 4_000)
        assertFalse(wd.dueAt(false, 7_000).channelKick, "evidence died with the old process")
        val wd2 = w()
        wd2.feed(rendBuiltVia("752", pathA), at = 0)
        wd2.dueAt(false, 3_000)
        wd2.feed(rendBuiltVia("753", pathA), at = 3_100)
        assertFalse(wd2.dueAt(true, 6_100).channelKick, "answered")
    }

    @Test
    fun theFirstHopNeverAppearsInAnyRendering() {
        val wd = w()
        wd.feed(rendBuiltVia("760", pathA), at = 0)
        wd.dueAt(false, 3_000)
        wd.feed(rendBuiltVia("761", pathA), at = 3_100)
        val d = wd.dueAt(false, 6_100)
        for (s in listOf(d.toString(), wd.toString()) + d.closures.map { it.toString() }) {
            assertFalse(s.contains("AAAA"), s)
            assertFalse(s.contains("GuardA"), s)
            assertFalse(s.contains("761"), s)
        }
    }

    // ---- telemetry codes on the ladder's own lines (2026-10-09) ----

    @Test
    fun everyFixedKickPhrase_carriesItsOwnCode_andAnUnknownPhraseCarriesNone() {
        assertEquals(ConnectionLog.Code.GUARD_KICK, HsCircuitWatchdog.kickCode(HsCircuitWatchdog.CHANNEL_KICK_PHRASE))
        assertEquals(ConnectionLog.Code.GUARD_KICK_SKIP, HsCircuitWatchdog.kickCode(HsCircuitWatchdog.CHANNEL_KICK_SKIP_PHRASE))
        assertEquals(ConnectionLog.Code.SOCKS_MOVED, HsCircuitWatchdog.kickCode(HsCircuitWatchdog.SOCKS_MOVED_PHRASE))
        assertEquals(ConnectionLog.Code.SOCKS_LOST, HsCircuitWatchdog.kickCode(HsCircuitWatchdog.SOCKS_LOST_PHRASE))
        // A code is never invented from a string.
        assertNull(HsCircuitWatchdog.kickCode("guard connection stalled - something new"))
    }

    @Test
    fun theLadderCodes_stayUnderTheTelemetryNameCeiling() {
        // ConnectionLog's arithmetic is pinned to the longest existing name
        // (TOR_BOOTSTRAP_PROBLEM, 21 chars); none of the ladder's codes may become
        // the new longest.
        val ladder = listOf(
            ConnectionLog.Code.INTRO_CIRC_CLOSED, ConnectionLog.Code.REND_CIRC_CLOSED,
            ConnectionLog.Code.STREAM_CIRC_CLOSED, ConnectionLog.Code.CLOSE_BUDGET_SPENT,
            ConnectionLog.Code.GUARD_KICK, ConnectionLog.Code.GUARD_KICK_SKIP,
            ConnectionLog.Code.SOCKS_MOVED, ConnectionLog.Code.SOCKS_LOST,
        )
        for (c in ladder) assertTrue(c.name.length <= 18, c.name)
    }
}

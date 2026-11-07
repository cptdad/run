package com.vg.run

import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// SEVERAL ONION ADDRESSES FOR ONE RELAY — the descriptor race (2026-10-23).
// Hermetic: synthetic addresses, synthetic HS_DESC lines, no Tor. Both platforms
// drive the same RelayAddressRace, so these pin both.
//
// Pinned here:
//  • ONE address = today: no extra HSFETCH, every event feeds the hedge, no
//    switch, slot 1 is the base URL, the warm-up never waits.
//  • the FIRST `HS_DESC RECEIVED` of any address wins and becomes the base URL;
//    a FAILED of one address never ends the race;
//  • the winner is sticky across a Tor HS-state reset (NEWNYM / new process)
//    until the re-race decides;
//  • the hedge sees the race as ONE logical descriptor (budget not multiplied),
//    targets unresolved addresses round robin, and only the winner once decided;
//  • the watchdog parsers match ANY configured address and never leak one.
// ---------------------------------------------------------------------------

private val ADDR_A = "a".repeat(56)
private val ADDR_B = "b".repeat(56)
private val ADDR_C = "c".repeat(55) + "7"
private val URL_A = "http://$ADDR_A.onion"
private val URL_B = "http://$ADDR_B.onion"
private val URL_C = "http://$ADDR_C.onion"
private const val HSDIR = "\$0123456789ABCDEF0123456789ABCDEF01234567~SomeNick"

private fun hsDesc(action: String, address: String, tail: String = "") =
    "650 HS_DESC $action $address NO_AUTH $HSDIR descIdXYZ $tail".trimEnd()

class RelayAddressRaceTest {

    private fun RelayAddressRace.feed(action: String, address: String): RelayAddressRace.Observation =
        observe(assertNotNull(parseDescriptorEvent(hsDesc(action, address)), "event for a configured address"))

    // ---------------------------------------------------------- configuration

    @Test
    fun singleAddress_isTodaysFlowExactly() {
        val race = RelayAddressRace(listOf(URL_A))
        assertFalse(race.isRacing)
        assertEquals(1, race.slotCount)
        assertEquals(URL_A, race.currentBaseUrl())
        assertTrue(race.beginRace().isEmpty(), "one address: no extra HSFETCH, ever")
        // Every event goes to the hedge, nothing switches, nothing waits.
        for (action in listOf("REQUESTED", "REQUESTED", "FAILED", "RECEIVED", "REQUESTED")) {
            val o = race.feed(action, ADDR_A)
            assertTrue(o.feedHedge, "$action must reach the hedge as before")
            assertFalse(o.switched)
            assertEquals(-1, o.wonSlot)
        }
        assertFalse(race.needsWait(URL_A))
        assertEquals(URL_A, race.resolve(URL_A))
        assertEquals(0, race.hedgeTargetSlot())
        assertEquals(ADDR_A, race.hsFetchAddressAt(race.hedgeTargetSlot()))
    }

    @Test
    fun noRelay_andNonOnionRelay_neverRace() {
        val none = RelayAddressRace(emptyList())
        assertEquals("", none.currentBaseUrl())
        assertFalse(none.isRacing)
        assertTrue(none.hsFetchAddresses.isEmpty())
        // A clearnet debug loopback with stray extras: extras are ignored.
        val loop = RelayAddressRace(listOf("http://10.0.2.2:8080", URL_B))
        assertFalse(loop.isRacing)
        assertEquals("http://10.0.2.2:8080", loop.currentBaseUrl())
        assertTrue(loop.hsFetchAddresses.isEmpty())
        assertNull(loop.parseDescriptorEvent(hsDesc("RECEIVED", ADDR_B)))
    }

    @Test
    fun extras_mustBeCleanDistinctV3Onions_atMostThreeSlots() {
        val race = RelayAddressRace(
            listOf(URL_A, "", URL_A.uppercase(), "http://not-an-onion.example", "http://short.onion", URL_B, URL_C, "http://${"d".repeat(56)}.onion"),
        )
        assertEquals(listOf(URL_A, URL_B, URL_C), race.urls, "dupes / non-v3 skipped, capped at 3")
        assertEquals(RelayAddressRace.MAX_ADDRESSES, race.slotCount)
        assertEquals(listOf(ADDR_A, ADDR_B, ADDR_C), race.hsFetchAddresses)
    }

    // ---------------------------------------------------------- the race

    @Test
    fun beginRace_returnsEveryAddressOnce_perTorHsState() {
        val race = RelayAddressRace(listOf(URL_A, URL_B))
        assertEquals(listOf(ADDR_A, ADDR_B), race.beginRace())
        assertTrue(race.beginRace().isEmpty(), "idempotent: Connected + warm-up + control-up all call it")
        race.noteTorHsStateReset()
        assertEquals(listOf(ADDR_A, ADDR_B), race.beginRace(), "NEWNYM / new Tor process: race again")
    }

    @Test
    fun firstReceived_wins_andBecomesTheBaseUrl() {
        val race = RelayAddressRace(listOf(URL_A, URL_B))
        var switches = 0
        race.bindSwitchListener(this) { switches++ }
        race.beginRace()
        race.feed("REQUESTED", ADDR_A)
        race.feed("REQUESTED", ADDR_B)
        assertEquals(URL_A, race.currentBaseUrl(), "slot 1 until a winner")
        assertTrue(race.needsWait(URL_A))
        val won = race.feed("RECEIVED", ADDR_B)
        assertEquals(1, won.wonSlot)
        assertTrue(won.switched)
        assertTrue(won.feedHedge, "the winning RECEIVED closes the hedge's episode")
        assertEquals(1, switches, "the session aborts its in-flight probe once")
        assertEquals(URL_B, race.currentBaseUrl())
        assertEquals(URL_B, race.resolve(URL_A), "a URL captured earlier follows the winner")
        assertEquals("http://other.example", race.resolve("http://other.example"))
        assertFalse(race.needsWait(URL_A))
        // The late loser changes nothing.
        val late = race.feed("RECEIVED", ADDR_A)
        assertEquals(-1, late.wonSlot)
        assertFalse(late.switched)
        assertEquals(URL_B, race.currentBaseUrl())
        assertEquals(1, switches)
    }

    @Test
    fun slotOneWinning_isNotASwitch() {
        val race = RelayAddressRace(listOf(URL_A, URL_B))
        var switches = 0
        race.bindSwitchListener(this) { switches++ }
        race.beginRace()
        race.feed("REQUESTED", ADDR_A)
        race.feed("REQUESTED", ADDR_B)
        val won = race.feed("RECEIVED", ADDR_A)
        assertEquals(0, won.wonSlot)
        assertFalse(won.switched, "the probe already rides slot 1 — nothing to abort")
        assertEquals(0, switches)
    }

    @Test
    fun oneAddressFailing_doesNotEndTheRace() {
        val race = RelayAddressRace(listOf(URL_A, URL_B, URL_C))
        race.beginRace()
        listOf(ADDR_A, ADDR_B, ADDR_C).forEach { race.feed("REQUESTED", it) }
        race.feed("FAILED", ADDR_A)
        assertTrue(race.needsWait(URL_A), "two addresses still racing")
        assertEquals(URL_A, race.currentBaseUrl())
        race.feed("FAILED", ADDR_C)
        assertTrue(race.needsWait(URL_A))
        assertEquals(1, race.feed("RECEIVED", ADDR_B).wonSlot)
        assertEquals(URL_B, race.currentBaseUrl())
    }

    @Test
    fun everyAddressFailed_stopsTheWait_butARetryCanStillWin() {
        val race = RelayAddressRace(listOf(URL_A, URL_B))
        race.beginRace()
        race.feed("REQUESTED", ADDR_A)
        race.feed("REQUESTED", ADDR_B)
        race.feed("FAILED", ADDR_A)
        race.feed("FAILED", ADDR_B)
        assertFalse(race.needsWait(URL_A), "nothing left to wait for")
        // Tor's own retry (or a hedge) for B lands later: still the race's winner.
        race.feed("REQUESTED", ADDR_B)
        assertEquals(1, race.feed("RECEIVED", ADDR_B).wonSlot)
        assertEquals(URL_B, race.currentBaseUrl())
    }

    @Test
    fun winnerIsSticky_acrossAReset_untilTheReRaceDecides() {
        val race = RelayAddressRace(listOf(URL_A, URL_B))
        var switches = 0
        race.bindSwitchListener(this) { switches++ }
        race.beginRace()
        race.feed("REQUESTED", ADDR_A)
        race.feed("REQUESTED", ADDR_B)
        race.feed("RECEIVED", ADDR_B)
        race.noteTorHsStateReset()                       // NEWNYM accepted
        assertEquals(URL_B, race.currentBaseUrl(), "never back to a slower slot 1 meanwhile")
        assertFalse(race.needsWait(URL_A), "nothing begun yet in the new HS state: nothing to wait for")
        race.beginRace()
        assertTrue(race.needsWait(URL_A), "re-race begun: the new HS state has no descriptor yet")
        race.feed("REQUESTED", ADDR_A)
        race.feed("REQUESTED", ADDR_B)
        val won = race.feed("RECEIVED", ADDR_A)
        assertTrue(won.switched)
        assertEquals(URL_A, race.currentBaseUrl())
        assertEquals(2, switches)
    }

    @Test
    fun switchListener_isOwnedAndReplaceable() {
        val race = RelayAddressRace(listOf(URL_A, URL_B))
        val oldOwner = Any()
        val newOwner = Any()
        var oldCalls = 0
        var newCalls = 0
        race.bindSwitchListener(oldOwner) { oldCalls++ }
        race.bindSwitchListener(newOwner) { newCalls++ }
        race.unbindSwitchListener(oldOwner)              // a cleared session: must not unbind the new one
        race.beginRace()
        race.feed("REQUESTED", ADDR_B)
        race.feed("RECEIVED", ADDR_B)
        assertEquals(0, oldCalls)
        assertEquals(1, newCalls)
    }

    // ---------------------------------------------------------- the hedge

    @Test
    fun hedgeFeeding_openRaceFeedsAll_decidedRaceOnlyTheWinner() {
        val race = RelayAddressRace(listOf(URL_A, URL_B))
        race.beginRace()
        assertTrue(race.feed("REQUESTED", ADDR_A).feedHedge)
        assertTrue(race.feed("REQUESTED", ADDR_B).feedHedge)
        assertTrue(race.feed("RECEIVED", ADDR_B).feedHedge)
        // A's outstanding request was counted by the hedge: its outcome retires it.
        assertTrue(race.feed("FAILED", ADDR_A).feedHedge)
        // A loser's later REQUESTED is not the relay's descriptor miss…
        assertFalse(race.feed("REQUESTED", ADDR_A).feedHedge)
        // …and its outcome was never counted, so it is not fed either.
        assertFalse(race.feed("RECEIVED", ADDR_A).feedHedge)
        // The winner's own re-fetch is (Tor's refetch after a failed intro).
        assertTrue(race.feed("REQUESTED", ADDR_B).feedHedge)
        assertTrue(race.feed("RECEIVED", ADDR_B).feedHedge)
    }

    @Test
    fun hedgeTarget_roundRobinsTheUnresolved_thenOnlyTheWinner() {
        val race = RelayAddressRace(listOf(URL_A, URL_B, URL_C))
        race.beginRace()
        listOf(ADDR_A, ADDR_B, ADDR_C).forEach { race.feed("REQUESTED", it) }
        race.feed("FAILED", ADDR_B)
        assertEquals(listOf(0, 2, 0, 2), List(4) { race.hedgeTargetSlot() }, "skips the failed address")
        race.feed("RECEIVED", ADDR_C)
        assertEquals(listOf(2, 2), List(2) { race.hedgeTargetSlot() }, "decided: hedge the winner only")
    }

    @Test
    fun twoAddressRace_deferstheOneSecondHedge_andAWinCancelsEverything() {
        // The race's two fetches fill the hedge's in-flight cap of 2: the 1 s
        // bare hedge waits until both look dead (4 s) — the race IS the overlap.
        val race = RelayAddressRace(listOf(URL_A, URL_B))
        val hedge = DescriptorHedge()
        fun feed(action: String, address: String, now: Long) {
            val event = race.parseDescriptorEvent(hsDesc(action, address))!!
            if (race.observe(event).feedHedge) hedge.observe(event.action, now)
        }
        race.beginRace()
        feed("REQUESTED", ADDR_A, 0)
        feed("REQUESTED", ADDR_B, 5)
        assertNull(hedge.due(1_000, relayAnswered = false, hedgeEnabled = true).stage, "no 1 s hedge: two racing fetches in flight")
        assertEquals(4_000L - 1_000L, hedge.msUntilNextCheck(1_000), "next check when the oldest racing fetch is presumed dead")
        feed("RECEIVED", ADDR_B, 2_000)
        val d = hedge.due(4_000, relayAnswered = false, hedgeEnabled = true)
        assertNull(d.stage, "a winner closes the episode")
        assertFalse(hedge.due(12_000, relayAnswered = false, hedgeEnabled = true).stageStalled, "no descriptor-stage NEWNYM")
        assertEquals(0, hedge.spentThisSession)
    }

    @Test
    fun twoAddressRace_bothStalled_hedgesAt4s_andStageStallsAt10s() {
        val race = RelayAddressRace(listOf(URL_A, URL_B))
        val hedge = DescriptorHedge()
        race.beginRace()
        for (address in listOf(ADDR_A, ADDR_B)) {
            val event = race.parseDescriptorEvent(hsDesc("REQUESTED", address))!!
            if (race.observe(event).feedHedge) hedge.observe(event.action, 0)
        }
        val first = hedge.due(4_000, relayAnswered = false, hedgeEnabled = true)
        assertEquals(DescriptorHedge.Stage.FIRST, first.stage)
        assertEquals(0, race.hedgeTargetSlot(), "first hedge: slot 1")
        assertTrue(hedge.due(10_000, relayAnswered = false, hedgeEnabled = true).stageStalled,
            "no address produced a descriptor in 10 s: the session may spend its NEWNYM")
    }

    @Test
    fun singleAddress_hedgeTimelineIsUnchanged() {
        val race = RelayAddressRace(listOf(URL_A))
        val hedge = DescriptorHedge()
        val event = race.parseDescriptorEvent(hsDesc("REQUESTED", ADDR_A))!!
        assertTrue(race.observe(event).feedHedge)
        hedge.observe(event.action, 0)
        assertEquals(DescriptorHedge.Stage.FIRST, hedge.due(1_000, relayAnswered = false, hedgeEnabled = true).stage)
    }

    // ---------------------------------------------------------- waiting

    @Test
    fun awaitWinner_returnsAtOnceWithoutARace_andWhenDecided() = runTest {
        assertEquals(0L, RelayAddressRace(listOf(URL_A)).awaitWinner(URL_A, 15_000))
        val race = RelayAddressRace(listOf(URL_A, URL_B))
        race.beginRace()
        race.feed("REQUESTED", ADDR_A)
        race.feed("REQUESTED", ADDR_B)
        launch {
            delay(1_500)
            race.feed("RECEIVED", ADDR_B)
        }
        race.awaitWinner(URL_A, 15_000)
        assertEquals(URL_B, race.currentBaseUrl(), "the waiter woke on the decision, not the timeout")
        assertEquals(0L, race.awaitWinner(URL_A, 15_000), "decided: no further wait")
    }

    @Test
    fun aRaceThatWasNeverBegun_isNeverWaitedFor() = runTest {
        // No control channel → no HSFETCH → no decision can come: the warm-up
        // must not sit out the wait bound.
        val race = RelayAddressRace(listOf(URL_A, URL_B))
        assertFalse(race.needsWait(URL_A))
        assertEquals(0L, race.awaitWinner(URL_A, 15_000))
    }

    @Test
    fun awaitWinner_isBounded() = runTest {
        val race = RelayAddressRace(listOf(URL_A, URL_B))
        race.beginRace()
        race.awaitWinner(URL_A, 15_000)                   // never decided: returns at the bound
        assertTrue(race.needsWait(URL_A))
        assertEquals(URL_A, race.currentBaseUrl())
    }

    // ---------------------------------------------------------- the parsers

    @Test
    fun parseEvent_matchesAnyConfiguredAddress_andCarriesOnlyTheSlot() {
        val list = listOf<String?>(ADDR_A, ADDR_B)
        assertEquals(0, RelayDescriptorWatchdog.parseEvent(hsDesc("REQUESTED", ADDR_A), list)!!.slot)
        assertEquals(1, RelayDescriptorWatchdog.parseEvent(hsDesc("RECEIVED", ADDR_B.uppercase()), list)!!.slot)
        assertNull(RelayDescriptorWatchdog.parseEvent(hsDesc("RECEIVED", ADDR_C), list), "another service")
        assertNull(RelayDescriptorWatchdog.parseEvent(hsDesc("RECEIVED", ADDR_A), listOf<String?>(null)))
        // The single-address form still means slot 1.
        assertEquals(0, RelayDescriptorWatchdog.parseEvent(hsDesc("RECEIVED", ADDR_A), ADDR_A)!!.slot)
        val failed = RelayDescriptorWatchdog.parseEvent(hsDesc("FAILED", ADDR_B, "REASON=NOT_FOUND"), list)!!
        assertEquals("NOT_FOUND", failed.failureReason)
    }

    @Test
    fun nothingRendered_carriesAnAddressOrAFingerprint() {
        val race = RelayAddressRace(listOf(URL_A, URL_B))
        race.beginRace()
        val event = race.parseDescriptorEvent(hsDesc("RECEIVED", ADDR_B))!!
        val rendered = listOf(race.toString(), event.toString(), race.observe(event).toString(),
            RelayAddressRace.startedPhrase(2), RelayAddressRace.wonPhrase(2, 2))
        for (text in rendered) {
            for (secret in listOf(ADDR_A, ADDR_B, ".onion", "0123456789ABCDEF", "SomeNick")) {
                assertFalse(text.contains(secret, ignoreCase = true), "'$text' leaks '$secret'")
            }
        }
        assertEquals("descriptor race started (2 addresses)", RelayAddressRace.startedPhrase(2))
        assertEquals("descriptor race won by address 2 of 2", RelayAddressRace.wonPhrase(2, 2))
    }

    @Test
    fun raceLines_areUncoded_soTheTelemetryAllowlistNeverSeesThem() {
        ConnectionLog.clear()
        val race = RelayAddressRace(listOf(URL_A, URL_B))
        race.beginRace()
        race.feed("REQUESTED", ADDR_B)
        race.feed("RECEIVED", ADDR_B)
        val lines = ConnectionLog.snapshot().filter { it.text.startsWith("descriptor race") }
        assertEquals(2, lines.size)
        assertTrue(lines.all { it.code == null }, "no new ConnectionLog code (relay allowlist)")
        for (line in lines) assertFalse(line.text.contains(ADDR_A) || line.text.contains(ADDR_B))
        ConnectionLog.clear()
    }

    @Test
    fun circuitWatchdog_matchesAnyConfiguredAddress() {
        val wd = HsCircuitWatchdog()
        val introB = "650 CIRC 77 LAUNCHED BUILD_FLAGS=IS_INTERNAL,NEED_CAPACITY,NEED_UPTIME PURPOSE=HS_CLIENT_INTRO HS_STATE=HSCI_CONNECTING REND_QUERY=$ADDR_B"
        assertNotNull(wd.observeAtAll(introB, listOf(ADDR_A, ADDR_B), 0), "a circuit to address 2 is ours")
        val wd2 = HsCircuitWatchdog()
        assertNull(wd2.observeAtAll(introB, listOf(ADDR_A), 0), "with only address 1 configured it is another service's")
        val streamB = "650 STREAM 9 SENTCONNECT 77 $ADDR_B.onion:80"
        assertNotNull(HsCircuitWatchdog().observeAtAll(streamB, listOf(ADDR_A, ADDR_B), 0))
        assertNull(HsCircuitWatchdog().observeAtAll(streamB, listOf(ADDR_A), 0))
    }

    @Test
    fun ledgerSet_routesBySlot() {
        val race = RelayAddressRace(listOf(URL_A, URL_B))
        val set = HsDirLedgerSet(race.slotCount)
        set.observe(race.parseDescriptorEvent(hsDesc("RECEIVED", ADDR_B))!!)
        assertNull(set.forSlot(0).pinnedServerArgument(), "address 1's HSDirs learnt nothing")
        assertNotNull(set.forSlot(1).pinnedServerArgument(), "address 2's good HSDir is pinned for address 2 only")
        set.resetForNewTorProcess()
        assertNull(set.forSlot(1).pinnedServerArgument())
        assertTrue(set.forSlot(7) === set.forSlot(0), "out of range falls back to slot 1")
    }

    // ------------------------------------------- warm return (iOS keep-alive)

    @Test
    fun decidedThisState_tracksTheCurrentHsStatesWinner() {
        // The iOS warm return re-runs ONLY an undecided race: a decided one means
        // a descriptor is in Tor's cache and must not be refetched.
        val race = RelayAddressRace(listOf(URL_A, URL_B))
        assertFalse(race.decidedThisState(), "nothing raced yet")
        race.beginRace()
        assertFalse(race.decidedThisState(), "begun, still open")
        race.feed("REQUESTED", ADDR_A)
        race.feed("FAILED", ADDR_A)
        assertFalse(race.decidedThisState(), "one failure never decides")
        race.feed("RECEIVED", ADDR_B)
        assertTrue(race.decidedThisState())
        race.noteTorHsStateReset()
        assertFalse(race.decidedThisState(), "a NEWNYM purged the cache: undecided again")
        assertEquals(1, race.currentSlot(), "...while the winner stays sticky")
        assertEquals(2, race.beginRace().size, "and the re-run races every address again")
    }

    @Test
    fun decidedThisState_isAlwaysTrueForASingleAddress() {
        val race = RelayAddressRace(listOf(URL_A))
        assertTrue(race.decidedThisState(), "one address: nothing to re-run")
        race.noteTorHsStateReset()
        assertTrue(race.decidedThisState())
    }
}

// ---------------------------------------------------------------------------
// The generated config (shared/build.gradle.kts generateRelayUrl) — asserted on
// the ACTUAL constants compiled into this test run. Values are never printed.
// ---------------------------------------------------------------------------
class RelayUrlListGenerationTest {

    @Test
    fun slotOne_isTodaysConstant_andListsAreBoundedAndDistinct() {
        if (RELAY_URL_FROM_PROPERTIES.isEmpty()) assertTrue(RELAY_URLS_FROM_PROPERTIES.isEmpty())
        else assertTrue(RELAY_URLS_FROM_PROPERTIES.first() == RELAY_URL_FROM_PROPERTIES, "prod slot 1 drifted")
        if (RELAY_DEV_URL_FROM_PROPERTIES.isEmpty()) assertTrue(RELAY_DEV_URLS_FROM_PROPERTIES.isEmpty(), "scrub must empty every dev slot")
        else assertTrue(RELAY_DEV_URLS_FROM_PROPERTIES.first() == RELAY_DEV_URL_FROM_PROPERTIES, "dev slot 1 drifted")
        for (list in listOf(RELAY_URLS_FROM_PROPERTIES, RELAY_DEV_URLS_FROM_PROPERTIES)) {
            assertTrue(list.size <= RelayAddressRace.MAX_ADDRESSES)
            assertEquals(list.size, list.map { it.lowercase().trimEnd('/') }.distinct().size, "duplicate slot")
            assertTrue(list.none { it.isEmpty() })
            assertTrue(list.none { it.contains(',') || it != it.trim() }, "the comma list must be split and trimmed")
        }
    }

    @Test
    fun noDevEntry_equalsAnyProdEntry() {
        val prod = RELAY_URLS_FROM_PROPERTIES.map { it.lowercase().trimEnd('/') }.toSet()
        assertTrue(RELAY_DEV_URLS_FROM_PROPERTIES.none { it.lowercase().trimEnd('/') in prod }, "a dev address sits in the prod list")
    }

    @Test
    fun extraSlots_areV3Onions_ofAnOnionSlotOne() {
        for (list in listOf(RELAY_URLS_FROM_PROPERTIES, RELAY_DEV_URLS_FROM_PROPERTIES)) {
            if (list.size < 2) continue
            assertTrue(list.all { RelayWarmup.v3OnionAddress(it) != null }, "every racing slot must be a v3 onion")
            assertTrue(RelayAddressRace(list).isRacing)
            assertEquals(list.size, RelayAddressRace(list).slotCount)
        }
    }
}

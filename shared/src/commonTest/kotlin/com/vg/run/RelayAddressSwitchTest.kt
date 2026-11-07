package com.vg.run

import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// SEVERAL ONION ADDRESSES (2026-10-23) — what the SESSION does with the race's
// decision:
//  • MessageManager.noteRelayAddressSwitched aborts the in-flight probe (it is
//    queued on the losing address's descriptor) and re-probes AT ONCE, booked as
//    neither a timeout nor a success — same contract as the NEWNYM abort — and
//    says so with its own uncoded panel phrase;
//  • the pre-unlock warm-up waits (bounded) for the race and sends its ONE GET to
//    the winner; with one address it never waits and its request is unchanged.
// ---------------------------------------------------------------------------

private val SW_A = "http://${"a".repeat(56)}.onion"
private val SW_B = "http://${"b".repeat(56)}.onion"
private val SW_ADDR_A = "a".repeat(56)
private val SW_ADDR_B = "b".repeat(56)
private const val SW_HSDIR = "\$0123456789ABCDEF0123456789ABCDEF01234567~N"

/** The first opted-in GET is aborted by a relay-address switch mid-flight; then it answers. */
private class SwitchMidFlightRelay : FakeRelayHttp() {
    lateinit var mgr: MessageManager
    val getFlags: List<Boolean> get() = requestsOf("GET").map { it.cancelOnNewCircuit }
    var cancels = 0
    init {
        onGet = {
            if (requestsOf("GET").size == 1) {
                mgr.noteRelayAddressSwitched()
                HttpResult(code = -1, body = "Canceled", isSuccess = false)
            } else RELAY_WARM_404
        }
        onCancelNewCircuit = { cancels++; 1 }
    }
}

private class UrlRecordingRelay : FakeRelayHttp(
    onPost = { throw AssertionError("no POST") },
    onPut = { throw AssertionError("no PUT") },
) {
    val gets: List<Pair<String, Int>> get() = requestsOf("GET").map { it.url to it.timeoutSeconds }
}

class RelayAddressSwitchTest {

    @Test
    fun switchMidProbe_abortsAndReprobesAtOnce_unbooked() {
        ConnectionLog.clear()
        val relay = SwitchMidFlightRelay()
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", relay)
        relay.mgr = mgr
        assertTrue(mgr.isRelayReachable(), "the re-probe on the winner answers")
        assertEquals(2, relay.getFlags.size, "abandoned attempt + one immediate re-probe")
        assertEquals(1, relay.cancels, "the in-flight probe was aborted")
        assertEquals(0, mgr.consecutiveFullBudgetProbeTimeouts(), "not a timeout")
        val texts = ConnectionLog.snapshot().map { it.text }
        val abandoned = ConnectionLog.snapshot().single { it.text.contains("abandoned") }
        assertTrue(abandoned.text.startsWith("probe #1: abandoned for a faster relay address in "), abandoned.text)
        assertEquals(null, abandoned.code, "uncoded: never reaches the telemetry allowlist")
        assertFalse(texts.any { it.contains("after NEWNYM") }, "a switch is not a NEWNYM")
        ConnectionLog.clear()
    }

    @Test
    fun abandonedPhrases_areFixedTextPlusNumbers() {
        assertEquals("probe #3: abandoned after NEWNYM in 1.5 s - re-probing",
            MessageManager.abandonedProbePhrase(3, 1_500, addressSwitched = false))
        assertEquals("probe #3: abandoned for a faster relay address in 1.5 s - re-probing",
            MessageManager.abandonedProbePhrase(3, 1_500, addressSwitched = true))
    }

    @Test
    fun aUrlThatIsNotARaceAddress_isUsedVerbatim() {
        // Every unit test hands MessageManager its own URL; the process-wide race
        // must never rewrite it.
        val relay = UrlRecordingRelay()
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", relay)
        assertTrue(mgr.isRelayReachable())
        assertEquals("http://relay.test", relay.gets.single().first)
    }

    @Test
    fun warmup_singleAddress_neverWaits_andIsUnchanged() = runTest {
        val relay = UrlRecordingRelay()
        val attempt = RelayWarmup.warmAttempt(relay, SW_A, RelayAddressRace(listOf(SW_A)))
        assertTrue(attempt.answered)
        assertEquals(listOf("$SW_A/" to RelayWarmup.HTTP_TIMEOUT_SECONDS), relay.gets)
        // And with no race at all (the public entry in a process without one).
        val relay2 = UrlRecordingRelay()
        RelayWarmup.warmAttempt(relay2, SW_A, null)
        assertEquals(listOf("$SW_A/" to RelayWarmup.HTTP_TIMEOUT_SECONDS), relay2.gets)
    }

    @Test
    fun warmup_waitsForTheRace_andGetsTheWinner() = runTest {
        val race = RelayAddressRace(listOf(SW_A, SW_B))
        race.beginRace()
        listOf(SW_ADDR_A, SW_ADDR_B).forEach {
            race.observe(race.parseDescriptorEvent("650 HS_DESC REQUESTED $it NO_AUTH $SW_HSDIR")!!)
        }
        launch {
            delay(1_200)
            race.observe(race.parseDescriptorEvent("650 HS_DESC RECEIVED $SW_ADDR_B NO_AUTH $SW_HSDIR")!!)
        }
        val relay = UrlRecordingRelay()
        assertTrue(RelayWarmup.warmAttempt(relay, SW_A, race).answered)
        val (url, timeout) = relay.gets.single()
        assertEquals("$SW_B/", url, "the GET rides the address whose descriptor arrived first")
        assertTrue(timeout in RelayWarmup.RACE_MIN_GET_SECONDS..RelayWarmup.HTTP_TIMEOUT_SECONDS)
    }

    @Test
    fun warmup_raceNeverDecides_stillSendsOneBoundedGetToSlotOne() = runTest {
        val race = RelayAddressRace(listOf(SW_A, SW_B))
        race.beginRace()
        val relay = UrlRecordingRelay()
        RelayWarmup.warmAttempt(relay, SW_A, race)
        val (url, timeout) = relay.gets.single()
        assertEquals("$SW_A/", url)
        assertTrue(timeout >= RelayWarmup.RACE_MIN_GET_SECONDS)
        assertTrue(RelayAddressRace.WARMUP_WAIT_MAX_MS / 1000 + RelayWarmup.RACE_MIN_GET_SECONDS <= RelayWarmup.HTTP_TIMEOUT_SECONDS,
            "wait + GET floor fit the warm-up's own budget, so the C5 classification is unchanged")
    }
}

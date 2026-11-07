package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// Push registration × the relay address race (2026-10-24). Hermetic: synthetic
// onion addresses, synthetic HS_DESC lines, an injected sleep — no Tor, no clock.
//
// Pinned here:
//  • every PUT/DELETE resolves its base URL AT REQUEST TIME — a caller that
//    captured slot 1 (or an older winner) once follows the current winner, also
//    when the winner switches between two PUTs of the same loop;
//  • a batch waits — bounded — while a race begun in this Tor HS state is
//    undecided, and stops waiting the moment it decides;
//  • one address / a URL that is not one of the race's / no race: no wait, no
//    sleep, URL verbatim (today's behaviour exactly).
// ---------------------------------------------------------------------------

private val PR_ADDR_A = "a".repeat(56)
private val PR_ADDR_B = "b".repeat(56)
private val PR_URL_A = "http://$PR_ADDR_A.onion"
private val PR_URL_B = "http://$PR_ADDR_B.onion"
private const val PR_HSDIR = "\$0123456789ABCDEF0123456789ABCDEF01234567~SomeNick"
private const val PR_INBOX_1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
private const val PR_INBOX_2 = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
private const val PR_CAP = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
private const val PR_TOKEN = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd"

private fun RelayAddressRace.feedReceived(address: String) {
    observe(assertNotNull(parseDescriptorEvent("650 HS_DESC RECEIVED $address NO_AUTH $PR_HSDIR descIdXYZ")))
}

/** Records PUT / DELETE URLs; [afterPut] runs after each PUT (to switch the race mid-loop). */
private class UrlRecorder(afterPut: (Int) -> Unit = {}) : FakeRelayHttp(
    onPost = { throw AssertionError("no POST") },
    onGet = { throw AssertionError("no GET") },
    onDelete = { HttpResult(200, null, true) },
) {
    val urls: List<String> get() = requests.filter { it.method == "PUT" || it.method == "DELETE" }.map { it.url }
    init { onPut = { afterPut(urls.size); HttpResult(200, null, true) } }
}

class PushRegistrationRaceTest {

    private fun racing(): RelayAddressRace = RelayAddressRace(listOf(PR_URL_A, PR_URL_B))

    @Test
    fun register_capturedSlot1_goesToTheDecidedWinner() {
        val race = racing()
        race.beginRace()
        race.feedReceived(PR_ADDR_B)
        val http = UrlRecorder()
        assertTrue(PushRegistration.register(http, PR_URL_A, PR_INBOX_1, PR_CAP, PR_TOKEN, "sandbox", race = race))
        assertEquals(listOf("$PR_URL_B/inbox/$PR_INBOX_1/push"), http.urls)
    }

    @Test
    fun register_followsAWinnerSwitchBetweenTwoPutsOfOneLoop() {
        val race = racing()
        race.beginRace()
        // The race decides for address 2 right after the FIRST PUT went out.
        val http = UrlRecorder(afterPut = { n -> if (n == 1) race.feedReceived(PR_ADDR_B) })
        val captured = PR_URL_A   // what a caller read ONCE before the loop
        for (inbox in listOf(PR_INBOX_1, PR_INBOX_2)) {
            PushRegistration.register(http, captured, inbox, PR_CAP, PR_TOKEN, "sandbox", race = race)
        }
        assertEquals(
            listOf("$PR_URL_A/inbox/$PR_INBOX_1/push", "$PR_URL_B/inbox/$PR_INBOX_2/push"),
            http.urls,
        )
    }

    @Test
    fun unregister_resolvesPerRequest() {
        val race = racing()
        race.beginRace()
        race.feedReceived(PR_ADDR_B)
        val http = UrlRecorder()
        val failures = PushRegistration.unregisterAllReturningFailures(
            http, PR_URL_A, listOf(InboundInboxRef(PR_INBOX_1, PR_CAP), InboundInboxRef(PR_INBOX_2, PR_CAP)),
            race = race, sleep = { throw AssertionError("decided race must not wait") },
        )
        assertTrue(failures.isEmpty())
        assertEquals(listOf("$PR_URL_B/inbox/$PR_INBOX_1/push", "$PR_URL_B/inbox/$PR_INBOX_2/push"), http.urls)
    }

    @Test
    fun await_undecidedRace_waitsUntilItDecides() {
        val race = racing()
        race.beginRace()
        var sleeps = 0
        val waited = PushRegistration.awaitRelayAddressDecided(PR_URL_A, maxMs = 15_000, race = race, sleep = {
            sleeps++
            if (sleeps == 3) race.feedReceived(PR_ADDR_B)
        })
        assertEquals(3, sleeps)
        assertEquals(300L, waited)
        assertEquals(PR_URL_B, race.resolve(PR_URL_A))
    }

    @Test
    fun await_isBounded_whenTheRaceNeverDecides() {
        val race = racing()
        race.beginRace()
        var slept = 0L
        val waited = PushRegistration.awaitRelayAddressDecided(PR_URL_A, maxMs = 1_050, race = race, sleep = { slept += it })
        assertEquals(1_050L, waited)
        assertEquals(1_050L, slept)
    }

    @Test
    fun await_neverSleeps_withoutAnOpenRace() {
        val noSleep: (Long) -> Unit = { throw AssertionError("must not sleep") }
        // No race object at all (single address / not initialised).
        assertEquals(0L, PushRegistration.awaitRelayAddressDecided(PR_URL_A, race = null, sleep = noSleep))
        // One address: never races.
        val single = RelayAddressRace(listOf(PR_URL_A))
        single.beginRace()
        assertEquals(0L, PushRegistration.awaitRelayAddressDecided(PR_URL_A, race = single, sleep = noSleep))
        // Several addresses but no race begun (no control channel): nothing to wait for.
        assertEquals(0L, PushRegistration.awaitRelayAddressDecided(PR_URL_A, race = racing(), sleep = noSleep))
        // A URL that is not one of the race's (unit-test relay): verbatim, no wait.
        val open = racing().also { it.beginRace() }
        assertEquals(0L, PushRegistration.awaitRelayAddressDecided("http://relay.test", race = open, sleep = noSleep))
        val http = UrlRecorder()
        PushRegistration.register(http, "http://relay.test", PR_INBOX_1, PR_CAP, PR_TOKEN, "sandbox", race = open)
        assertEquals(listOf("http://relay.test/inbox/$PR_INBOX_1/push"), http.urls)
    }

    @Test
    fun unregisterAll_raceWaitZero_neverSleeps_evenWhenUndecided() {
        val race = racing()
        race.beginRace()
        val http = UrlRecorder()
        PushRegistration.unregisterAllReturningFailures(
            http, PR_URL_A, listOf(InboundInboxRef(PR_INBOX_1, PR_CAP)),
            race = race, sleep = { throw AssertionError("raceWaitMaxMs = 0 must not sleep") }, raceWaitMaxMs = 0,
        )
        // Undecided: the current (sticky) slot — slot 1 here.
        assertEquals(listOf("$PR_URL_A/inbox/$PR_INBOX_1/push"), http.urls)
    }
}

// The opt-out ladder's transport re-acquire (chain:push Case A, 2026-10-24).
class PushDeregTransportWaitTest {

    @Test
    fun present_returnsAtOnce() = kotlinx.coroutines.test.runTest {
        var calls = 0
        assertEquals("t", PushRegistration.awaitTransport(60_000) { calls++; "t" })
        assertEquals(1, calls)
        assertEquals(0L, testScheduler.currentTime)
    }

    @Test
    fun briefGap_afterNetworkRestore_isBridged() = kotlinx.coroutines.test.runTest {
        // Tor comes back Connected 6 s after the retry looked (the Case A gap).
        var calls = 0
        val got = PushRegistration.awaitTransport(60_000) { calls++; if (testScheduler.currentTime >= 6_000) "t" else null }
        assertEquals("t", got)
        assertEquals(6_000L, testScheduler.currentTime)
    }

    @Test
    fun neverBack_isBounded() = kotlinx.coroutines.test.runTest {
        val got = PushRegistration.awaitTransport<String>(60_000) { null }
        assertEquals(null, got)
        assertEquals(60_000L, testScheduler.currentTime)
    }
}

package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// COLD-AWARE SEND BUDGET — MessageManager.postWithTransientRetry.
//
// Every send POST used to inherit the 60 s message-transport default. On a COLD
// transport (nothing on it has ever completed an onion round-trip) that is the
// worst possible shape: each attempt opens a FRESH Tor stream with no carry-over,
// and the whole retry loop is bounded by SEND_TRANSIENT_BUDGET_MS (90 s) checked
// BETWEEN attempts — so 60 s per attempt bought TWO attempts and spent ~120 s
// doing it. The retry exists precisely to rotate onto another circuit, so a
// tighter cold budget buys more rotations inside a shorter wall clock.
//
// The two failure directions this pins:
//   • too LONG (the old 60 s) — the loop can barely retry, and a wedged circuit
//     monopolises the per-contact send lock;
//   • too SHORT — a cold Tor's one-off descriptor fetch + rendezvous routinely
//     needs more than ~10 s, and since no attempt carries progress to the next,
//     a budget under that ceiling means NO attempt can ever complete (b309a44).
//
// And the latch is read PER ATTEMPT: whichever cheap GET completes the first
// rendezvous can land while this loop is retrying, and the next attempt should
// get the full steady-state budget.
// ---------------------------------------------------------------------------

/**
 * A real send seals a real AEAD envelope, so these skip on a target whose crypto
 * bridge is not registered (the iOS test target) — same gate AntiSpliceReplayTest
 * uses. On the JVM suites the crypto is always up and they run for real.
 */

private val SEND_INBOX = ("sendbox".padEnd(32, 'A')).take(32)
private val SEND_PEER_INBOX = ("peerbox".padEnd(32, 'B')).take(32)
private val SEND_CAP = "W".repeat(43)

/** Records the per-request timeout the manager asked for, and scripts POST codes. */
private class TimeoutSpyRelay(private vararg val postCodes: Int) : RelayHttp {
    val postTimeouts = mutableListOf<Int>()
    var gets = 0
    /** Runs right after each POST is recorded — used to flip the latch mid-loop. */
    var afterPost: (() -> Unit)? = null

    override fun post(url: String, body: ByteArray, contentType: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult {
        val code = postCodes.getOrElse(postTimeouts.size) { postCodes.lastOrNull() ?: 202 }
        postTimeouts.add(timeoutSeconds)
        afterPost?.invoke()
        return HttpResult(code = code, body = "", isSuccess = code in 200..299)
    }

    override fun put(url: String, body: ByteArray, contentType: String, headers: Map<String, String>, timeoutSeconds: Int) =
        HttpResult(code = 200, body = "", isSuccess = true)

    override fun get(url: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult {
        gets++
        // The relay's real answer to GET / is a 404 — still a completed round-trip.
        return HttpResult(code = 404, body = "not found", isSuccess = false)
    }
}

private fun seedSendable(vault: InMemoryVault, contactId: String = "c1") {
    vault.insertContact(ContactRecord(contactId, generateSecureRandom(32), 1, "A", 0L))
    vault.insertInboxId(InboxIdRecord(
        inboxId = SEND_INBOX, contactId = contactId, createdAt = 1L,
        expiresAt = Long.MAX_VALUE, direction = "inbound", cap = SEND_CAP,
    ))
    vault.insertInboxId(InboxIdRecord(
        inboxId = SEND_PEER_INBOX, contactId = contactId, createdAt = 1L,
        expiresAt = Long.MAX_VALUE, direction = "outbound", cap = SEND_CAP,
    ))
}

class SendTimeoutBudgetTest {

    @Test
    fun coldTransport_sendGetsTheRendezvousSizedBudget() {
        if (!aeadUp()) return
        val vault = InMemoryVault()
        seedSendable(vault)
        val relay = TimeoutSpyRelay(202)
        val mgr = MessageManager(vault, "http://relay.test", relay)

        assertFalse(mgr.hasCompletedRelayRoundTrip(), "a fresh transport has proven nothing")
        assertTrue(mgr.sendMessage("c1", "hi"))
        assertEquals(
            listOf(MessageManager.SEND_COLD_TIMEOUT_SECONDS), relay.postTimeouts,
            "a cold send must not block the full 60 s default before the retry loop can rotate streams",
        )
    }

    @Test
    fun afterARoundTrip_sendGetsTheFullMessageTransportBudget() {
        if (!aeadUp()) return
        val vault = InMemoryVault()
        seedSendable(vault)
        val relay = TimeoutSpyRelay(202)
        val mgr = MessageManager(vault, "http://relay.test", relay)

        mgr.isRelayReachable()   // the 404 is a completed round-trip → latch
        assertTrue(mgr.hasCompletedRelayRoundTrip())

        assertTrue(mgr.sendMessage("c1", "hi"))
        assertEquals(
            listOf(DEFAULT_RELAY_HTTP_TIMEOUT_SECONDS), relay.postTimeouts,
            "once the rendezvous is done, real message traffic keeps the long budget",
        )
    }

    @Test
    fun theLatchIsReadPerAttempt_notOncePerSend() {
        if (!aeadUp()) return
        val vault = InMemoryVault()
        seedSendable(vault)
        // Attempt 1 is a transport drop (code <= 0); a concurrent probe completes the
        // first rendezvous while we back off, and attempt 2 succeeds.
        val relay = TimeoutSpyRelay(-1, 202)
        val mgr = MessageManager(vault, "http://relay.test", relay)
        relay.afterPost = { mgr.isRelayReachable() }

        assertTrue(mgr.sendMessage("c1", "hi"))
        assertEquals(
            listOf(MessageManager.SEND_COLD_TIMEOUT_SECONDS, DEFAULT_RELAY_HTTP_TIMEOUT_SECONDS),
            relay.postTimeouts,
            "the retry after a mid-loop latch flip must use the steady-state budget",
        )
    }

    @Test
    fun theColdBudgetIsPinnedToTheRendezvousFloor() {
        // b309a44: 30 s is the empirically-tuned budget a first cold onion rendezvous
        // needs on a ONE-SHOT the user is waiting on. The health probe's cold budget
        // (HEALTH_HTTP_TIMEOUT_SECONDS) is deliberately TIGHTER — it is a loop that
        // re-fires every ~2 s until it succeeds, so it can spend a miss cheaply,
        // while this send gets only three rotations inside SEND_TRANSIENT_BUDGET_MS.
        // Both stay above the ~10 s rendezvous floor below which no attempt could
        // ever complete, and neither may creep back up to the 60 s default.
        assertTrue(
            MessageManager.HEALTH_HTTP_TIMEOUT_SECONDS < MessageManager.SEND_COLD_TIMEOUT_SECONDS,
            "the retrying probe may be tighter than the one-shot send, never the other way round",
        )
        assertTrue(
            MessageManager.HEALTH_HTTP_TIMEOUT_SECONDS > 10,
            "no cold budget may drop to/under the rendezvous floor (b309a44)",
        )
        assertEquals(30, MessageManager.SEND_COLD_TIMEOUT_SECONDS, "never lower (b309a44)")
        assertTrue(
            MessageManager.SEND_COLD_TIMEOUT_SECONDS < DEFAULT_RELAY_HTTP_TIMEOUT_SECONDS,
            "the whole point is that the cold budget is TIGHTER than the default",
        )
        // Three attempts must fit inside the loop's wall-clock budget (which is
        // checked between attempts): that extra rotation is what buys the recovery.
        assertTrue(
            MessageManager.SEND_COLD_TIMEOUT_SECONDS * 3L <= MessageManager.SEND_TRANSIENT_BUDGET_MS / 1000L,
            "a cold send should get three stream rotations inside SEND_TRANSIENT_BUDGET_MS",
        )
    }
}

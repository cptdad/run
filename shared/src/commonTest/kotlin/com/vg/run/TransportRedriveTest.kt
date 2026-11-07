package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

// ---------------------------------------------------------------------------
// TRANSPORT-BACK RE-DRIVE of transport-failed sends (resilience:tor-death,
// 2026-10-15): the app's embedded Tor was killed 2.8 s after a Send tap; the
// send burned its four transient attempts against the dead SOCKS port, the
// self-heal brought a new Tor up 40 s later, and the message sat in its failed
// state until a manual Retry. Three rules now, all commonMain:
//
//   1. CLASSIFY — a send whose every POST attempt died on the transport (threw /
//      no HTTP status) is SendOutcome.TRANSPORT_FAILED and, under a caller token,
//      is PARKED in the RAM-only TransportFailedSends ledger with a failure time.
//      A relay 4xx/5xx and a local refusal are FAILED and never parked.
//   2. FAIL FAST — once the owner says the transport is KNOWN down
//      (noteTransportLost), the retry loop stops after the attempt in flight.
//   3. RE-DRIVE — redriveTransportFailures() on the NEXT transport re-sends every
//      parked entry inside the 15-minute window through the manual-Retry path
//      (a fresh sendMessage: next persisted counter), once per transport-back
//      event; a re-drive that fails again is not re-parked.
//
// Deterministic: scripted relay, injected clock, injected backoff sleep.
// ---------------------------------------------------------------------------

/** Real AEAD seal ⇒ skip where the crypto bridge is absent (iOS test target). */

private val RD_INBOX = ("rdinbox".padEnd(32, 'A')).take(32)
private val RD_PEER_INBOX = ("rdpeerbox".padEnd(32, 'B')).take(32)
private val RD_CAP = "W".repeat(43)
private const val RD_CONTACT = "contact-rd-0001"

/**
 * Scripts POST results in order: a NEGATIVE code models a transport drop (no HTTP
 * status), `THROW` models the client throwing; the last entry repeats. Records
 * every POST body so a re-drive's fresh envelope can be told from a replay.
 */
private class ScriptedRelay(vararg codes: Int) : RelayHttp {
    companion object { const val THROW = Int.MIN_VALUE }
    private val script = codes.toList()
    val postBodies = mutableListOf<ByteArray>()
    var afterPost: (() -> Unit)? = null
    val posts: Int get() = postBodies.size

    override fun post(url: String, body: ByteArray, contentType: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult {
        val code = script.getOrElse(postBodies.size) { script.lastOrNull() ?: 202 }
        postBodies.add(body.copyOf())
        afterPost?.invoke()
        if (code == THROW) throw IllegalStateException("socks: connection refused")
        return HttpResult(code = code, body = if (code in 200..299) "" else """{"error":"x"}""", isSuccess = code in 200..299)
    }
    override fun put(url: String, body: ByteArray, contentType: String, headers: Map<String, String>, timeoutSeconds: Int) =
        HttpResult(code = 200, body = "", isSuccess = true)
    override fun get(url: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult =
        HttpResult(code = 404, body = "not found", isSuccess = false)
}

private fun seedRedrivable(vault: InMemoryVault, contactId: String = RD_CONTACT) {
    vault.insertContact(ContactRecord(contactId, generateSecureRandom(32), 1, "A", 0L))
    vault.insertInboxId(InboxIdRecord(
        inboxId = RD_INBOX, contactId = contactId, createdAt = 1L,
        expiresAt = Long.MAX_VALUE, direction = "inbound", cap = RD_CAP,
    ))
    vault.insertInboxId(InboxIdRecord(
        inboxId = RD_PEER_INBOX, contactId = contactId, createdAt = 1L,
        expiresAt = Long.MAX_VALUE, direction = "outbound", cap = RD_CAP,
    ))
}

/**
 * LogBuffer is behind the LoggingState kill switch (off in tests); capture only
 * for the duration of [block] and leave nothing behind — the RelayProbeDiagnosticsTest
 * pattern.
 */
private inline fun <T> withLogCapture(block: () -> T): T {
    val was = LoggingState.enabled
    LoggingState.enabled = true
    LogBuffer.clear()
    try {
        return block()
    } finally {
        LoggingState.enabled = was
        LogBuffer.clear()
    }
}

private class Rig(vararg codes: Int) {
    val vault = InMemoryVault().also { seedRedrivable(it) }
    val relay = ScriptedRelay(*codes)
    var clock = 1_000_000L
    val ledger = TransportFailedSends(clock = { clock })
    val sleeps = mutableListOf<Long>()
    fun manager(r: ScriptedRelay = relay): MessageManager =
        MessageManager(vault, "http://relay.test", r, transportFailedSends = ledger).also { mgr ->
            mgr.sendRetrySleep = { sleeps.add(it) }
        }
}

class TransportRedriveTest {

    // --- 1. classification + parking ------------------------------------------

    @Test
    fun transportDrop_isClassifiedTransportFailed_andParkedWithTheFailureTime() {
        if (!aeadUp()) return
        val rig = Rig(-1)
        val mgr = rig.manager()
        rig.clock = 5_000_000L

        val outcome = mgr.sendMessageWithOutcome(RD_CONTACT, "hello", redriveToken = "bubble-1")

        assertEquals(SendOutcome.TRANSPORT_FAILED, outcome)
        assertEquals(MessageManager.SEND_TRANSIENT_ATTEMPTS, rig.relay.posts, "believed-up transport keeps the full transient loop")
        assertEquals(1, rig.ledger.size())
        val entry = rig.ledger.takeEligible().single()
        assertEquals("bubble-1", entry.token)
        assertEquals(RD_CONTACT, entry.contactId)
        assertEquals("hello", entry.plaintext)
        assertEquals(5_000_000L, entry.failedAtMs, "the failure time is stamped from the ledger clock")
    }

    @Test
    fun clientThrow_isTransportClassToo() {
        if (!aeadUp()) return
        val rig = Rig(ScriptedRelay.THROW)
        val mgr = rig.manager()
        assertEquals(SendOutcome.TRANSPORT_FAILED, mgr.sendMessageWithOutcome(RD_CONTACT, "hi", redriveToken = "t"))
        assertEquals(1, rig.ledger.size())
    }

    @Test
    fun relay4xx_isNotTransportClass_andNeverParked() {
        if (!aeadUp()) return
        for (code in listOf(400, 403, 404, 429, 500)) {
            val rig = Rig(code)
            val mgr = rig.manager()
            assertEquals(SendOutcome.FAILED, mgr.sendMessageWithOutcome(RD_CONTACT, "hi", redriveToken = "t-$code"), "code $code")
            assertEquals(1, rig.relay.posts, "a real HTTP response is terminal — no transient loop (code $code)")
            assertEquals(0, rig.ledger.size(), "a relay response must never be parked for re-drive (code $code)")
        }
    }

    @Test
    fun localRefusal_isNotTransportClass_andNeverParked() {
        if (!aeadUp()) return
        val rig = Rig(202)
        val mgr = rig.manager()
        // Unknown contact: refused before any crypto, counter bump or POST.
        assertEquals(SendOutcome.FAILED, mgr.sendMessageWithOutcome("no-such-contact", "hi", redriveToken = "t"))
        // Over-ceiling message: refused before the counter bump.
        assertEquals(SendOutcome.FAILED, mgr.sendMessageWithOutcome(RD_CONTACT, "x".repeat(200_000), redriveToken = "t2"))
        assertEquals(0, rig.relay.posts)
        assertEquals(0, rig.ledger.size())
    }

    @Test
    fun plainSendMessage_isUnchanged_andNeverParks() {
        if (!aeadUp()) return
        val rig = Rig(-1)
        val mgr = rig.manager()
        assertFalse(mgr.sendMessage(RD_CONTACT, "hi"))
        assertEquals(MessageManager.SEND_TRANSIENT_ATTEMPTS, rig.relay.posts)
        assertEquals(0, rig.ledger.size(), "no token ⇒ the legacy Boolean contract, nothing parked")
    }

    @Test
    fun noTokenOutcome_isClassifiedButNotParked() {
        if (!aeadUp()) return
        val rig = Rig(-1)
        val mgr = rig.manager()
        assertEquals(SendOutcome.TRANSPORT_FAILED, mgr.sendMessageWithOutcome(RD_CONTACT, "hi"))
        assertEquals(0, rig.ledger.size())
    }

    @Test
    fun aLandedSend_dropsTheParkedEntryWithTheSameToken() {
        if (!aeadUp()) return
        val rig = Rig(-1, -1, -1, -1, 202)
        val mgr = rig.manager()
        assertEquals(SendOutcome.TRANSPORT_FAILED, mgr.sendMessageWithOutcome(RD_CONTACT, "hi", redriveToken = "b"))
        assertEquals(1, rig.ledger.size())
        // The user's manual Retry under the same bubble id lands.
        assertEquals(SendOutcome.SENT, mgr.sendMessageWithOutcome(RD_CONTACT, "hi", redriveToken = "b"))
        assertEquals(0, rig.ledger.size(), "a delivered message must not be re-driven later")
    }

    @Test
    fun aManualRetryWhileStillDown_isOneEntry_withTheLatestFailureTime() {
        if (!aeadUp()) return
        val rig = Rig(-1)
        val mgr = rig.manager()
        rig.clock = 10L
        mgr.sendMessageWithOutcome(RD_CONTACT, "hi", redriveToken = "b")
        rig.clock = 20L
        mgr.sendMessageWithOutcome(RD_CONTACT, "hi", redriveToken = "b")
        assertEquals(1, rig.ledger.size(), "same token ⇒ upsert, never a second copy to deliver twice")
        assertEquals(20L, rig.ledger.takeEligible().single().failedAtMs)
    }

    // --- 2. known-down fail-fast ------------------------------------------------

    @Test
    fun transportLostMidSend_stopsAfterTheAttemptInFlight_noTransientLoop() {
        if (!aeadUp()) return
        val rig = Rig(-1)
        val mgr = rig.manager()
        // The Tor child dies while attempt 1 is in flight; the owner tells us.
        rig.relay.afterPost = { mgr.noteTransportLost() }

        val outcome = mgr.sendMessageWithOutcome(RD_CONTACT, "hi", redriveToken = "b")

        assertEquals(SendOutcome.TRANSPORT_FAILED, outcome)
        assertEquals(1, rig.relay.posts, "one attempt, not SEND_TRANSIENT_ATTEMPTS")
        assertTrue(rig.sleeps.isEmpty(), "no backoff is spent on a known-dead transport")
        assertEquals(1, rig.ledger.size(), "fail fast INTO the parked state")
        assertTrue(mgr.isTransportLost())
    }

    @Test
    fun transportAlreadyLost_makesExactlyOneAttempt() {
        if (!aeadUp()) return
        val rig = Rig(-1)
        val mgr = rig.manager()
        mgr.noteTransportLost()
        assertEquals(SendOutcome.TRANSPORT_FAILED, mgr.sendMessageWithOutcome(RD_CONTACT, "hi", redriveToken = "b"))
        assertEquals(1, rig.relay.posts, "a stale flag costs one cheap attempt, never a silent refusal")
        assertTrue(rig.sleeps.isEmpty())
    }

    @Test
    fun transportLost_butTheOneAttemptLands_isSent() {
        if (!aeadUp()) return
        val rig = Rig(202)
        val mgr = rig.manager()
        mgr.noteTransportLost()
        assertEquals(SendOutcome.SENT, mgr.sendMessageWithOutcome(RD_CONTACT, "hi", redriveToken = "b"))
        assertEquals(0, rig.ledger.size())
    }

    @Test
    fun believedUpTransport_keepsTheExistingTransientLoop() {
        if (!aeadUp()) return
        val rig = Rig(-1, -1, 202)
        val mgr = rig.manager()
        assertEquals(SendOutcome.SENT, mgr.sendMessageWithOutcome(RD_CONTACT, "hi", redriveToken = "b"))
        assertEquals(3, rig.relay.posts)
        assertEquals(2, rig.sleeps.size, "two backoffs between three attempts, exactly as before")
        assertEquals(0, rig.ledger.size())
    }

    // --- 3. the re-drive ---------------------------------------------------------

    @Test
    fun redrive_resendsOnlyParkedEntriesInsideTheWindow_onceAndThroughSendMessage() = runTest {
        if (!aeadUp()) return@runTest
        val rig = Rig(-1)
        val dying = rig.manager()
        rig.clock = 0L
        assertEquals(SendOutcome.TRANSPORT_FAILED, dying.sendMessageWithOutcome(RD_CONTACT, "stale", redriveToken = "old"))
        rig.clock = 60_000L
        assertEquals(SendOutcome.TRANSPORT_FAILED, dying.sendMessageWithOutcome(RD_CONTACT, "fresh", redriveToken = "new"))
        dying.noteTransportLost()
        assertEquals(2, rig.ledger.size())

        // Transport back: a NEW instance on the same (shared) ledger, 16 min after the
        // first failure and 15 min after the second.
        rig.clock = 60_000L + TransportFailedSends.REDRIVE_WINDOW_MS
        val healthy = ScriptedRelay(202)
        val fresh = rig.manager(healthy)

        assertEquals(1, fresh.redriveTransportFailures(), "only the entry inside the 15-minute window is re-driven")
        assertEquals(1, healthy.posts)
        assertEquals(0, rig.ledger.size(), "the stale entry is dropped, the re-driven one consumed")
        // The re-driven bytes are a FRESH envelope, never the bytes that failed.
        assertTrue(rig.relay.postBodies.none { it.contentEquals(healthy.postBodies.single()) })

        assertEquals(0, fresh.redriveTransportFailures(), "once per transport-back event: a second call finds nothing")
        assertEquals(1, healthy.posts)
    }

    @Test
    fun redrive_hasExactlyTheManualRetrysCounterSemantics() = runTest {
        if (!aeadUp()) return@runTest
        // CONTROL ARM: the manual path — a failed send then a manual Retry (a fresh
        // sendMessage) on a legacy (static-envelope) contact: the first send
        // consumed counter 1, the Retry seals counter 2.
        val manual = Rig(-1, -1, -1, -1, 202)
        val m = manual.manager()
        assertFalse(m.sendMessage(RD_CONTACT, "hi"))
        assertEquals(1L, manual.vault.contacts[RD_CONTACT]!!.outboundCounter, "the failed send persisted counter 1 BEFORE posting")
        assertTrue(m.sendMessage(RD_CONTACT, "hi"))
        assertEquals(2L, manual.vault.contacts[RD_CONTACT]!!.outboundCounter, "manual Retry = next counter")

        // AUTOMATIC ARM: the same shape through the re-drive.
        val auto = Rig(-1)
        val dying = auto.manager()
        assertEquals(SendOutcome.TRANSPORT_FAILED, dying.sendMessageWithOutcome(RD_CONTACT, "hi", redriveToken = "b"))
        assertEquals(1L, auto.vault.contacts[RD_CONTACT]!!.outboundCounter)
        val healthy = ScriptedRelay(202)
        val fresh = auto.manager(healthy)
        assertEquals(1, fresh.redriveTransportFailures())
        assertEquals(2L, auto.vault.contacts[RD_CONTACT]!!.outboundCounter, "the re-drive advanced the counter exactly like the manual Retry")
        assertEquals(1, healthy.posts)
    }

    @Test
    fun redrive_thatFailsAgain_leavesTheNormalFailedState_notReparked() = runTest {
        if (!aeadUp()) return@runTest
        val rig = Rig(-1)
        val dying = rig.manager()
        var redrivenCallbacks = 0
        assertEquals(
            SendOutcome.TRANSPORT_FAILED,
            dying.sendMessageWithOutcome(RD_CONTACT, "hi", redriveToken = "b", onRedriven = { redrivenCallbacks++ }),
        )
        val stillDead = ScriptedRelay(-1)
        val fresh = rig.manager(stillDead)

        assertEquals(1, fresh.redriveTransportFailures(), "re-driven (attempted) once")
        assertEquals(MessageManager.SEND_TRANSIENT_ATTEMPTS, stillDead.posts, "the re-drive itself is an ordinary believed-up send")
        assertEquals(0, rig.ledger.size(), "NOT re-parked: the bubble stays failed, manual Retry still works")
        assertEquals(0, redrivenCallbacks, "no delivery callback for a re-drive that did not land")
        assertEquals(0, fresh.redriveTransportFailures())
    }

    @Test
    fun redrive_thatLands_firesTheCallbackOnce() = runTest {
        if (!aeadUp()) return@runTest
        val rig = Rig(-1)
        val dying = rig.manager()
        var redrivenCallbacks = 0
        dying.sendMessageWithOutcome(RD_CONTACT, "hi", redriveToken = "b", onRedriven = { redrivenCallbacks++ })
        val fresh = rig.manager(ScriptedRelay(202))
        assertEquals(1, fresh.redriveTransportFailures())
        assertEquals(1, redrivenCallbacks)
        assertEquals(0, fresh.redriveTransportFailures())
        assertEquals(1, redrivenCallbacks)
    }

    @Test
    fun redrive_withNothingPending_returnsZero_andLogsNothing() = runTest {
        if (!aeadUp()) return@runTest
        withLogCapture {
            val rig = Rig(202)
            val mgr = rig.manager()
            assertEquals(0, mgr.redriveTransportFailures())
            assertEquals(0, rig.relay.posts)
            assertTrue(LogBuffer.getAll().none { it.message.contains("transport back") }, "nothing pending ⇒ silent")
        }
    }

    @Test
    fun redrive_skipsAnEntryTheUserCancelled() = runTest {
        if (!aeadUp()) return@runTest
        val rig = Rig(-1)
        val dying = rig.manager()
        dying.sendMessageWithOutcome(RD_CONTACT, "hi", redriveToken = "deleted-bubble")
        assertTrue(rig.ledger.remove("deleted-bubble"))
        val healthy = ScriptedRelay(202)
        assertEquals(0, rig.manager(healthy).redriveTransportFailures())
        assertEquals(0, healthy.posts)
    }

    @Test
    fun scrubInMemory_clearsTheLedger() {
        if (!aeadUp()) return
        val rig = Rig(-1)
        val mgr = rig.manager()
        mgr.sendMessageWithOutcome(RD_CONTACT, "hi", redriveToken = "b")
        assertEquals(1, rig.ledger.size())
        mgr.scrubInMemory()
        assertEquals(0, rig.ledger.size(), "lock / wipe must leave no parked plaintext behind")
    }

    // --- log hygiene ----------------------------------------------------------------

    @Test
    fun logLines_carryCountsOnly_neverAnIdentifierOrPlaintext() = runTest {
        if (!aeadUp()) return@runTest
        withLogCapture {
            val rig = Rig(-1)
            val dying = rig.manager()
            rig.relay.afterPost = { dying.noteTransportLost() }
            val plaintext = "secret-plaintext-7f3a"
            dying.sendMessageWithOutcome(RD_CONTACT, plaintext, redriveToken = "bubble-token-9c")
            val fresh = rig.manager(ScriptedRelay(202))
            assertEquals(1, fresh.redriveTransportFailures())

            val lines = LogBuffer.getAll().map { it.message }
            val redriveLine = lines.single { it.startsWith("transport back") }
            assertEquals("transport back — re-driving 1 transport-failed sends", redriveLine)
            val stopLine = lines.single { it.startsWith("send stopped after") }
            assertEquals("send stopped after 1 attempt(s) — transport is known down, leaving it to the transport-back re-drive", stopLine)
            for (line in listOf(redriveLine, stopLine)) {
                assertFalse(line.contains(RD_CONTACT), "no contact id")
                assertFalse(line.contains(RD_PEER_INBOX), "no inbox id")
                assertFalse(line.contains(RD_PEER_INBOX.take(8)), "not even the 8-char inbox prefix")
                assertFalse(line.contains(RD_CAP), "no capability")
                assertFalse(line.contains(plaintext), "no plaintext")
                assertFalse(line.contains("bubble-token-9c"), "no token")
            }
        }
    }

    // --- the ledger on its own -------------------------------------------------

    @Test
    fun ledger_window_cap_order_andClear() {
        var clock = 0L
        val ledger = TransportFailedSends(clock = { clock })
        assertTrue(ledger.takeEligible().isEmpty())
        assertFalse(ledger.remove("absent"))

        // Oldest evicted past the cap; order is failure order.
        for (i in 0 until TransportFailedSends.MAX_ENTRIES + 3) {
            clock = i.toLong()
            ledger.record("t$i", "c", "m$i", false, null, sessionEpoch = ledger.sessionEpoch)
        }
        assertEquals(TransportFailedSends.MAX_ENTRIES, ledger.size())
        val taken = ledger.takeEligible()
        assertEquals("t3", taken.first().token, "the three oldest were evicted")
        assertEquals("t${TransportFailedSends.MAX_ENTRIES + 2}", taken.last().token)
        assertEquals(0, ledger.size(), "takeEligible empties the ledger")

        // Exactly-at-window is eligible; one ms past is not — and both are consumed.
        clock = 0L
        ledger.record("edge", "c", "m", false, null, sessionEpoch = ledger.sessionEpoch)
        ledger.record("late", "c", "m", true, null, sessionEpoch = ledger.sessionEpoch)
        clock = TransportFailedSends.REDRIVE_WINDOW_MS
        ledger.record("now", "c", "m", false, null, sessionEpoch = ledger.sessionEpoch)
        assertEquals(3, ledger.size())
        clock = TransportFailedSends.REDRIVE_WINDOW_MS + 1
        val eligible = ledger.takeEligible().map { it.token }
        assertEquals(listOf("now"), eligible)
        assertEquals(0, ledger.size())

        ledger.record("x", "c", "m", false, null, sessionEpoch = ledger.sessionEpoch)
        ledger.clear()
        assertEquals(0, ledger.size())
        assertNull(ledger.takeEligible().firstOrNull())
    }

    @Test
    fun ledger_upsertMovesTheEntryToTheEnd_andKeepsTheLatestCallback() {
        var clock = 0L
        val ledger = TransportFailedSends(clock = { clock })
        var first = 0; var second = 0
        ledger.record("a", "c", "m", false, { first++ }, sessionEpoch = ledger.sessionEpoch)
        ledger.record("b", "c", "m", false, null, sessionEpoch = ledger.sessionEpoch)
        clock = 5L
        ledger.record("a", "c", "m", false, { second++ }, sessionEpoch = ledger.sessionEpoch)
        val taken = ledger.takeEligible()
        assertEquals(listOf("b", "a"), taken.map { it.token })
        assertEquals(5L, taken.last().failedAtMs)
        taken.last().onRedriven?.invoke()
        assertEquals(0, first); assertEquals(1, second)
        assertNotEquals(taken[0].failedAtMs, taken[1].failedAtMs)
    }

    @Test
    fun theWindowIsFifteenMinutes_andTheSharedLedgerIsOneObject() {
        assertEquals(15L * 60 * 1000, TransportFailedSends.REDRIVE_WINDOW_MS)
        assertTrue(TransportFailedSends.shared === TransportFailedSends.shared)
    }
}

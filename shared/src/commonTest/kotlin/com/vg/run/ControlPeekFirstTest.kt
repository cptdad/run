package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// CONTROL-CHANNEL PEEK-FIRST — MessageManager.peekControlPending /
// MessageManager.isControlConverging / GroupManager.pollAllControls.
//
// The background control sweep used to DRAIN every contact's control inbox on
// every cycle. `GET /inbox/{id}` deletes what it returns at REQUEST-HANDLING
// time, so a drain whose response is lost on a cold or wedged circuit destroys
// those invites / rosters / inbox announces permanently — and the inbox is
// almost always EMPTY, so nearly every one of those destructive, cold-stalling
// GETs bought nothing.
//
// The properties pinned here are the ones that make peek-first safe rather than
// merely cheaper:
//
//   • only a peek that POSITIVELY answered "0 queued" may skip the drain;
//     every uncertain answer (404 / 429 / transport failure / unreadable body)
//     still drains, so no transient failure can starve control delivery;
//   • the relay-loss 404 accounting is UNCHANGED — one 404 recorded per cycle,
//     exactly as when the drain was the only request (the peek deliberately
//     records none of its own, or the streak would count double);
//   • a healthy peek is the same proof-of-life a healthy drain is: it clears
//     the channel's streak and latches the onion round-trip;
//   • an interrupted read-cap rotation is reconciled BEFORE the probe, the
//     same call pollChannel makes;
//   • while CONVERGING (a join→roster→resolve chain in flight) the peek is
//     skipped entirely — traffic is expected, so the extra round-trip would
//     only slow the exchange the fast window exists to accelerate;
//   • and — the regression this must never cause — peekOnce / peekInboxRef keep
//     their ZERO side effects, because the parallel unread prime runs them from
//     several coroutines at once.
// ---------------------------------------------------------------------------

/** 32-char base64url-alphabet inbox id derived from [tag]. */
private fun ctlInbox(tag: String) = ("cx$tag".padEnd(32, 'A')).take(32)

private val CTL_ID = ctlInbox("ctl")
private val TXT_ID = ctlInbox("txt")
private val CTL_CAP = "R".repeat(43)        // capabilities are exactly 43 chars
private val CTL_NEW_CAP = "N".repeat(43)

/**
 * URL-aware control relay double. Distinguishes the two GET shapes that matter:
 * `…/inbox/{id}/peek` (non-destructive probe) and a bare `…/inbox/{id}` (the
 * DESTRUCTIVE drain), so a test can assert which one the sweep chose.
 */
private class CtlRelay(
    var peekPending: Int? = 0,
    var peekCode: Int = 200,
    var drainCode: Int = 200,
) : PeekCountRelay(putReply = HttpResult(code = 200, body = "", isSuccess = true), deleteReply = HttpResult(code = 200, body = "", isSuccess = true)) {
    /** Every request as "VERB url", in order. */
    val calls: List<String> get() = requests.map { "${it.method} ${it.url}" }
    val peeks: Int get() = peekRequests().size
    val drains: Int get() = drainRequests().size

    override fun peekReply(inboxId: String): HttpResult {
        if (peekCode !in 200..299) {
            return HttpResult(code = peekCode, body = RELAY_REJECTED_BODY, isSuccess = false)
        }
        // pending = null models a 2xx whose body carries no readable count.
        val body = peekPending?.let { """{"pending":$it}""" } ?: """{"unexpected":"shape"}"""
        return HttpResult(code = 200, body = body, isSuccess = true)
    }

    override fun drainReply(inboxId: String): HttpResult =
        if (drainCode !in 200..299) HttpResult(code = drainCode, body = RELAY_REJECTED_BODY, isSuccess = false)
        else RELAY_EMPTY_DRAIN
}

private fun seedCtlContact(
    vault: InMemoryVault,
    contactId: String = "c1",
    ctlInboxId: String? = CTL_ID,
    cap: String? = CTL_CAP,
    textInboxId: String? = null,
) {
    vault.insertContact(ContactRecord(contactId, generateSecureRandom(32), 1, "A-$contactId", 0L))
    if (ctlInboxId != null) vault.insertInboxId(InboxIdRecord(
        inboxId = ctlInboxId, contactId = contactId, createdAt = 1L,
        expiresAt = Long.MAX_VALUE, direction = MessageManager.DIR_INBOUND_CTL, cap = cap,
    ))
    if (textInboxId != null) vault.insertInboxId(InboxIdRecord(
        inboxId = textInboxId, contactId = contactId, createdAt = 1L,
        expiresAt = Long.MAX_VALUE, direction = "inbound", cap = cap,
    ))
}

class ControlPeekFirstTest {

    @Test
    fun emptyControlInbox_isPeekedAndNeverDrained() {
        val vault = InMemoryVault()
        seedCtlContact(vault)
        val relay = CtlRelay(peekPending = 0)
        val gm = GroupManager(vault) { MessageManager(vault, "http://relay.test", relay) }

        assertFalse(gm.pollAllControls(), "an empty control inbox drains nothing")
        assertEquals(1, relay.peeks, "the idle cycle must cost exactly one cheap probe")
        assertEquals(
            0, relay.drains,
            "a peek that positively answered 0 must skip the DESTRUCTIVE drain entirely",
        )
    }

    @Test
    fun pendingControlTraffic_isDrained() {
        val vault = InMemoryVault()
        seedCtlContact(vault)
        val relay = CtlRelay(peekPending = 2)
        val gm = GroupManager(vault) { MessageManager(vault, "http://relay.test", relay) }

        gm.pollAllControls()
        assertEquals(1, relay.peeks)
        assertEquals(1, relay.drains, "pending > 0 must still drain — this is the delivery path")
    }

    @Test
    fun unknownPeekOutcomes_allStillDrain() {
        // 404 (gone / wrong cap / locked / mid-rotation), 429 (rate limited), a
        // transport failure, and a 2xx with an unreadable body. None of them says
        // "nothing is waiting", so every one of them must fall through to the drain
        // — reading any of them as empty would starve invites/rosters/announces
        // behind a transient failure.
        for (peekCode in listOf(404, 429, -1)) {
            val vault = InMemoryVault()
            seedCtlContact(vault)
            val relay = CtlRelay(peekCode = peekCode)
            val gm = GroupManager(vault) { MessageManager(vault, "http://relay.test", relay) }
            gm.pollAllControls()
            assertEquals(1, relay.peeks, "peek code $peekCode")
            assertEquals(1, relay.drains, "an UNKNOWN peek (code $peekCode) must drain anyway")
        }
        val vault = InMemoryVault()
        seedCtlContact(vault)
        val relay = CtlRelay(peekPending = null)   // 2xx, no readable `pending`
        val gm = GroupManager(vault) { MessageManager(vault, "http://relay.test", relay) }
        gm.pollAllControls()
        assertEquals(1, relay.drains, "an unreadable count is UNKNOWN, not zero")
    }

    @Test
    fun convergingWindow_drainsWithoutPeeking() {
        val vault = InMemoryVault()
        seedCtlContact(vault)
        val relay = CtlRelay(peekPending = 0)
        val mgr = MessageManager(vault, "http://relay.test", relay)
        val gm = GroupManager(vault) { mgr }

        // Arm the convergence window the fast cadence uses (a join→roster→resolve
        // chain in flight). The ONLY writers are a control SEND and a
        // QUALIFYING received control message (GroupManager.ingest →
        // noteControlActivity) — never controlPollDelayMs, see below.
        mgr.noteControlActivity(progress = true)
        assertTrue(mgr.isControlConverging())

        gm.pollAllControls()
        assertEquals(0, relay.peeks, "while converging, traffic is EXPECTED — the probe is pure added latency")
        assertEquals(1, relay.drains)
    }

    @Test
    fun idleWindow_isNotConverging() {
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", CtlRelay())
        // A fresh transport has seen no control activity at all.
        assertFalse(mgr.isControlConverging(), "a fresh manager must not claim to be converging")
        // Asking for the delay in the IDLE state must not arm the window either —
        // isControlConverging is a predicate, and controlPollDelayMs(false) is the
        // only "not converging" report the platform makes.
        mgr.controlPollDelayMs(convergingNow = false)
        assertFalse(mgr.isControlConverging())
    }

    // -----------------------------------------------------------------------
    // controlPollDelayMs(convergingNow = true) reports a
    // per-cycle condition; it must NOT arm the persistent convergence window. Both
    // platforms feed it `received || hasUnresolvedMembers()`, and `received` is true
    // for ANY drained blob — so arming off it let one paired contact posting a blob
    // a minute hold the device in 2.5–5 s sweeps for the whole foreground session
    // AND keep the peek-before-drain disabled for every contact.
    // -----------------------------------------------------------------------

    @Test
    fun convergingNow_givesOneFastCycle_butNeverArmsTheWindow() {
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", CtlRelay())

        val fast = mgr.controlPollDelayMs(convergingNow = true)
        assertTrue(
            fast < MessageManager.CONTROL_POLL_IDLE_BASE_MS,
            "a cycle that reports converging must still get ONE fast follow-up (hasUnresolvedMembers)",
        )
        assertFalse(
            mgr.isControlConverging(),
            "…but it must not arm the 60 s window: that is what a hostile contact pinned",
        )
        // And the very next cycle, with nothing to report, is back to IDLE.
        assertTrue(mgr.controlPollDelayMs(convergingNow = false) >= MessageManager.CONTROL_POLL_IDLE_BASE_MS)
    }

    @Test
    fun peerNoise_cannotHoldTheFastEpisodeOpenForever() {
        // The same kind of absolute bound as the group join window:: an episode expires
        // CONTROL_FAST_EPISODE_MAX_MS after it started REGARDLESS of re-arms, and a
        // re-arm carrying no progress does not restart it.
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", CtlRelay())
        var clock = 1_000_000L
        mgr.controlConvergenceClockMs = { clock }

        mgr.noteControlActivity(progress = false)
        assertTrue(mgr.isControlConverging())

        // Re-arm every 50 s (inside the 60 s window) for well past the episode cap.
        var armed = 0
        while (armed < 30) {
            clock += 50_000L
            mgr.noteControlActivity(progress = false)
            armed++
        }
        assertFalse(
            mgr.isControlConverging(),
            "an arm every 50 s must NOT hold the fast cadence open past the episode ceiling",
        )
        // The peek-first optimisation is therefore back on for every contact.
        assertTrue(mgr.controlPollDelayMs(convergingNow = false) >= MessageManager.CONTROL_POLL_IDLE_BASE_MS)
    }

    @Test
    fun realProgress_reanchorsTheEpisode_soHonestConvergenceIsNeverThrottled() {
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", CtlRelay())
        var clock = 1_000_000L
        mgr.controlConvergenceClockMs = { clock }

        mgr.noteControlActivity(progress = false)
        clock += MessageManager.CONTROL_FAST_EPISODE_MAX_MS - 1_000L
        // One arrival that actually moved group state (or one of our own sends).
        mgr.noteControlActivity(progress = true)
        clock += MessageManager.CONTROL_FAST_EPISODE_MAX_MS - 1_000L
        mgr.noteControlActivity(progress = false)
        assertTrue(
            mgr.isControlConverging(),
            "progress re-anchors the episode — a genuine join→roster→resolve chain is never cut short",
        )
    }

    @Test
    fun aQuietGapRestartsTheEpisode() {
        // After the window genuinely lapses (no arm for CONTROL_CONVERGENCE_WINDOW_MS)
        // the next arm starts a FRESH episode — otherwise one exhausted episode would
        // disable fast convergence for the rest of the session.
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", CtlRelay())
        var clock = 1_000_000L
        mgr.controlConvergenceClockMs = { clock }

        mgr.noteControlActivity(progress = false)
        var armed = 0
        while (armed < 30) { clock += 50_000L; mgr.noteControlActivity(progress = false); armed++ }
        assertFalse(mgr.isControlConverging())

        clock += MessageManager.CONTROL_CONVERGENCE_WINDOW_MS + 1
        mgr.noteControlActivity(progress = false)
        assertTrue(mgr.isControlConverging(), "a quiet gap must reset the episode")
    }

    @Test
    fun peek404_feedsTheRelayLossStreakExactlyLikeADrain404() {
        // The peek deliberately records NO 404 of its own: an unknown outcome
        // drains, and that drain's 404 branch does the bookkeeping. So a peek-first
        // cycle must count ONE 404 per cycle — the same as the drain-only path —
        // never two, which would trip the re-pair badge in half the cycles.
        val peekVault = InMemoryVault(); seedCtlContact(peekVault)
        val peekRelay = CtlRelay(peekCode = 404, drainCode = 404)
        val peekMgr = MessageManager(peekVault, "http://relay.test", peekRelay)
        var peekClock = 0L
        peekMgr.relayLostClockMs = { peekClock }
        val gm = GroupManager(peekVault) { peekMgr }

        // The drain-only reference: the same contact polled the old way.
        val drainVault = InMemoryVault(); seedCtlContact(drainVault)
        val drainMgr = MessageManager(drainVault, "http://relay.test", CtlRelay(drainCode = 404))
        var drainClock = 0L
        drainMgr.relayLostClockMs = { drainClock }

        fun bothFlagged(): Pair<Boolean, Boolean> =
            ("c1" in peekMgr.relayLostContacts()) to ("c1" in drainMgr.relayLostContacts())

        repeat(peekMgr.RELAY_LOST_404_STREAK - 2) {
            gm.pollAllControls()
            drainMgr.pollControlMessages("c1")
        }
        peekClock = peekMgr.RELAY_LOST_MIN_WINDOW_MS
        drainClock = drainMgr.RELAY_LOST_MIN_WINDOW_MS

        gm.pollAllControls()
        drainMgr.pollControlMessages("c1")
        assertEquals(false to false, bothFlagged(), "one short of the streak: neither path may flag yet")

        gm.pollAllControls()
        drainMgr.pollControlMessages("c1")
        assertEquals(true to true, bothFlagged(), "the peek-first path must flag on the SAME cycle as the drain-only one")
    }

    @Test
    fun healthyPeek_clearsTheStreak_andLatchesTheRoundTrip() {
        val vault = InMemoryVault()
        seedCtlContact(vault)
        val relay = CtlRelay(peekCode = 404, drainCode = 404)
        val mgr = MessageManager(vault, "http://relay.test", relay)
        var clock = 0L
        mgr.relayLostClockMs = { clock }
        val gm = GroupManager(vault) { mgr }

        repeat(mgr.RELAY_LOST_404_STREAK - 1) { gm.pollAllControls() }
        clock = mgr.RELAY_LOST_MIN_WINDOW_MS
        gm.pollAllControls()
        assertTrue("c1" in mgr.relayLostContacts(), "a persistent control 404 must still flag for re-pair")
        assertFalse(mgr.hasCompletedRelayRoundTrip(), "nothing has answered 2xx yet")

        // The relay recovers with an EMPTY inbox, so this cycle peeks and never
        // drains: the peek alone has to be enough to clear the streak, or a healthy
        // idle contact would stay flagged forever.
        val drainsBeforeRecovery = relay.drains
        relay.peekCode = 200
        relay.peekPending = 0
        gm.pollAllControls()
        assertEquals(drainsBeforeRecovery, relay.drains, "the recovery cycle must not need a drain")
        assertFalse("c1" in mgr.relayLostContacts(), "a healthy peek is the same proof of life a healthy drain is")
        assertTrue(mgr.hasCompletedRelayRoundTrip(), "a /peek that answered IS a completed onion round-trip")
    }
}

class PeekControlPendingTest {

    @Test
    fun returnsTheQueuedCount() {
        val vault = InMemoryVault()
        seedCtlContact(vault)
        val relay = CtlRelay(peekPending = 7)
        val mgr = MessageManager(vault, "http://relay.test", relay)

        assertEquals(7, mgr.peekControlPending("c1"))
        assertEquals(1, relay.peeks)
        assertEquals(0, relay.drains, "the probe must never touch the draining endpoint")
        assertTrue(relay.calls.single().endsWith("/inbox/$CTL_ID/peek"), "it must probe the CONTROL inbox")
    }

    @Test
    fun preV7PairingWithNoControlInbox_isUnknownAndCostsNoRequest() {
        val vault = InMemoryVault()
        seedCtlContact(vault, ctlInboxId = null, textInboxId = TXT_ID)
        val relay = CtlRelay()
        val mgr = MessageManager(vault, "http://relay.test", relay)

        assertNull(mgr.peekControlPending("c1"), "no control inbox is UNKNOWN, never zero")
        assertTrue(relay.calls.isEmpty(), "nothing to probe — no request may leave")
    }

    @Test
    fun unknownContact_orMalformedStoredCap_isRefusedBeforeAnyRequest() {
        val relay = CtlRelay()
        val vault = InMemoryVault()
        val mgr = MessageManager(vault, "http://relay.test", relay)
        assertNull(mgr.peekControlPending("nobody"))

        // CRLF in a stored cap bound for the X-Read-Capability header, and a
        // pre-migration UUID-shaped inbox id: both refused before the transport.
        seedCtlContact(vault, contactId = "bad-cap", cap = "bad\r\nX-Evil: 1")
        assertNull(mgr.peekControlPending("bad-cap"))
        val idVault = InMemoryVault()
        seedCtlContact(idVault, contactId = "bad-id", ctlInboxId = "0f8c3a11-1111-2222-3333-444455556666")
        assertNull(MessageManager(idVault, "http://relay.test", relay).peekControlPending("bad-id"))

        assertTrue(relay.calls.isEmpty(), "a malformed cap/inbox must never reach the transport")
    }

    @Test
    fun reconcilesAnInterruptedCapRotationBeforeProbing() {
        // The pending marker holds a CANDIDATE read cap written before the
        // rotation PUT left the device. pollChannel reconciles it before it reads
        // the row; the control peek is now a second reader of that row, so it must
        // do the same or it would probe with a cap the relay may no longer hold.
        val vault = InMemoryVault()
        seedCtlContact(vault)
        val pendKey = MessageManager.capPendingKey("c1", MessageManager.DIR_INBOUND_CTL)
        vault.putMeta(pendKey, CTL_NEW_CAP)
        val relay = CtlRelay(peekPending = 0)
        val mgr = MessageManager(vault, "http://relay.test", relay)

        assertEquals(0, mgr.peekControlPending("c1"))
        assertNull(vault.getMeta(pendKey), "the resolved marker must be dropped")
        assertEquals(
            CTL_NEW_CAP, vault.getInboxIdForContact("c1", MessageManager.DIR_INBOUND_CTL)?.cap,
            "the candidate answered 200, so it is the record's cap now",
        )
    }
}

// ---------------------------------------------------------------------------
// The regression guard: peekOnce / peekInboxRef must keep ZERO side effects.
//
// Their documented ABSENCE of vault bookkeeping is a safety property, not an
// oversight — the connect-time unread prime runs peekInboxRef from several
// coroutines at once, and VaultDatabase thread-safety under genuinely concurrent
// access is unproven on both platforms. peekControlPending is layered strictly
// ABOVE peekOnce and adds its side effects there; none of them may leak down.
// ---------------------------------------------------------------------------
class PeekSideEffectFreedomTest {

    @Test
    fun peekInboxRef_latchesNothing_butPeekControlPendingDoes() {
        val refVault = InMemoryVault()
        seedCtlContact(refVault, textInboxId = TXT_ID)
        val refMgr = MessageManager(refVault, "http://relay.test", CtlRelay(peekPending = 3))
        assertEquals(3, refMgr.peekInboxRef(TXT_ID, CTL_CAP))
        assertFalse(
            refMgr.hasCompletedRelayRoundTrip(),
            "peekInboxRef must stay bookkeeping-free — the round-trip latch is the control peek's job",
        )

        val ctlVault = InMemoryVault()
        seedCtlContact(ctlVault)
        val ctlMgr = MessageManager(ctlVault, "http://relay.test", CtlRelay(peekPending = 3))
        assertEquals(3, ctlMgr.peekControlPending("c1"))
        assertTrue(ctlMgr.hasCompletedRelayRoundTrip())
    }

    @Test
    fun peekInboxRef_recordsNoRelayLossStreak() {
        val vault = InMemoryVault()
        seedCtlContact(vault, textInboxId = TXT_ID)
        val mgr = MessageManager(vault, "http://relay.test", CtlRelay(peekCode = 404))
        var clock = 0L
        mgr.relayLostClockMs = { clock }

        repeat(mgr.RELAY_LOST_404_STREAK + 2) {
            assertNull(mgr.peekInboxRef(TXT_ID, CTL_CAP))
            clock += mgr.RELAY_LOST_MIN_WINDOW_MS
        }
        assertTrue(
            mgr.relayLostContacts().isEmpty(),
            "an in-flight cap rotation makes the prime's peek 404 transiently — it must never flag a contact",
        )
    }

    @Test
    fun peekInboxRef_doesNotReconcileAPendingCapRotation() {
        val vault = InMemoryVault()
        seedCtlContact(vault, textInboxId = TXT_ID)
        val pendKey = MessageManager.capPendingKey("c1", "inbound")
        vault.putMeta(pendKey, CTL_NEW_CAP)
        val relay = CtlRelay(peekPending = 1)
        val mgr = MessageManager(vault, "http://relay.test", relay)

        assertEquals(1, mgr.peekInboxRef(TXT_ID, CTL_CAP))
        assertEquals(CTL_NEW_CAP, vault.getMeta(pendKey), "the marker must survive an unrelated peek")
        assertEquals(CTL_CAP, vault.getInboxIdForContact("c1", "inbound")?.cap, "no cap may be committed here")
        assertEquals(listOf("GET http://relay.test/inbox/$TXT_ID/peek"), relay.calls,
            "exactly one request: no reconcile probe, no rotation PUT, no push DELETE")
    }
}

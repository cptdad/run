package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

// ---------------------------------------------------------------------------
// MINT ABORT — MessageManager.mintInbox / mintInboxPair.
//
// The caller's PowAbort was polled by exactly ONE thing: the PoW grind. Neither
// mintInbox's outer transient-retry loop (MAX_MINT_TRANSIENT_ATTEMPTS = 12, each
// attempt up to two 25 s POSTs plus a 1.5-12 s backoff) nor mintInboxPair's
// second mint ever consulted it. So a signalled abort — ReferralManager's
// ACCEPT_MINT_DEADLINE_MS, or the user backing out of Add Contact — kept the
// device grinding and POSTing long after the caller had given up: the 480 s
// referral deadline could overrun to ~888 s.
//
// Rules under test:
//   • the outer retry loop checks the abort at the TOP of every iteration and
//     inside the backoff, so a cancel lands in ~a second, not minutes;
//   • an abort between the pair's two mints stops the SECOND mint before it
//     spends a grind — and still destroys the just-minted, never-shared main
//     inbox rather than leaving it parked on the relay;
//   • none of this changes the happy path: a mint with no abort still completes,
//     and a pair still mints both inboxes.
// ---------------------------------------------------------------------------

private val MINT_ABORT_INBOX = ("mintbox".padEnd(32, 'M')).take(32)
private val MINT_ABORT_READ_CAP = "R".repeat(43)
private val MINT_ABORT_WRITE_CAP = "W".repeat(43)

/** Single-sourced; see [powChallengeBody] (difficulty 8 = sub-millisecond solve). */
private fun mintChallengeBody(nonce: String = "AAECAwQFBgcICQoLDA0ODw") = powChallengeBody(nonce)

private val mintOkBody =
    """{"inboxId":"$MINT_ABORT_INBOX","readCapability":"$MINT_ABORT_READ_CAP","writeCapability":"$MINT_ABORT_WRITE_CAP","expiresAt":12345}"""

/** Every POST is a transport drop (code <= 0) — the transient failure the loop retries. */
private class DeadPostRelay : FakeRelayHttp() {
    init { HttpResult(code = -1, body = null, isSuccess = false).let { dead -> onPost = { dead }; onPut = { dead } } }
    val posts: Int get() = requestsOf("POST").size
}

/** Answers the two-request mint handshake, forever: 400 challenge (no PoW token), then 201. */
private class PairMintRelay : MintingRelay(
    mintReply = { HttpResult(code = 201, body = mintOkBody, isSuccess = true) },
    challengeBody = mintChallengeBody(),
    putReply = HttpResult(code = 200, body = "", isSuccess = true),
    deleteReply = HttpResult(code = 200, body = "", isSuccess = true),
) {
    var getsDead = false
    val mints: Int get() = submits
    val deletes: Int get() = deleteCalls.size
    init {
        onGet = {
            if (getsDead) HttpResult(code = -1, body = null, isSuccess = false)
            else HttpResult(code = 404, body = "not found", isSuccess = false)   // up, by design
        }
    }
}

class MintAbortTest {

    @Test
    fun abortRaisedBetweenTransientRetries_stopsTheLoopPromptly() {
        val relay = DeadPostRelay()
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", relay)

        // The abort fires the moment the first attempt has been made — exactly the
        // shape of a deadline expiring, or the user backing out, mid-mint.
        assertNull(mgr.mintInbox(abort = PowAbort { relay.posts >= 1 }))
        assertEquals(
            1, relay.posts,
            "an aborted mint must stop at the current attempt, not grind through all 12 transient retries",
        )
    }

    @Test
    fun abortAlreadySignalledBeforeTheFirstAttempt_sendsNothing() {
        val relay = DeadPostRelay()
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", relay)

        assertNull(mgr.mintInbox(abort = PowAbort { true }))
        assertEquals(0, relay.posts, "a mint whose deadline has already passed must not touch the relay")
    }

    @Test
    fun withoutAnAbort_theHandshakeStillCompletes() {
        // Guard against "fixing" the overrun by breaking the mint: the abort check
        // must be invisible to a caller that never aborts.
        val relay = PairMintRelay()
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", relay)

        val minted = mgr.mintInbox()
        assertNotNull(minted)
        assertEquals(MINT_ABORT_INBOX, minted.inboxId)
        assertEquals(2, relay.posts, "challenge + submit, exactly as before")
    }

    @Test
    fun abortBetweenThePairsTwoMints_stopsTheSecondAndCleansUpTheFirst() = runTest {
        val relay = PairMintRelay()
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", relay)

        // Fires as soon as the FIRST inbox has been minted: the deadline expired
        // while that mint was running, which is the realistic case (the first mint
        // is allowed to consume the whole budget).
        val pair = mgr.mintInboxPair(abort = PowAbort { relay.mints >= 1 })

        assertNull(pair, "an aborted pair mint yields nothing")
        assertEquals(2, relay.posts, "the SECOND mint must never start (2 POSTs = one handshake)")
        assertEquals(
            1, relay.deletes,
            "the minted-but-never-shared main inbox is destroyed, not left parked on the relay",
        )
    }

    @Test
    fun abortBeforeTheThirdMint_stopsItButKeepsThePairing() = runTest {
        // The pairing mint is THREE sequential 20-bit grinds, so a deadline is
        // likeliest to expire before the last one — and the MINT-ABORT check still
        // stops that third grind dead.
        //
        // What it deliberately does NOT do is abandon the pairing. The group inbox
        // is an OPTIONAL optimisation whose absence every layer already handles
        // (`MintedInboxPair.grp` is nullable, `PairingVault` writes no `*-grp` row,
        // the QR carries no `gib`, `sendGroupText` falls back to the text inbox,
        // and §1.6's backfill converges it on a later control sweep) — so throwing
        // away two good inboxes, two completed grinds and the user's IRL pairing
        // moment would be strictly worse than shipping the pairing in exactly the
        // state every pre-change pairing is already in. Contrast
        // `abortAfterTheFirstMint…` above: the CONTROL inbox is not optional.
        val relay = PairMintRelay()
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", relay)

        val pair = mgr.mintInboxPair(abort = PowAbort { relay.mints >= 2 })

        assertNotNull(pair, "an aborted THIRD mint must still yield a usable pairing")
        assertNull(pair.grp, "…without the group inbox, which the backfill mints later")
        assertEquals(4, relay.posts, "the THIRD mint must never start (2 handshakes = 4 POSTs)")
        assertEquals(
            0, relay.deletes,
            "neither successfully minted inbox may be destroyed — they are the pairing",
        )
    }

    @Test
    fun withoutAnAbort_thePairStillMintsAllThreeInboxes() = runTest {
        val relay = PairMintRelay()
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", relay)

        val pair = mgr.mintInboxPair()
        assertNotNull(pair)
        assertEquals(3, relay.mints, "the text, the control AND the group inbox")
        assertEquals(6, relay.posts, "three two-request handshakes")
        assertEquals(0, relay.deletes, "nothing to clean up on the happy path")
        assertNotNull(pair.grp, "a successful pair mint always carries a group inbox")
    }

    @Test
    fun warmGate_isSkippedOnceTheTransportHasProvenARoundTrip() = runTest {
        // P6a: the pre-mint warm gate exists to avoid firing PoW + POSTs into a cold
        // circuit. Once ANY relay request on this transport has completed a
        // round-trip, that question is already answered — probing again only adds a
        // round-trip in front of the mint, and on a circuit that has since gone
        // quiet it burns up to WARM_PROBE_MAX_WAIT_MS before minting anyway.
        val relay = PairMintRelay()
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", relay)

        assertTrue(mgr.isRelayReachable(), "the relay's by-design 404 is a completed round-trip")
        assertTrue(mgr.hasCompletedRelayRoundTrip())
        val getsAfterProbe = relay.gets
        relay.getsDead = true   // a probe from here would fail, and keep failing

        val pair = mgr.mintInboxPair()
        assertNotNull(pair, "the mint proceeds on the already-proven circuit")
        assertEquals(getsAfterProbe, relay.gets, "an already-warm transport must not re-probe before minting")
    }
}

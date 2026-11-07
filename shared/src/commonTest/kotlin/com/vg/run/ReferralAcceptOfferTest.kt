package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

// ---------------------------------------------------------------------------
// acceptOffer — the REAL suspend entry point (referral.md, "Crash-window rule").
//
// Every pre-existing referral test reaches finalize through `registerAccepted`
// (= stageAccept + confirmAcceptSent with INJECTED material), so everything only
// acceptOffer owns was untested: the PoW inbox-pair mint, the mint deadline it
// hands the mint as a PowAbort, the persist-BEFORE-send ordering (st=0 → st=1),
// the rule that a failed send LEAVES the offer pending for a Retry, and the
// RETRY REUSE that re-sends the SAME staged keypair + minted pair instead of
// minting fresh (a fresh key would derive a secret the peer — who may already
// hold the first public key — can never match).
//
// Driven over a scripted RelayHttp double like ReferralRedriveTest: a POST to
// `/inbox` is the two-request PoW mint handshake, a POST to `/inbox/{id}` is the
// accept send, and the base GET is the mint's warm gate.
// ---------------------------------------------------------------------------

/** Both bridges this file needs: AES-GCM (the control send) and X25519
 *  (acceptOffer generates the ephemeral keypair itself). */
private fun aoCryptoUp(): Boolean = try {
    aesGcmEncrypt(ByteArray(1), generateSecureRandom(32), ByteArray(0))
    x25519GenerateKeypair()
    true
} catch (_: Exception) { false }

/** The introducer's outbound control inbox — where our accept must be POSTed. */
private val AO_CTL_OUT = "aoct" + "1".repeat(28)
/** Ids + caps the scripted relay hands out, mint by mint. */
private val AO_MINT_1 = "aomainA" + "M".repeat(25)
private val AO_MINT_2 = "aoctlA" + "N".repeat(26)
private val AO_MINT_3 = "aomainB" + "P".repeat(25)
private val AO_MINT_4 = "aoctlB" + "Q".repeat(26)
/** The THIRD inbox of a pairing mint (group text). Queued between our own pair
 *  and AO_MINT_3/4, which stay reserved for the PEER's announced ids. */
private val AO_MINT_G = "aogrpA" + "R".repeat(26)
private val AO_CAP_R = "R".repeat(43)
private val AO_CAP_W = "W".repeat(43)
private val AO_CAP_S = "S".repeat(43)
private val AO_CAP_X = "X".repeat(43)

private val AO_CHALLENGE = POW_CHALLENGE_BODY

private fun aoMintBody(inboxId: String, read: String, write: String) =
    """{"inboxId":"$inboxId","readCapability":"$read","writeCapability":"$write","expiresAt":12345}"""

/**
 * Relay double for the accept path. Replies by REQUEST SHAPE rather than from a
 * FIFO script (the mint fans two POSTs per inbox and the send interleaves with
 * them), so a dispatcher/ordering change can't silently mis-script a case.
 */
private class AcceptRelay : MintingRelay(challengeBody = AO_CHALLENGE, deleteReply = HttpResult(200, "", true)) {
    private val mintQueue = mutableListOf(
        Triple(AO_MINT_1, AO_CAP_R, AO_CAP_W),
        Triple(AO_MINT_2, AO_CAP_S, AO_CAP_X),
        Triple(AO_MINT_G, AO_CAP_R, AO_CAP_X),
        Triple(AO_MINT_3, AO_CAP_R, AO_CAP_W),
        Triple(AO_MINT_4, AO_CAP_S, AO_CAP_X),
    )

    /** When true every mint SUBMIT is refused with 507 — a TERMINAL relay code. */
    var mintFails = false
    /** The reply every accept send (POST /inbox/{id}) gets. */
    var sendReply: HttpResult = HttpResult(202, "", true)

    var mintsCompleted = 0
    val deletes: Int get() = deleteCalls.size

    init {
        onSend = { sendReply }
        mintReply = {
            if (mintFails) HttpResult(507, """{"error":"inbox limit"}""", false)
            else {
                val next = mintQueue.removeAt(0)
                mintsCompleted++
                HttpResult(201, aoMintBody(next.first, next.second, next.third), true)
            }
        }
    }
}

/** Introducee (Bob) paired with the introducer (Alice) on the control channel. */
private class IntroduceeFixture {
    val vault = InMemoryVault()
    val relay = AcceptRelay()
    val mgr = MessageManager(vault, "http://relay.test", relay as RelayHttp)

    init {
        vault.insertContact(ContactRecord("alice", generateSecureRandom(32), 0, "Alice", 0L))
        vault.insertInboxId(
            InboxIdRecord(AO_CTL_OUT, "alice", 1L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_CTL, AO_CAP_W)
        )
    }

    fun newManager() = ReferralManager(vault) { mgr }

    // "Running Fox" is a format-conforming alias (ContactAliasGenerator),
    // so it survives ReferralManager's sanitization verbatim — a non-conforming
    // default here would make `rec.peerAlias` non-deterministic in every test
    // that relies on it below.
    fun deliverOffer(rm: ReferralManager, introId: String, peerAlias: String = "Running Fox") =
        rm.handleControl(
            "alice", MessageManager.CONTROL_KIND_REFERRAL_OFFER,
            """{"ii":${jsonEscapeString(introId)},"pa":${jsonEscapeString(peerAlias)}}""",
        )
}

private fun storedAcceptFor(vault: InMemoryVault, introId: String): StoredAccept? =
    vault.getMeta(ReferralMetaKeys.ACCEPT_PREFIX + introId)?.let { decodeStoredAccept(it) }

private fun metaKeysWithPrefix(vault: InMemoryVault, prefix: String) =
    vault.meta.keys.filter { it.startsWith(prefix) }

class ReferralAcceptOfferTest {

    // -- (a) happy path: mint → stage → send → st=1 ---------------------------

    @Test
    fun acceptOffer_mintsStagesSendsAndConfirms() = runTest {
        if (!aoCryptoUp()) return@runTest
        val f = IntroduceeFixture()
        val rm = f.newManager()
        f.deliverOffer(rm, "ao1")

        assertTrue(rm.acceptOffer("ao1"), "a clean mint + send must report success")

        // The accept left, addressed to the INTRODUCER's control inbox — and it
        // asks the relay for 7-day retention (the relay's own default is
        // 24 h, so without ?ttl the blob could expire off the inbox while both
        // ends of the handshake were still alive).
        assertEquals(1, f.relay.sendUrls.size, "exactly one accept send")
        assertEquals("/inbox/$AO_CTL_OUT?ttl=604800", f.relay.sendUrls.single().removePrefix("http://relay.test"))
        // All THREE inboxes were minted (three two-request handshakes).
        assertEquals(3, f.relay.mintsCompleted)
        assertEquals(6, f.relay.mintPosts)

        // The record is staged and CONFIRMED (st=1), holding exactly the minted pair.
        val rec = assertNotNull(storedAcceptFor(f.vault, "ao1"), "acceptOffer must persist the accept material")
        assertTrue(rec.sent, "a confirmed delivery flips the record to st=1")
        assertEquals(0, rec.attempts)
        assertEquals("alice", rec.introducerContactId)
        assertEquals("Running Fox", rec.peerAlias)
        assertEquals(AO_MINT_1, rec.minted.main.inboxId)
        assertEquals(AO_CAP_R, rec.minted.main.readCapability)
        assertEquals(AO_MINT_2, rec.minted.ctl.inboxId)
        assertEquals(AO_MINT_G, rec.minted.grp?.inboxId, "the staged record carries the group inbox too")
        assertEquals(32, rec.privateKey.size)
        assertEquals(32, rec.publicKey.size)

        // The offer is consumed on the CONFIRMED send, in RAM and in the vault.
        assertTrue(rm.pendingOffers().isEmpty(), "a confirmed accept consumes the offer")
        assertNull(f.vault.getMeta(ReferralMetaKeys.OFFER_PREFIX + "ao1"))
        // Nothing was finalized — no peer accept has arrived yet.
        assertEquals(1, f.vault.getAllContacts().size, "only the introducer exists until the peer accepts")
    }

    // -- (b) send failure: offer survives, and the Retry REUSES the material ---

    @Test
    fun acceptOffer_sendFails_offerSurvives_andRetryReusesTheSameMaterial() = runTest {
        if (!aoCryptoUp()) return@runTest
        val f = IntroduceeFixture()
        val rm = f.newManager()
        f.deliverOffer(rm, "ao2")

        f.relay.sendReply = HttpResult(500, "nope", false)
        assertFalse(rm.acceptOffer("ao2"), "a refused send must report failure")

        // The offer is still pending so the UI can re-present a Retry…
        assertEquals(listOf("ao2"), rm.pendingOffers().map { it.introId }, "a failed send must NOT consume the offer")
        assertNotNull(f.vault.getMeta(ReferralMetaKeys.OFFER_PREFIX + "ao2"))
        // …and the staged material is durable at st=0 with the attempt counted.
        val first = assertNotNull(storedAcceptFor(f.vault, "ao2"), "the accept is persisted BEFORE the send (st=0)")
        assertFalse(first.sent, "an unconfirmed delivery must stay st=0")
        assertEquals(1, first.attempts)
        val mintsAfterFirst = f.relay.mintsCompleted

        // The user taps Retry. It must re-send THE SAME public key and THE SAME
        // minted pair — a fresh keypair would derive a secret the peer (who may
        // already hold the first public key) can never match.
        f.relay.sendReply = HttpResult(202, "", true)
        assertTrue(rm.acceptOffer("ao2"), "the retry must succeed on a healthy relay")

        val second = assertNotNull(storedAcceptFor(f.vault, "ao2"))
        assertTrue(second.sent, "the retry's confirmed send flips the record to st=1")
        assertEquals(0, second.attempts, "a confirmed send resets the bounded attempt counter")
        assertEquals(first.publicKey.toList(), second.publicKey.toList(), "the retry must reuse the SAME public key")
        assertEquals(first.privateKey.toList(), second.privateKey.toList(), "the retry must reuse the SAME private key")
        assertEquals(first.minted.main.inboxId, second.minted.main.inboxId, "the retry must reuse the SAME minted inbox")
        assertEquals(first.minted.ctl.inboxId, second.minted.ctl.inboxId)
        assertEquals(
            mintsAfterFirst, f.relay.mintsCompleted,
            "a retry must NOT re-mint — that is a second PoW grind on an already-degraded circuit",
        )
        assertEquals(2, f.relay.sendUrls.size, "one failed send + one retry")
        assertTrue(rm.pendingOffers().isEmpty(), "the confirmed retry finally consumes the offer")
    }

    // -- (c) mint failure: no partial state --------------------------------

    @Test
    fun acceptOffer_mintFails_returnsFalse_offerStaysPending_andNoPartialAcceptRecord() = runTest {
        if (!aoCryptoUp()) return@runTest
        val f = IntroduceeFixture()
        val rm = f.newManager()
        f.deliverOffer(rm, "ao3")

        f.relay.mintFails = true          // 507 inbox-limit: terminal, no retry
        assertFalse(rm.acceptOffer("ao3"), "a mint that cannot complete must not report success")

        assertEquals(listOf("ao3"), rm.pendingOffers().map { it.introId }, "the offer stays approvable")
        assertNotNull(f.vault.getMeta(ReferralMetaKeys.OFFER_PREFIX + "ao3"))
        assertTrue(
            metaKeysWithPrefix(f.vault, ReferralMetaKeys.ACCEPT_PREFIX).isEmpty(),
            "no accept material may be staged when there is no inbox pair to stage",
        )
        assertEquals(0, f.relay.sendUrls.size, "nothing may be sent without a minted pair")
        assertEquals(1, f.vault.getAllContacts().size)
    }

    // -- (d) the mint DEADLINE is wired into the mint's abort ------------------

    @Test
    fun acceptOffer_whenTheMintDeadlineHasPassed_touchesTheRelayNotAtAll() = runTest {
        if (!aoCryptoUp()) return@runTest
        val f = IntroduceeFixture()
        val rm = f.newManager()
        f.deliverOffer(rm, "ao4")

        // acceptOffer computes `deadline = clockMs() + ACCEPT_MINT_DEADLINE_MS`
        // and hands the mint a PowAbort over it. A clock that jumps a full
        // deadline forward after the FIRST read is the shape of a deadline that
        // expired while the accept was queued: mintInboxPair's entry check fires
        // before any PoW or POST (MintAbortTest pins that check itself).
        var reads = 0
        val base = currentTimeMillis()
        rm.clockMs = { if (reads++ == 0) base else base + 10L * 480_000L }

        assertFalse(rm.acceptOffer("ao4"), "an expired deadline must not report success")
        assertEquals(0, f.relay.mintPosts, "a mint whose deadline has already passed must not touch the relay")
        assertEquals(0, f.relay.sendUrls.size)
        assertTrue(
            metaKeysWithPrefix(f.vault, ReferralMetaKeys.ACCEPT_PREFIX).isEmpty(),
            "an aborted mint stages nothing",
        )
        assertEquals(listOf("ao4"), rm.pendingOffers().map { it.introId }, "the offer stays approvable")
    }

    @Test
    fun acceptOffer_unknownIntroId_isANoOp() = runTest {
        if (!aoCryptoUp()) return@runTest
        val f = IntroduceeFixture()
        val rm = f.newManager()

        assertFalse(rm.acceptOffer("never-offered"))
        assertEquals(0, f.relay.mintPosts, "an unknown introId must not mint")
        assertEquals(0, f.relay.sendUrls.size)
    }

    // -- (2) decline AFTER a failed send, i.e. over STAGED material ------------

    @Test
    fun declineAfterAFailedSend_dropsOfferPendingAndStash_andStaysDeclined() = runTest {
        if (!aoCryptoUp()) return@runTest
        val f = IntroduceeFixture()
        val rm = f.newManager()
        f.deliverOffer(rm, "ao5")

        // Approve → the send fails → the durable offer leg re-presents the offer → this time DECLINE.
        f.relay.sendReply = HttpResult(500, "nope", false)
        assertFalse(rm.acceptOffer("ao5"))
        assertNotNull(storedAcceptFor(f.vault, "ao5"), "precondition: material really is staged")
        // A peer accept relayed before the decline is stashed against the same id.
        rm.handleControl(
            "alice", MessageManager.CONTROL_KIND_REFERRAL_ACCEPT,
            """{"ii":"ao5","pk":${jsonEscapeString(encodeBase64(x25519GenerateKeypair().publicKey))},""" +
                """"ib":${jsonEscapeString(AO_MINT_3)},"wc":${jsonEscapeString(AO_CAP_W)},""" +
                """"cib":${jsonEscapeString(AO_MINT_4)},"cwc":${jsonEscapeString(AO_CAP_X)}}""",
        )
        assertEquals(1, metaKeysWithPrefix(f.vault, ReferralMetaKeys.STASH_PREFIX).size, "precondition: a stash exists")

        rm.declineOffer("ao5")

        assertTrue(rm.pendingOffers().isEmpty(), "a declined offer disappears from the UI")
        assertNull(f.vault.getMeta(ReferralMetaKeys.OFFER_PREFIX + "ao5"), "the offer record must go")
        assertNull(
            f.vault.getMeta(ReferralMetaKeys.ACCEPT_PREFIX + "ao5"),
            "staged material owns a live redrive obligation — a decline must drop it, or a later sweep " +
                "would send an accept for a referral the user just refused",
        )
        assertNull(f.vault.getMeta(ReferralMetaKeys.STASH_PREFIX + "ao5"), "the stash must go with it")
        // The tombstone is written… under the HASHED v2 key (1C-2): the raw introId
        // must never appear in the vault, only doneTokenFor(introId).
        assertNull(f.vault.getMeta(ReferralMetaKeys.COMPLETED_KEY), "no legacy v1 tombstone is ever written by current code")
        val done = assertNotNull(f.vault.getMeta(ReferralMetaKeys.COMPLETED_KEY_V2))
        assertTrue(
            decodeCompletedIntros(done, 128).contains(ReferralManager.doneTokenFor("ao5")),
            "a decline is recorded as completed",
        )
        assertFalse(done.contains("ao5"), "the raw introId must never be persisted in the tombstone (1C-2)")
        // …so a re-delivered offer stays declined, and no sweep re-sends anything.
        val sendsBefore = f.relay.sendUrls.size
        f.deliverOffer(rm, "ao5")
        assertTrue(rm.pendingOffers().isEmpty(), "the tombstone must drop the re-delivery")
        f.relay.sendReply = HttpResult(202, "", true)
        rm.runMaintenance()
        assertEquals(sendsBefore, f.relay.sendUrls.size, "a declined referral must never be redriven")
        assertEquals(1, f.vault.getAllContacts().size, "a declined referral creates no contact")
    }

    /** The RAM half of the same rule: the staged ephemeral X25519 private key is
     *  OVERWRITTEN on decline, not merely dropped. Driven through
     *  `registerAccepted` because that is the only seam that lets a test hold a
     *  reference to the exact key array acceptOffer would otherwise mint
     *  internally; the decline branch it exercises is identical. */
    @Test
    fun decline_zeroesTheStagedEphemeralPrivateKey() {
        if (!aoCryptoUp()) return
        val f = IntroduceeFixture()
        val rm = f.newManager()
        f.deliverOffer(rm, "ao6")
        val mine = x25519GenerateKeypair()
        rm.registerAccepted(
            "ao6", rm.pendingOffers().single(), mine,
            MintedInboxPair(
                MintedInbox(AO_MINT_1, AO_CAP_R, AO_CAP_W, Long.MAX_VALUE),
                MintedInbox(AO_MINT_2, AO_CAP_S, AO_CAP_X, Long.MAX_VALUE),
            ),
        )
        assertTrue(mine.privateKey.any { it != 0.toByte() }, "precondition: a fresh key has nonzero bytes")

        rm.declineOffer("ao6")

        assertTrue(
            mine.privateKey.all { it == 0.toByte() },
            "a declined referral's ephemeral private key must be overwritten, not just dereferenced",
        )
    }

    // -- (10) the introducee-side send budget ---------------------------------
    //
    // This budget is PER SESSION: 12 attempts inside ONE session, record
    // KEPT on exhaustion, user retry unbounded; a NEW session re-arms the
    // counter to 0 rather than inheriting the persisted value, so a relay that
    // was down for one session can no longer permanently disarm the obligation.
    // The re-arm itself is pinned by
    // ReferralAttemptBudgetPerSessionTest.anExhaustedAcceptBudget_isRearmedByTheNextSession,
    // and the within-session bound by …withinOneSession_theBudgetStillBounds.

    @Test
    fun unsentAccept_stopsAutomaticRedriveAtItsBudget_butAUserRetryStillWorks() = runTest {
        if (!aoCryptoUp()) return@runTest
        val f = IntroduceeFixture()
        // A staged-but-unconfirmed accept plus its still-live offer — exactly the
        // state a failed send (or process death mid-send) leaves behind.
        val priv = ByteArray(32) { (it + 1).toByte() }
        val pub = ByteArray(32) { (it + 100).toByte() }
        val minted = MintedInboxPair(
            MintedInbox(AO_MINT_1, AO_CAP_R, AO_CAP_W, Long.MAX_VALUE),
            MintedInbox(AO_MINT_2, AO_CAP_S, AO_CAP_X, Long.MAX_VALUE),
        )
        f.vault.putMeta(
            ReferralMetaKeys.ACCEPT_PREFIX + "ao7",
            encodeStoredAccept(StoredAccept("alice", "Carol", priv, pub, minted, false, 0, currentTimeMillis())),
        )
        f.vault.putMeta(
            ReferralMetaKeys.OFFER_PREFIX + "ao7",
            encodeStoredOffer(StoredOffer("alice", "Alice", "Carol", currentTimeMillis())),
        )
        val rm = f.newManager()
        assertEquals(listOf("ao7"), rm.pendingOffers().map { it.introId }, "an unsent accept keeps its offer")

        // 20 sweeps, every send refused: the AUTOMATIC redrive stops at 12.
        f.relay.sendReply = HttpResult(500, "nope", false)
        repeat(20) { rm.runMaintenance() }
        assertEquals(12, f.relay.sendUrls.size, "the automatic redrive must stop at its 12-attempt budget")

        // The record is KEPT — `sendDirectControl == false` does not prove the blob
        // never landed, so the material must stay reusable; only the TTL reclaims it.
        val parked = assertNotNull(storedAcceptFor(f.vault, "ao7"), "an exhausted budget must not delete the material")
        assertFalse(parked.sent)
        assertEquals(12, parked.attempts)
        assertEquals(priv.toList(), parked.privateKey.toList())

        // …and a USER-driven retry still goes out, with the same staged material.
        f.relay.sendReply = HttpResult(202, "", true)
        assertTrue(rm.acceptOffer("ao7"), "a user retry is not bound by the automatic redrive budget")
        assertEquals(13, f.relay.sendUrls.size, "the user retry is one more send")
        assertEquals(0, f.relay.mintsCompleted, "the user retry must reuse the staged pair, never re-mint")
        val confirmed = assertNotNull(storedAcceptFor(f.vault, "ao7"))
        assertTrue(confirmed.sent, "the user retry's confirmed send flips the record to st=1")
        assertEquals(0, confirmed.attempts)
        assertEquals(priv.toList(), confirmed.privateKey.toList(), "same private key")
        assertEquals(pub.toList(), confirmed.publicKey.toList(), "same public key")
        assertEquals(AO_MINT_1, confirmed.minted.main.inboxId, "same minted pair")
    }
}

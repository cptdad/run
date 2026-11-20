package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// A relay 404 on a SEND is evidence that the peer's inbox is gone
// (PeerInboxGone.kt). Before this, every queued item that re-drives on failure
// re-POSTed to a missing inbox for the life of its record: a referral offer to a
// contact who deleted the introducer was retried for up to 28 days (12 POSTs per
// session) and the introduction never ended. These tests pin:
//  - the evidence rule (relay must have proven it holds our state, spaced 404s,
//    bound to the inbox id, cleared by any 2xx, aged out, malformed = none);
//  - the referral re-drives ending (offer / relayed accept) or stopping (our own
//    accept) on it, with nothing destroyed;
//  - the brick-safety cases: a relay that lost ALL state, a transport failure and
//    a single 404 never end anything;
//  - the sibling loops (channel-lost notice, Maximum level notice) stop re-POSTing.
// ---------------------------------------------------------------------------

private val PG_CAP = "A".repeat(43)
private val PG_B_CTL_OUT = "bgone" + "1".repeat(27)
private val PG_C_CTL_OUT = "clive" + "2".repeat(27)
private val PG_C_CTL_IN = "cownx" + "3".repeat(27)
private const val HOUR = 60L * 60 * 1000

/** Route-keyed relay: 404 for [gone] inboxes (or for everything when the relay has
 *  "lost its state"), a transport failure while [transportDown], 202 otherwise;
 *  every drain is an empty 200. Records every request. */
private class GoneRelay : FakeRelayHttp() {
    val gone = mutableSetOf<String>()
    var lostAllState = false
    var transportDown = false
    private val rejected = HttpResult(404, """{"error":"request rejected"}""", false)

    init {
        onPost = { r ->
            when {
                transportDown -> RELAY_DEAD
                lostAllState || relayInboxIdOf(r.url) in gone -> rejected
                else -> RELAY_OK_202
            }
        }
        onGet = {
            when {
                transportDown -> RELAY_DEAD
                lostAllState -> rejected
                else -> RELAY_EMPTY_DRAIN
            }
        }
    }

    fun postsTo(inboxId: String) = requestsOf("POST").count { relayInboxIdOf(it.url) == inboxId }
}

/** Introducer paired with bb and cc (control rows), plus cc's inbound control row so
 *  a control drain can prove the relay holds our state. */
private class GoneFixture {
    val vault = InMemoryVault()
    val relay = GoneRelay()
    val mgr = MessageManager(vault, "http://relay.test", relay)
    var now = currentTimeMillis()
    val rm: ReferralManager

    init {
        mgr.peerInboxEvidenceClockMs = { now }
        mgr.sendRetrySleep = { }
        vault.insertContact(ContactRecord("bb", generateSecureRandom(32), 0, "Bob", 0L))
        vault.insertContact(ContactRecord("cc", generateSecureRandom(32), 0, "Carol", 0L))
        vault.insertInboxId(InboxIdRecord(PG_B_CTL_OUT, "bb", 1L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_CTL, PG_CAP))
        vault.insertInboxId(InboxIdRecord(PG_C_CTL_OUT, "cc", 1L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_CTL, PG_CAP))
        vault.insertInboxId(InboxIdRecord(PG_C_CTL_IN, "cc", 1L, Long.MAX_VALUE, MessageManager.DIR_INBOUND_CTL, PG_CAP))
        rm = ReferralManager(vault) { mgr }
        rm.clockMs = { now }
    }

    /** One control-sweep drain of OUR inbox: the relay answers for our state (or not). */
    fun sweepDrain() { mgr.pollControlMessages("cc") }

    fun sessions() = vault.meta.keys.filter { it.startsWith(ReferralMetaKeys.SESSION_PREFIX) }
    fun redrives() = vault.meta.keys.filter { it.startsWith(ReferralMetaKeys.REDRIVE_PREFIX) }
    fun evidence(contactId: String) = vault.getMeta(PeerInboxGonePolicy.keyFor(contactId))
}

class PeerInboxGonePolicyTest {
    private val tag = PeerInboxGonePolicy.inboxTag(PG_B_CTL_OUT)
    private val t0 = 1_700_000_000_000L

    @Test
    fun aNotFoundCountsOnlyWithProofOfRelayState_andOnlyOncePerSpacing() {
        val none = emptyList<PeerInboxGonePolicy.Entry>()
        assertSame(none, PeerInboxGonePolicy.afterNotFound(none, tag, t0, relayProvedOurState = false),
            "a relay that has not proven it holds our state counts nothing")
        val one = PeerInboxGonePolicy.afterNotFound(none, tag, t0, true)
        assertEquals(1, one.single().count)
        assertSame(one, PeerInboxGonePolicy.afterNotFound(one, tag, t0 + HOUR - 1, true), "a burst counts once")
        assertEquals(PeerInboxVerdict.HOLD, PeerInboxGonePolicy.verdict(one, tag, t0 + 1))
        assertEquals(PeerInboxVerdict.SEND, PeerInboxGonePolicy.verdict(one, tag, t0 + HOUR))
        val two = PeerInboxGonePolicy.afterNotFound(one, tag, t0 + HOUR, true)
        val three = PeerInboxGonePolicy.afterNotFound(two, tag, t0 + 2 * HOUR, true)
        assertEquals(3, three.single().count)
        assertEquals(PeerInboxVerdict.GONE, PeerInboxGonePolicy.verdict(three, tag, t0 + 2 * HOUR))
        assertEquals(3, PeerInboxGonePolicy.afterNotFound(three, tag, t0 + 9 * HOUR, true).single().count, "capped")
    }

    @Test
    fun evidenceIsBoundToTheInbox_clearedByA2xx_agedOut_andBackwardClockCountsNothing() {
        var e = emptyList<PeerInboxGonePolicy.Entry>()
        repeat(3) { e = PeerInboxGonePolicy.afterNotFound(e, tag, t0 + it * HOUR, true) }
        val otherInbox = PeerInboxGonePolicy.inboxTag("other" + "9".repeat(27))
        assertEquals(PeerInboxVerdict.SEND, PeerInboxGonePolicy.verdict(e, otherInbox, t0 + 2 * HOUR),
            "a re-announced inbox starts clean")
        assertTrue(PeerInboxGonePolicy.afterAccepted(e, tag).isEmpty(), "any 2xx on that inbox clears it")
        assertEquals(PeerInboxVerdict.SEND,
            PeerInboxGonePolicy.verdict(e, tag, t0 + 2 * HOUR + PeerInboxGonePolicy.EVIDENCE_MAX_AGE_MS + 1),
            "a week-old verdict re-probes")
        assertEquals(PeerInboxVerdict.SEND, PeerInboxGonePolicy.verdict(e, tag, t0 - 1), "backward clock fails toward SEND")
        val one = PeerInboxGonePolicy.afterNotFound(emptyList(), tag, t0, true)
        assertSame(one, PeerInboxGonePolicy.afterNotFound(one, tag, t0 - 5 * HOUR, true), "no spacing proof backward")
    }

    @Test
    fun codec_roundTrips_andAnythingMalformedIsNoEvidence() {
        val e = PeerInboxGonePolicy.afterNotFound(emptyList(), tag, t0, true)
        assertEquals(1, PeerInboxGonePolicy.decode(PeerInboxGonePolicy.encode(e)).single().count)
        assertNull(PeerInboxGonePolicy.encode(emptyList()))
        for (bad in listOf("", "v1", "v2;$tag,1,1", "v1;$tag,0,1", "v1;$tag,4,1", "v1;short,1,1",
            "v1;$tag,1,x", "v1;$tag,1", "v1;$tag,1,1;$tag,1,2", "garbage")) {
            assertTrue(PeerInboxGonePolicy.decode(bad).isEmpty(), "must decode as no evidence: $bad")
        }
    }
}

class PeerInboxGoneReferralTest {

    /** THE defect: the introducer kept re-POSTing the offer to a contact who deleted
     *  it, and the introduction never ended. Fails on the pre-fix code (the session
     *  survives and every sweep POSTs). */
    @Test
    fun anOfferToADeletedContact_endsTheIntroduction_afterSpacedNotFounds() {
        if (!aeadUp()) return
        val f = GoneFixture()
        f.relay.gone += PG_B_CTL_OUT
        val introId = assertNotNull(f.rm.startReferral("bb", "cc"))
        assertEquals(1, f.sessions().size)

        repeat(4) {
            f.sweepDrain()
            f.rm.runMaintenance()
            f.rm.runMaintenance()   // a second sweep inside the same hour sends nothing (HOLD)
            f.now += HOUR + 1
        }
        assertTrue(f.sessions().isEmpty(), "the introduction ends instead of living for 28 days")
        // startReferral's own offer + one counted probe per hour until the verdict (3).
        assertEquals(4, f.relay.postsTo(PG_B_CTL_OUT), "bounded: one POST per hour, then none")

        val before = f.relay.postsTo(PG_B_CTL_OUT)
        repeat(5) { f.sweepDrain(); f.rm.runMaintenance(); f.now += HOUR + 1 }
        assertEquals(before, f.relay.postsTo(PG_B_CTL_OUT), "nothing is sent for an ended introduction")
        // Nothing irreversible: both contacts and their rows are untouched.
        assertNotNull(f.vault.getContact("bb")); assertNotNull(f.vault.getContact("cc"))
        assertNotNull(f.vault.getInboxIdForContact("bb", MessageManager.DIR_OUTBOUND_CTL))
        // A late accept for the ended introduction is not relayed anywhere.
        f.relay.clearRequests()
        f.rm.handleControl("cc", MessageManager.CONTROL_KIND_REFERRAL_ACCEPT, """{"ii":${jsonEscapeString(introId)}}""")
        assertTrue(f.relay.requestsOf("POST").isEmpty())
    }

    /** Brick-safety: a relay that came back with NO state 404s our own inboxes too —
     *  nothing is counted, nothing ends; the offer keeps its ordinary bounded redrive. */
    @Test
    fun aRelayThatLostAllState_neverEndsAnything() {
        if (!aeadUp()) return
        val f = GoneFixture()
        f.relay.gone += PG_B_CTL_OUT
        assertNotNull(f.rm.startReferral("bb", "cc"))   // bb's offer undelivered → redriven
        f.relay.lostAllState = true
        // Age out the proof startReferral's accepted offer gave (BEFORE the loop), so
        // the only thing that could make a 404 count below is the own-inbox 404 itself.
        f.now += PeerInboxGonePolicy.RELAY_PROOF_MAX_AGE_MS + 1
        repeat(5) {
            f.sweepDrain()              // 404 on OUR inbox — must NOT count as proof…
            f.now += 1_000              // …and the clock stays well inside the proof window
            f.rm.runMaintenance()       // the offer's 404 would count if it had
            f.now += HOUR + 1
        }
        assertEquals(1, f.sessions().size, "an emptied relay must never end an introduction")
        assertNull(f.evidence("bb"), "and must leave no evidence behind")
    }

    /** A MINT is not proof that the relay holds our state: an emptied relay answers
     *  an inbox creation with 2xx as well. A 404 on a send right after a successful
     *  mint (and nothing else) must not count. */
    @Test
    fun aSuccessfulMint_isNotProofOfRelayState() {
        if (!aeadUp()) return
        val vault = InMemoryVault()
        val relay = MintingRelay(onSend = { HttpResult(404, """{"error":"request rejected"}""", false) })
        val mgr = MessageManager(vault, "http://relay.test", relay)
        var now = currentTimeMillis()
        mgr.peerInboxEvidenceClockMs = { now }
        mgr.sendRetrySleep = { }
        vault.insertContact(ContactRecord("bb", generateSecureRandom(32), 0, "Bob", 0L))
        vault.insertInboxId(InboxIdRecord(PG_B_CTL_OUT, "bb", 1L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_CTL, PG_CAP))
        assertNotNull(mgr.mintInbox(), "the mint itself succeeds")
        now += 1_000
        assertTrue(!mgr.sendDirectControl("bb", MessageManager.CONTROL_KIND_SCREENSHOT, "{}"))
        assertEquals(1, relay.sendUrls.size, "the append reached the relay and was answered 404")
        assertNull(vault.getMeta(PeerInboxGonePolicy.keyFor("bb")), "a mint is not proof: the 404 counts nothing")
    }

    /** A transport failure is not evidence of anything. */
    @Test
    fun transportFailures_neverCount() {
        if (!aeadUp()) return
        val f = GoneFixture()
        f.relay.gone += PG_B_CTL_OUT
        assertNotNull(f.rm.startReferral("bb", "cc"))
        f.relay.transportDown = true
        repeat(5) { f.rm.runMaintenance(); f.now += HOUR + 1 }
        assertEquals(1, f.sessions().size)
        assertNull(f.evidence("bb"))
    }

    /** Two counted 404s, then the inbox answers again: the evidence is cleared and the
     *  offer is delivered — a relay hiccup costs a delay, never the introduction. */
    @Test
    fun aRecoveredInbox_clearsTheEvidence_andTheOfferLands() {
        if (!aeadUp()) return
        val f = GoneFixture()
        f.relay.gone += PG_B_CTL_OUT
        assertNotNull(f.rm.startReferral("bb", "cc"))
        repeat(2) { f.sweepDrain(); f.rm.runMaintenance(); f.now += HOUR + 1 }
        assertNotNull(f.evidence("bb"))
        f.relay.gone.clear()
        f.sweepDrain(); f.rm.runMaintenance()
        assertNull(f.evidence("bb"), "a 2xx on that inbox clears the evidence")
        assertEquals(1, f.sessions().size, "the introduction is still live (waiting for accepts)")
    }

    /** The introducer's queued RELAY of an accept to a party that deleted it ends the
     *  introduction too (session + queued accepts). Fails pre-fix (re-sent forever). */
    @Test
    fun aQueuedRelayToAGoneParty_endsTheIntroduction() {
        if (!aeadUp() || !x25519Up()) return
        val f = GoneFixture()
        val introId = assertNotNull(f.rm.startReferral("bb", "cc"))   // both offers land
        f.relay.gone += PG_B_CTL_OUT
        val accept = """{"ii":${jsonEscapeString(introId)},"pk":${jsonEscapeString(encodeBase64(x25519GenerateKeypair().publicKey))}}"""
        f.sweepDrain()
        f.rm.handleControl("cc", MessageManager.CONTROL_KIND_REFERRAL_ACCEPT, accept)   // forward to bb → 404, queued
        assertEquals(1, f.redrives().size)
        repeat(4) { f.sweepDrain(); f.rm.runMaintenance(); f.now += HOUR + 1 }
        assertTrue(f.redrives().isEmpty(), "the queued relay ends")
        assertTrue(f.sessions().isEmpty(), "and so does the introduction")
    }

    /** INTRODUCEE side: our accept to an introducer that deleted us stops being re-sent,
     *  but the staged record (its keypair and minted inboxes) is NOT destroyed on this
     *  evidence — the existing TTL reclaims it. Fails pre-fix (re-sent every sweep). */
    @Test
    fun ourAcceptToAGoneIntroducer_stopsResending_butKeepsTheRecord() {
        if (!aeadUp()) return
        val f = GoneFixture()
        val now = f.now
        f.vault.putMeta(
            ReferralMetaKeys.ACCEPT_PREFIX + "gone1",
            encodeStoredAccept(
                StoredAccept(
                    "bb", "Carol", ByteArray(32) { (it + 1).toByte() }, ByteArray(32) { (it + 9).toByte() },
                    MintedInboxPair(
                        MintedInbox("mi" + "M".repeat(30), PG_CAP, PG_CAP, Long.MAX_VALUE),
                        MintedInbox("mc" + "N".repeat(30), PG_CAP, PG_CAP, Long.MAX_VALUE),
                    ),
                    false, 0, now,
                )
            ),
        )
        val rm = ReferralManager(f.vault) { f.mgr }.also { it.clockMs = { f.now } }
        f.vault.putMeta(
            PeerInboxGonePolicy.keyFor("bb"),
            PeerInboxGonePolicy.encode(listOf(PeerInboxGonePolicy.Entry(PeerInboxGonePolicy.inboxTag(PG_B_CTL_OUT), 3, now)))!!,
        )
        repeat(3) { rm.runMaintenance() }
        assertEquals(0, f.relay.postsTo(PG_B_CTL_OUT), "no accept is re-sent to a gone introducer")
        val rec = assertNotNull(decodeStoredAccept(assertNotNull(f.vault.getMeta(ReferralMetaKeys.ACCEPT_PREFIX + "gone1"))))
        assertEquals(now, rec.createdAt, "the record is kept and NOT refreshed, so the idle TTL reclaims it")
    }
}

class PeerInboxGoneEvidenceTest {

    /** The evidence row is a per-contact key: purged with the contact, never
     *  re-created for a contact deleted while its send was in flight. */
    @Test
    fun evidence_diesWithTheContact_andIsNeverResurrected() {
        if (!aeadUp()) return
        val f = GoneFixture()
        f.relay.gone += PG_B_CTL_OUT
        f.sweepDrain()
        f.mgr.sendDirectControl("bb", MessageManager.CONTROL_KIND_SCREENSHOT, "{}")
        assertNotNull(f.evidence("bb"))
        assertTrue(PeerInboxGonePolicy.keyFor("bb") in ratchetMetaKeysForContact("bb"))
        assertTrue(MoveMetaPolicy.isAllowedKey(PeerInboxGonePolicy.keyFor("bb")))
        f.vault.deleteContact("bb")
        assertNull(f.evidence("bb"), "purged with the contact")
        f.mgr.sendDirectControl("bb", MessageManager.CONTROL_KIND_SCREENSHOT, "{}")
        assertNull(f.evidence("bb"), "a send to a deleted contact writes nothing")
    }

    /** The relay's proof of holding our state must be recent: a 404 long after the
     *  last authenticated 2xx is not evidence. */
    @Test
    fun aNotFoundWithoutRecentProof_countsNothing() {
        if (!aeadUp()) return
        val f = GoneFixture()
        f.relay.gone += PG_B_CTL_OUT
        f.sweepDrain()
        f.now += PeerInboxGonePolicy.RELAY_PROOF_MAX_AGE_MS + 1
        f.mgr.sendDirectControl("bb", MessageManager.CONTROL_KIND_SCREENSHOT, "{}")
        assertNull(f.evidence("bb"), "proof older than the window does not make a 404 evidence")
    }

    /** Sibling loop: the v3 channel-lost notice was re-sent every sweep until it
     *  landed — forever for a peer that deleted us. Fails pre-fix. */
    @Test
    fun theChannelLostNotice_isNotResentToAGoneInbox_andStillOwed() {
        if (!aeadUp()) return
        val f = GoneFixture()
        f.vault.insertContact(ContactRecord("bb", generateSecureRandom(32), 0, "Bob", 0L, ratchetBootstrapV3 = true))
        f.vault.putMeta(MessageManager.drLostKey("bb"), MessageManager.DR_LOST_NOTICE_OWED)
        f.vault.putMeta(
            PeerInboxGonePolicy.keyFor("bb"),
            PeerInboxGonePolicy.encode(listOf(PeerInboxGonePolicy.Entry(PeerInboxGonePolicy.inboxTag(PG_B_CTL_OUT), 3, f.now)))!!,
        )
        repeat(3) { f.mgr.redriveChannelLostNotices() }
        assertEquals(0, f.relay.postsTo(PG_B_CTL_OUT))
        assertEquals(MessageManager.DR_LOST_NOTICE_OWED, f.vault.getMeta(MessageManager.drLostKey("bb")), "nothing written")
        // The verdict ages out after a week: one re-probe, and a landed notice is recorded.
        f.now += PeerInboxGonePolicy.EVIDENCE_MAX_AGE_MS + 1
        f.mgr.redriveChannelLostNotices()
        assertEquals(1, f.relay.postsTo(PG_B_CTL_OUT))
        assertEquals(MessageManager.DR_LOST_NOTICE_SENT, f.vault.getMeta(MessageManager.drLostKey("bb")))
    }

    /** Sibling loop: the Maximum level notice was re-sent on every pass to a peer that
     *  deleted us. A held contact is skipped without spending the pass's attempts. */
    @Test
    fun theMaximumNotice_skipsAHeldContact_withoutSpendingAttempts() {
        val vault = InMemoryVault()
        for (id in listOf("a", "b", "c")) vault.insertContact(ContactRecord(id, generateSecureRandom(32), 0, id, 0L))
        val shield = MaximumShield(vault, { MaximumShieldLevel.MAXIMUM }, sleeper = { }, jitterMs = { 1L })
        val sent = mutableListOf<String>()
        val attempts = shield.reconcile(emptySet(), maxAttempts = 2, held = { it == "a" }) { id, _ -> sent.add(id); true }
        assertEquals(2, attempts)
        assertEquals(setOf("b", "c"), sent.toSet(), "the held contact neither sends nor eats an attempt")
        assertNull(vault.getMeta(MaximumShieldPolicy.sentMarkerKey("a")), "its marker is left unset")
    }
}

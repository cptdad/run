package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest

// ---------------------------------------------------------------------------
// Referral EDGE CASES — the bounds, the mid-session GC, the finalize rejection
// micro-branches, replay/race idempotence, the codec edges, the delete purge on
// a FINALIZED referred contact, the push surface, and the batch-ordering
// guarantee the handshake depends on.
//
// Everything here is either an in-RAM bound (a paired-but-misbehaving
// introducer/peer must not be able to grow memory or the vault without limit) or
// a rejection path that must leave the handshake RECOVERABLE: no contact
// written, `ref_p` kept, `finalized` still false — pinned by re-driving the same
// introId with well-formed material and watching it finalize.
// ---------------------------------------------------------------------------

private val EC_OFFER = MessageManager.CONTROL_KIND_REFERRAL_OFFER
private val EC_ACCEPT = MessageManager.CONTROL_KIND_REFERRAL_ACCEPT

/** 32-char inbox ids / 43-char caps — the shapes the validators demand. */
private val EC_PEER_IB  = "ep" + "A".repeat(30)
private val EC_PEER_CIB = "ep" + "B".repeat(30)
private val EC_MY_IB    = "em" + "C".repeat(30)
private val EC_MY_CIB   = "em" + "D".repeat(30)
private val EC_CAP_R = "R".repeat(43)
private val EC_CAP_W = "W".repeat(43)
private val EC_CAP_S = "S".repeat(43)
private val EC_CAP_X = "X".repeat(43)

private fun ecMint() = MintedInboxPair(
    MintedInbox(EC_MY_IB, EC_CAP_R, EC_CAP_W, Long.MAX_VALUE),
    MintedInbox(EC_MY_CIB, EC_CAP_S, EC_CAP_X, Long.MAX_VALUE),
)

/** A ref-accept body as the PEER would send it (their pub + their inbox offer). */
private fun ecAcceptJson(
    introId: String,
    peerPubB64: String,
    ib: String = EC_PEER_IB,
    cib: String = EC_PEER_CIB,
) = """{"ii":${jsonEscapeString(introId)},"pk":${jsonEscapeString(peerPubB64)},""" +
    """"ib":${jsonEscapeString(ib)},"wc":${jsonEscapeString(EC_CAP_W)},""" +
    """"cib":${jsonEscapeString(cib)},"cwc":${jsonEscapeString(EC_CAP_X)}}"""

private fun ecAcceptJson(introId: String, peerPub: ByteArray, ib: String = EC_PEER_IB, cib: String = EC_PEER_CIB) =
    ecAcceptJson(introId, encodeBase64(peerPub), ib, cib)

// ---------------------------------------------------------------------------
// (3) In-session caps. Each map is insertion-ordered and evicts the OLDEST on
// overflow; the eviction must take the evicted entry's VAULT record with it (an
// orphan would otherwise sit there until the 24 h TTL) and, for `pending`, must
// OVERWRITE the dropped handshake's ephemeral X25519 private key first.
// ---------------------------------------------------------------------------

class ReferralCapEvictionTest {

    private val noTransport: () -> MessageManager? = { null }

    /** A per-introducer cap of 8 pending offers
     *  AND a global-cap eviction fairness rule (the inserting introducer's OWN
     *  oldest offer is evicted first — see ReferralOfferFloodTest). To isolate
     *  THIS test's plain "global cap + vault cleanup" concern from that
     *  fairness rule, the first 128 offers are spread round-robin across 20
     *  introducers (max 7 pending each, safely under the per-introducer cap of
     *  8), and the 129th — the one that must trigger eviction — comes from a
     *  BRAND NEW introducer with none of its own pending, so the fairness rule
     *  falls back to its "no self entries" branch: evict the globally oldest,
     *  exactly this test's original intent. */
    @Test
    fun offers_atTheCap_evictTheOldestAndDropItsVaultRecord() {
        val vault = InMemoryVault()
        val introducers = (0 until 20).map { "cap-intro-$it" }
        for (i in introducers) seedReferralContact(vault, i, i)
        seedReferralContact(vault, "cap-intro-new", "cap-intro-new")
        val rm = ReferralManager(vault, noTransport)

        val ids = (1..129).map { "off$it" }
        for ((k, id) in ids.dropLast(1).withIndex()) {
            rm.handleControl(introducers[k % introducers.size], EC_OFFER, referralOfferJson(id, "Running Fox"))
        }
        rm.handleControl("cap-intro-new", EC_OFFER, referralOfferJson(ids.last(), "Running Fox"))

        val live = rm.pendingOffers().map { it.introId }.toSet()
        assertEquals(128, live.size, "offers are bounded at MAX_OFFERS")
        assertFalse(ids.first() in live, "the 129th offer must evict the OLDEST")
        assertTrue(ids.last() in live, "the newest offer must survive")
        assertNull(
            vault.getMeta(ReferralMetaKeys.OFFER_PREFIX + ids.first()),
            "the evicted offer's vault record must go with it, not linger as TTL-only residue",
        )
        assertEquals(128, metaKeysStartingWith(vault, ReferralMetaKeys.OFFER_PREFIX).size)
    }

    @Test
    fun pending_atTheCap_evictsTheOldestAndZeroesItsEphemeralPrivateKey() {
        if (!x25519Up()) return
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        val rm = ReferralManager(vault, noTransport)

        val oldest = x25519GenerateKeypair()
        for (i in 1..129) {
            val introId = "pen$i"
            val kp = if (i == 1) oldest else x25519GenerateKeypair()
            rm.registerAccepted(
                introId,
                ReferralOffer(introId, "alice", "Alice", "Carol", currentTimeMillis()),
                kp,
                ecMint(),
            )
            if (i == 1) assertTrue(oldest.privateKey.any { it != 0.toByte() }, "precondition: a fresh key is nonzero")
        }

        assertTrue(
            oldest.privateKey.all { it == 0.toByte() },
            "the evicted handshake's ephemeral private key must be OVERWRITTEN — a dropped map reference " +
                "leaves 32 key bytes as heap residue scrubInMemory() can never find",
        )
        assertNull(vault.getMeta(ReferralMetaKeys.ACCEPT_PREFIX + "pen1"), "the evicted entry's vault record goes too")
        assertEquals(128, metaKeysStartingWith(vault, ReferralMetaKeys.ACCEPT_PREFIX).size)
        assertNotNull(vault.getMeta(ReferralMetaKeys.ACCEPT_PREFIX + "pen129"))
    }

    /** A per-introducer cap of 8 pending offers,
     *  so the 65 offers driving this test are spread across 10 introducers
     *  (max 7 pending each) instead of one — see the sibling note on
     *  [offers_atTheCap_evictTheOldestAndDropItsVaultRecord]. */
    @Test
    fun stashedAccepts_atTheCap_evictTheOldestSoAFreshAcceptIsNeverStarved() {
        if (!x25519Up()) return
        val vault = InMemoryVault()
        val introducers = (0 until 10).map { "stash-intro-$it" }
        for (i in introducers) seedReferralContact(vault, i, i)
        val rm = ReferralManager(vault, noTransport)

        // 65 offers, each immediately followed by the peer's relayed accept (which
        // has to be stashed — we have not consented to any of them).
        for (i in 1..65) {
            val introducer = introducers[(i - 1) % introducers.size]
            rm.handleControl(introducer, EC_OFFER, referralOfferJson("stash$i", "Running Fox"))
            rm.handleControl(introducer, EC_ACCEPT, ecAcceptJson("stash$i", x25519GenerateKeypair().publicKey))
        }

        assertEquals(64, metaKeysStartingWith(vault, ReferralMetaKeys.STASH_PREFIX).size, "stashes are bounded at MAX_STASHED_ACCEPTS")
        assertNull(
            vault.getMeta(ReferralMetaKeys.STASH_PREFIX + "stash1"),
            "at the cap the OLDEST is evicted, never the incoming one — a backlog must not starve a real accept",
        )
        assertNotNull(vault.getMeta(ReferralMetaKeys.STASH_PREFIX + "stash65"), "the freshest accept survives")
        assertEquals(introducers.size, vault.getAllContacts().size, "no stash may pair anything")
    }

    @Test
    fun stashedAccepts_expiredEntriesAreAgedOutBeforeTheCapIsEvenConsulted() {
        if (!x25519Up()) return
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        val rm = ReferralManager(vault, noTransport)

        rm.handleControl("alice", EC_OFFER, referralOfferJson("age1", "Carol"))
        rm.handleControl("alice", EC_ACCEPT, ecAcceptJson("age1", x25519GenerateKeypair().publicKey))
        assertEquals(1, metaKeysStartingWith(vault, ReferralMetaKeys.STASH_PREFIX).size, "precondition: one stash")

        // A session that outlived the 24 h TTL (the clock seam stands in for the
        // wait). The next stash's housekeeping sweep must age the stale one out —
        // this is the TTL, not the cap: only two entries ever exist.
        rm.clockMs = { currentTimeMillis() + REFERRAL_RECORD_TTL_MS + 60_000L }
        rm.handleControl("alice", EC_OFFER, referralOfferJson("age2", "Carol"))
        rm.handleControl("alice", EC_ACCEPT, ecAcceptJson("age2", x25519GenerateKeypair().publicKey))

        assertNull(vault.getMeta(ReferralMetaKeys.STASH_PREFIX + "age1"), "an expired stash must be aged out")
        assertNotNull(vault.getMeta(ReferralMetaKeys.STASH_PREFIX + "age2"), "the fresh stash survives")
    }
}

/** Introducer paired with BOTH introducees on the control channel — the only
 *  channel the referral handshake ever uses. */
private class EcIntroducerFixture {
    val vault = InMemoryVault()
    val http = RecordingRelayHttp()
    val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)

    init {
        vault.insertContact(ContactRecord("bb", generateSecureRandom(32), 0, "Bob", 0L))
        vault.insertContact(ContactRecord("cc", generateSecureRandom(32), 0, "Carol", 0L))
        vault.insertInboxId(InboxIdRecord("bbct" + "1".repeat(28), "bb", 1L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_CTL, EC_CAP_W))
        vault.insertInboxId(InboxIdRecord("ccct" + "2".repeat(28), "cc", 1L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_CTL, EC_CAP_X))
    }

    fun newManager() = ReferralManager(vault) { mgr }
}


class ReferralIntroducerCapTest {

    @Test
    fun introSessions_atTheCap_evictTheOldestAndDropItsVaultRecord() {
        if (!aeadUp()) return
        val f = EcIntroducerFixture()
        val rm = f.newManager()
        // Two offers leave per introduction; script them all so no send ever hits
        // the transient-retry backoff.
        repeat(129 * 2) { f.http.script(httpAccepted()) }

        val ids = (1..129).map { assertNotNull(rm.startReferral("bb", "cc")) }

        assertEquals(128, metaKeysStartingWith(f.vault, ReferralMetaKeys.SESSION_PREFIX).size, "sessions are bounded")
        assertNull(
            f.vault.getMeta(ReferralMetaKeys.SESSION_PREFIX + ids.first()),
            "the evicted session's vault record must go with it",
        )
        assertNotNull(f.vault.getMeta(ReferralMetaKeys.SESSION_PREFIX + ids.last()))
    }

    @Test
    fun relayRedrives_atTheCap_evictTheOldestAndDropItsVaultRecord() {
        if (!aeadUp() || !x25519Up()) return
        val f = EcIntroducerFixture()
        val rm = f.newManager()

        val ids = mutableListOf<String>()
        repeat(129) {
            f.http.script(httpAccepted(), httpAccepted())
            val introId = assertNotNull(rm.startReferral("bb", "cc"))
            ids.add(introId)
            f.http.script(httpRefused())      // the forward is dropped → a redrive obligation
            rm.handleControl("bb", EC_ACCEPT, ecAcceptJson(introId, x25519GenerateKeypair().publicKey))
        }

        assertEquals(128, metaKeysStartingWith(f.vault, ReferralMetaKeys.REDRIVE_PREFIX).size, "redrives are bounded")
        assertNull(
            f.vault.getMeta(ReferralMetaKeys.REDRIVE_PREFIX + "${ids.first()}:cc"),
            "the evicted redrive's vault record must go with it",
        )
        assertNotNull(f.vault.getMeta(ReferralMetaKeys.REDRIVE_PREFIX + "${ids.last()}:cc"))
    }
}

// ---------------------------------------------------------------------------
// (4) MID-SESSION TTL GC. Rehydration's GC is already covered; this is the
// other half — a long-lived session whose records age out while it runs. The
// ephemeral X25519 private key must be OVERWRITTEN as it goes, so no referral
// key can outlive its 24 h bound in RAM.
// ---------------------------------------------------------------------------

class ReferralMidSessionGcTest {

    @Test
    fun runMaintenance_gcsEveryExpiredRecordMidSession_andZeroesTheEphemeralKey() {
        if (!aeadUp() || !x25519Up()) return
        val f = EcIntroducerFixture()
        val rm = f.newManager()

        // One record of every kind, all created in THIS session.
        f.http.script(httpAccepted(), httpAccepted())
        val sessionId = assertNotNull(rm.startReferral("bb", "cc"))          // ref_s
        f.http.script(httpRefused())
        rm.handleControl("bb", EC_ACCEPT, ecAcceptJson(sessionId, x25519GenerateKeypair().publicKey))  // ref_r
        rm.handleControl("cc", EC_OFFER, referralOfferJson("gc1", "Carol"))        // ref_o
        rm.handleControl("cc", EC_OFFER, referralOfferJson("gc3", "Erin"))
        rm.handleControl("cc", EC_ACCEPT, ecAcceptJson("gc3", x25519GenerateKeypair().publicKey))      // ref_a
        val kp = x25519GenerateKeypair()
        rm.registerAccepted("gc2", ReferralOffer("gc2", "cc", "Carol", "Zed", currentTimeMillis()), kp, ecMint())  // ref_p

        // Preconditions — otherwise the assertions below would pass vacuously.
        for (prefix in listOf(
            ReferralMetaKeys.SESSION_PREFIX, ReferralMetaKeys.REDRIVE_PREFIX,
            ReferralMetaKeys.OFFER_PREFIX, ReferralMetaKeys.STASH_PREFIX, ReferralMetaKeys.ACCEPT_PREFIX,
        )) {
            assertTrue(metaKeysStartingWith(f.vault, prefix).isNotEmpty(), "precondition: a $prefix record exists")
        }
        assertTrue(kp.privateKey.any { it != 0.toByte() }, "precondition: the ephemeral key is live")
        val callsBefore = f.http.calls.size

        // The session runs past the TTL (the clock seam stands in for the wait).
        rm.clockMs = { currentTimeMillis() + REFERRAL_RECORD_TTL_MS + 60_000L }
        rm.runMaintenance()

        assertTrue(
            kp.privateKey.all { it == 0.toByte() },
            "an ephemeral referral private key must not outlive its 24 h bound in RAM",
        )
        // A per-introducer rate-limit key
        // (`ref_off_rl:<introducerContactId>`) that is NOT a per-handshake TTL
        // record — like GroupManager's analogous `grp_inv_rl:` counter, it is a
        // rolling window that self-prunes on next use, so it deliberately
        // survives a handshake-record GC sweep. Check the five PER-HANDSHAKE
        // prefixes this test's own precondition loop enumerates above, rather
        // than every `ref_`-prefixed key.
        for (prefix in listOf(
            ReferralMetaKeys.SESSION_PREFIX, ReferralMetaKeys.REDRIVE_PREFIX,
            ReferralMetaKeys.OFFER_PREFIX, ReferralMetaKeys.STASH_PREFIX, ReferralMetaKeys.ACCEPT_PREFIX,
        )) {
            assertTrue(
                metaKeysStartingWith(f.vault, prefix).isEmpty(),
                "every expired $prefix record must be GC'd DURING the session, found: ${f.vault.meta.keys}",
            )
        }
        assertTrue(rm.pendingOffers().isEmpty(), "an expired offer must stop being presented")
        assertEquals(callsBefore, f.http.calls.size, "a GC'd obligation must not also be redriven")

        // …and the manager is still fully usable afterwards.
        rm.clockMs = { currentTimeMillis() }
        rm.handleControl("cc", EC_OFFER, referralOfferJson("gc9", "Frank"))
        assertEquals(listOf("gc9"), rm.pendingOffers().map { it.introId })
    }
}

// ---------------------------------------------------------------------------
// (5) finalizeFromPeerAccept rejection micro-branches. Every one must leave the
// handshake RECOVERABLE: no contact written, no inbox rows written, `ref_p`
// kept — proven by re-driving the SAME introId with well-formed material and
// watching it finalize (which is only possible while `finalized` is false).
// ---------------------------------------------------------------------------

class ReferralFinalizeRejectionTest {

    private val noTransport: () -> MessageManager? = { null }

    private class Staged(val vault: InMemoryVault, val rm: ReferralManager, val introId: String)

    private fun staged(introId: String): Staged {
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        val rm = ReferralManager(vault, noTransport)
        rm.handleControl("alice", EC_OFFER, referralOfferJson(introId, "Carol"))
        rm.registerAccepted(introId, rm.pendingOffers().single(), x25519GenerateKeypair(), ecMint())
        return Staged(vault, rm, introId)
    }

    /** The shared shape of every rejection: nothing written, material kept, and a
     *  well-formed retry on the same introId still completes the handshake. */
    private fun assertRejectedButRecoverable(s: Staged) {
        assertEquals(1, s.vault.getAllContacts().size, "a rejected accept must create no contact")
        assertEquals(0, s.vault.inboxes.size, "a rejected accept must write no inbox rows")
        assertNotNull(
            s.vault.getMeta(ReferralMetaKeys.ACCEPT_PREFIX + s.introId),
            "our own accept material must be kept — the peer may still send a good accept",
        )
        s.rm.handleControl("alice", EC_ACCEPT, ecAcceptJson(s.introId, x25519GenerateKeypair().publicKey))
        assertEquals(
            2, s.vault.getAllContacts().size,
            "the handshake must still be finalizable (a rejection may never latch `finalized`)",
        )
    }

    @Test
    fun peerAnnouncingOneIdForBothItsInboxes_isRejected() {
        if (!x25519Up()) return
        val s = staged("mb1")
        // Two outbound rows sharing one inboxId would leave the new contact's
        // channel broken with no re-pair UX.
        s.rm.handleControl(
            "alice", EC_ACCEPT,
            ecAcceptJson("mb1", x25519GenerateKeypair().publicKey, ib = EC_PEER_IB, cib = EC_PEER_IB),
        )
        assertRejectedButRecoverable(s)
    }

    @Test
    fun peerPublicKeyOfTheWrongSize_isRejected() {
        if (!x25519Up()) return
        val s = staged("mb2")
        s.rm.handleControl("alice", EC_ACCEPT, ecAcceptJson("mb2", encodeBase64(ByteArray(31) { 7 })))
        assertRejectedButRecoverable(s)
    }

    @Test
    fun peerPublicKeyThatIsNotBase64_isRejected() {
        if (!x25519Up()) return
        val s = staged("mb3")
        s.rm.handleControl("alice", EC_ACCEPT, ecAcceptJson("mb3", "!!! not base64 !!!"))
        assertRejectedButRecoverable(s)
    }

    @Test
    fun allZeroPeerPublicKey_isRejectedByTheEcdhCheck() {
        if (!x25519Up()) return
        val s = staged("mb4")
        // A low-order/degenerate peer key would yield an all-zero shared secret —
        // a key the INTRODUCER would know. x25519EcdhChecked refuses it, and the
        // whole handshake is dropped rather than establishing a degenerate channel.
        s.rm.handleControl("alice", EC_ACCEPT, ecAcceptJson("mb4", ByteArray(32)))
        assertRejectedButRecoverable(s)
    }

    @Test
    fun aVaultTransactionFailure_leavesTheHandshakeRetryable() {
        if (!x25519Up()) return
        val inner = InMemoryVault()
        seedReferralContact(inner, "alice", "Alice")
        var failNextTransaction = true
        val vault = object : VaultDatabase by inner {
            override fun withTransaction(block: () -> Unit) {
                if (failNextTransaction) {
                    failNextTransaction = false
                    throw RuntimeException("simulated vault write failure")
                }
                inner.withTransaction(block)
            }
        }
        val rm = ReferralManager(vault) { null }
        rm.handleControl("alice", EC_OFFER, referralOfferJson("mb5", "Carol"))
        rm.registerAccepted("mb5", rm.pendingOffers().single(), x25519GenerateKeypair(), ecMint())
        val body = ecAcceptJson("mb5", x25519GenerateKeypair().publicKey)

        rm.handleControl("alice", EC_ACCEPT, body)

        // A persist failure is RETRYABLE, not terminal: nothing was committed and
        // our accept material is still there, so a later re-delivery can re-drive.
        assertEquals(1, inner.getAllContacts().size, "a failed transaction must create no contact")
        assertNotNull(inner.getMeta(ReferralMetaKeys.ACCEPT_PREFIX + "mb5"), "ref_p must survive a failed finalize")
        // `finalized` stayed false — the same body re-drives to a real contact.
        rm.handleControl("alice", EC_ACCEPT, body)
        assertEquals(2, inner.getAllContacts().size, "the re-delivery must finalize once the vault recovers")
    }
}

// ---------------------------------------------------------------------------
// (6)(7) Idempotence of a re-delivered / concurrently-delivered peer accept.
// ---------------------------------------------------------------------------

class ReferralFinalizeIdempotenceTest {

    @Test
    fun theSameAcceptBodyDeliveredTwice_createsExactlyOneContact() {
        if (!x25519Up()) return
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        val rm = ReferralManager(vault) { null }
        rm.handleControl("alice", EC_OFFER, referralOfferJson("rep1", "Carol"))
        rm.registerAccepted("rep1", rm.pendingOffers().single(), x25519GenerateKeypair(), ecMint())
        val body = ecAcceptJson("rep1", x25519GenerateKeypair().publicKey)

        rm.handleControl("alice", EC_ACCEPT, body)
        val referredId = ReferralManager.referredContactIdFor("rep1")
        val secret = assertNotNull(vault.getContact(referredId)).sharedSecret.toList()
        val inboxCount = vault.inboxes.size

        // The relay re-serves the identical blob on a later drain (its inbox
        // retention outlives one poll) — byte-for-byte the same body.
        rm.handleControl("alice", EC_ACCEPT, body)

        assertEquals(2, vault.getAllContacts().size, "a literal replay must not mint a second contact")
        assertEquals(secret, assertNotNull(vault.getContact(referredId)).sharedSecret.toList(),
            "a literal replay must not re-key the existing contact")
        assertEquals(inboxCount, vault.inboxes.size, "a literal replay must not rewrite the inbox rows")
    }

    @Test
    fun twoConcurrentDeliveriesOfTheSameAccept_createExactlyOneContact() = runTest {
        if (!x25519Up()) return@runTest
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        val rm = ReferralManager(vault) { null }
        rm.handleControl("alice", EC_OFFER, referralOfferJson("race1", "Carol"))
        rm.registerAccepted("race1", rm.pendingOffers().single(), x25519GenerateKeypair(), ecMint())
        val body = ecAcceptJson("race1", x25519GenerateKeypair().publicKey)

        // The two real callers — the stashed-accept apply on acceptOffer's IO
        // coroutine and the background control poller — can genuinely land at the
        // same time, which is why the whole check-derive-persist-flip runs under
        // one lock. On JVM these are two OS threads.
        val jobs = List(2) {
            launch(Dispatchers.Default) { rm.handleControl("alice", EC_ACCEPT, body) }
        }
        jobs.forEach { it.join() }

        assertEquals(
            1, vault.getAllContacts().count { it.contactId != "alice" },
            "a double finalize must not insert a second, dangling referred contact",
        )
        assertEquals(4, vault.inboxes.size, "exactly the four inbox rows of ONE referral")
        assertTrue(
            vault.meta.keys.none { it.startsWith(ReferralMetaKeys.ACCEPT_PREFIX) },
            "the winner's transaction still drops the handshake record",
        )
    }
}

// ---------------------------------------------------------------------------
// (8) Codec edges. Aliases and relayed bodies are ATTACKER-INFLUENCED, so the
// escaping has to round-trip and must not let a value shadow the contact field
// the delete-contact purge classifier reads.
// ---------------------------------------------------------------------------

class ReferralCodecEdgeCaseTest {

    /** Separators, newlines, quotes, backslashes and a fake `"ic"` field. */
    private val hostile = "Ca\"rol\n\r\t:,\\ \",\"ic\":\"mallory\""

    @Test
    fun storedOffer_roundTrips_hostileAliases_andCannotBeShadowed() {
        val enc = encodeStoredOffer(StoredOffer("alice", hostile, hostile, 0L))
        val dec = assertNotNull(decodeStoredOffer(enc))
        assertEquals("alice", dec.introducerContactId)
        assertEquals(hostile, dec.introducerAlias, "aliases are attacker-influenced: escaping must round-trip")
        assertEquals(hostile, dec.peerAlias)
        assertEquals(0L, dec.createdAt)
        // The purge classifier reads the same field and must see the REAL one.
        val key = ReferralMetaKeys.OFFER_PREFIX + "i"
        assertTrue(isReferralMetaResidueForContact(key, enc, "alice"))
        assertFalse(isReferralMetaResidueForContact(key, enc, "mallory"), "an alias must not forge a contact reference")

        // Empty aliases are legal; an empty introducer id is not (it can name no contact).
        val bare = assertNotNull(decodeStoredOffer(encodeStoredOffer(StoredOffer("a", "", "", Long.MAX_VALUE))))
        assertEquals("", bare.peerAlias)
        assertEquals(Long.MAX_VALUE, bare.createdAt)
        assertNull(decodeStoredOffer(encodeStoredOffer(StoredOffer("", "x", "y", 1L))))
        assertNull(decodeStoredOffer("{not json at all"))
    }

    @Test
    fun storedSession_roundTrips_theRelayedSet_andRejectsDegenerateRecords() {
        val enc = encodeStoredSession(StoredSession("bb", "cc", setOf("bb", "cc"), Long.MAX_VALUE))
        val dec = assertNotNull(decodeStoredSession(enc))
        assertEquals("bb", dec.contactA)
        assertEquals("cc", dec.contactB)
        assertEquals(setOf("bb", "cc"), dec.relayed, "both relayed halves must survive")
        assertEquals(Long.MAX_VALUE, dec.createdAt)

        val none = assertNotNull(decodeStoredSession(encodeStoredSession(StoredSession("bb", "cc", emptySet(), 0L))))
        assertTrue(none.relayed.isEmpty(), "a session with neither accept relayed yet is legal")
        val one = assertNotNull(decodeStoredSession(encodeStoredSession(StoredSession("bb", "cc", setOf("bb"), 0L))))
        assertEquals(setOf("bb"), one.relayed)

        // Degenerate: an introduction of a contact to ITSELF can never be relayed.
        assertNull(decodeStoredSession(encodeStoredSession(StoredSession("bb", "bb", emptySet(), 0L))))
        assertNull(decodeStoredSession(encodeStoredSession(StoredSession("", "cc", emptySet(), 0L))))
        assertNull(decodeStoredSession(encodeStoredSession(StoredSession("bb", "", emptySet(), 0L))))
    }

    @Test
    fun storedStash_roundTrips_aNestedRelayedBody_andCannotBeShadowedByIt() {
        // The stash body is a peer's accept blob relayed VERBATIM through the
        // introducer — nested JSON inside a JSON string value, and hostile: it
        // names a different contact in its own "fr" field.
        val body = """{"fr":"mallory","ii":"nest1","pk":"AAAA","note":"quote \" and newline \n"}"""
        val enc = encodeStoredStash(StoredStash("alice", body, 42L))
        val dec = assertNotNull(decodeStoredStash(enc))
        assertEquals("alice", dec.fromContactId)
        assertEquals(body, dec.body, "the relayed body must survive byte-for-byte")
        assertEquals(42L, dec.createdAt)
        val key = ReferralMetaKeys.STASH_PREFIX + "nest1"
        assertTrue(isReferralMetaResidueForContact(key, enc, "alice"))
        assertFalse(isReferralMetaResidueForContact(key, enc, "mallory"), "a relayed body must not forge a reference")

        assertNull(decodeStoredStash(encodeStoredStash(StoredStash("", body, 0L))))
        assertNull(decodeStoredStash(encodeStoredStash(StoredStash("alice", "", 0L))))
    }

    @Test
    fun storedRedrive_roundTrips_andRefusesAnIntroIdThatCouldSmuggleStructure() {
        val body = """{"ii":"rd1","pk":"AAAA"}"""
        val enc = encodeStoredRedrive(StoredRedrive("rd1", "cc", "bb", body, Int.MAX_VALUE, Long.MAX_VALUE))
        val dec = assertNotNull(decodeStoredRedrive(enc))
        assertEquals("rd1", dec.introId)
        assertEquals("cc", dec.toContactId)
        assertEquals("bb", dec.fromContactId)
        assertEquals(body, dec.body)
        assertEquals(Int.MAX_VALUE, dec.attempts)
        assertEquals(Long.MAX_VALUE, dec.createdAt)
        // Both contact positions are classified — the record names two contacts.
        val key = ReferralMetaKeys.REDRIVE_PREFIX + "rd1:cc"
        assertTrue(isReferralMetaResidueForContact(key, enc, "cc"))
        assertTrue(isReferralMetaResidueForContact(key, enc, "bb"))
        assertFalse(isReferralMetaResidueForContact(key, enc, "mallory"))

        // The introId is part of the KEY name (and of the newline-delimited
        // tombstone list), so anything that could smuggle structure is refused.
        for (bad in listOf("bad:id", "bad\nid", "", "x".repeat(65))) {
            assertNull(
                decodeStoredRedrive(encodeStoredRedrive(StoredRedrive(bad, "cc", "bb", body, 0, 1L))),
                "an unsafe introId <$bad> must not decode",
            )
        }
        // 64 chars is the boundary and IS accepted.
        assertNotNull(decodeStoredRedrive(encodeStoredRedrive(StoredRedrive("x".repeat(64), "cc", "bb", body, 0, 1L))))
        assertNull(decodeStoredRedrive(encodeStoredRedrive(StoredRedrive("rd1", "cc", "bb", "", 0, 1L))))
    }

    @Test
    fun everyDecoder_toleratesAnUnknownTrailingField() {
        // Forward compatibility: a newer build may add a field to any record, and
        // an older build (or a downgrade) must still read what it understands
        // rather than GC'ing a live handshake as unreadable.
        fun withExtra(json: String) = json.dropLast(1) + ""","zz":"a field this build predates"}"""
        val now = 7L
        assertNotNull(decodeStoredOffer(withExtra(encodeStoredOffer(StoredOffer("alice", "A", "C", now)))))
        assertNotNull(decodeStoredSession(withExtra(encodeStoredSession(StoredSession("bb", "cc", setOf("bb"), now)))))
        assertNotNull(decodeStoredStash(withExtra(encodeStoredStash(StoredStash("alice", "{}", now)))))
        assertNotNull(decodeStoredRedrive(withExtra(encodeStoredRedrive(StoredRedrive("rd1", "cc", "bb", "{}", 0, now)))))
        val accept = assertNotNull(
            decodeStoredAccept(
                withExtra(
                    encodeStoredAccept(
                        StoredAccept("alice", "Carol", ByteArray(32) { 1 }, ByteArray(32) { 2 }, ecMint(), true, 3, now)
                    )
                )
            )
        )
        assertEquals(EC_MY_IB, accept.minted.main.inboxId)
        assertTrue(accept.sent)
        assertEquals(3, accept.attempts)
    }
}

// ---------------------------------------------------------------------------
// (9) Deleting a FINALIZED referred contact. The already-covered case is the
// INTRODUCER deleted mid-handshake; this is the other end — the referred peer
// itself, after the contact exists. She is an ordinary contact by then and can
// herself introduce us to someone, so records naming HER must be purged.
// ---------------------------------------------------------------------------

class ReferralDeleteFinalizedPeerTest {

    @Test
    fun deletingAReferredContact_purgesEveryRecordNamingIt_andLeavesTheRestAlone() {
        if (!x25519Up()) return
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        seedReferralContact(vault, "dave", "Dave")
        val rm = ReferralManager(vault) { null }

        // Finalize a referred contact vouched for by Alice.
        rm.handleControl("alice", EC_OFFER, referralOfferJson("fin1", "Carol"))
        rm.registerAccepted("fin1", rm.pendingOffers().single(), x25519GenerateKeypair(), ecMint())
        rm.handleControl("alice", EC_ACCEPT, ecAcceptJson("fin1", x25519GenerateKeypair().publicKey))
        val referred = ReferralManager.referredContactIdFor("fin1")
        assertNotNull(vault.getContact(referred), "precondition: the referred contact exists")
        assertEquals(4, vault.inboxes.size, "precondition: its four inbox rows exist")
        assertEquals("1", vault.getMeta(MessageManager.drIntentKey(referred)), "precondition: ratchet-capable")

        // Carol is now an ordinary contact and introduces US to someone: records
        // that name HER, holding an ephemeral private key and our own read caps.
        vault.putMeta(
            ReferralMetaKeys.OFFER_PREFIX + "fin3",
            encodeStoredOffer(StoredOffer(referred, "Carol", "Zed", currentTimeMillis())),
        )
        vault.putMeta(
            ReferralMetaKeys.ACCEPT_PREFIX + "fin4",
            encodeStoredAccept(
                StoredAccept(referred, "Zed", ByteArray(32) { 3 }, ByteArray(32) { 4 }, ecMint(), true, 0, currentTimeMillis())
            ),
        )
        // …plus an unrelated in-flight referral from Dave, which must survive.
        rm.handleControl("dave", EC_OFFER, referralOfferJson("fin2", "Erin"))
        val tombstoneBefore = assertNotNull(vault.getMeta(ReferralMetaKeys.COMPLETED_KEY_V2))
        assertFalse(tombstoneBefore.contains("fin1"), "the tombstone must hold a hash, never the raw introId (1C-2)")
        assertFalse(
            tombstoneBefore.contains(referred),
            "the tombstone must not contain the referred contact's id either",
        )

        vault.deleteContact(referred)

        assertNull(vault.getContact(referred))
        assertTrue(vault.inboxes.none { it.contactId == referred }, "the contact's inbox rows go with it")
        assertNull(vault.getMeta(MessageManager.drIntentKey(referred)), "its ratchet meta goes with it")
        assertNull(
            vault.getMeta(ReferralMetaKeys.OFFER_PREFIX + "fin3"),
            "an offer naming the deleted contact must be purged",
        )
        assertNull(
            vault.getMeta(ReferralMetaKeys.ACCEPT_PREFIX + "fin4"),
            "an ephemeral X25519 private key must not outlive the contact it was minted for",
        )
        assertTrue(
            vault.meta.keys.none { isReferralMetaKey(it) && isReferralMetaResidueForContact(it, vault.meta[it], referred) },
            "no referral residue may name the deleted contact, found: ${vault.meta.keys}",
        )
        assertNotNull(vault.getMeta(ReferralMetaKeys.OFFER_PREFIX + "fin2"), "an unrelated referral must survive")
        assertEquals(
            tombstoneBefore, vault.getMeta(ReferralMetaKeys.COMPLETED_KEY_V2),
            "the tombstone list references no contact and must never be touched by a delete",
        )
    }
}

// ---------------------------------------------------------------------------
// (11) The push surface a referral extends. Every finalize mints a NEW inbound
// TEXT inbox and a NEW inbound CONTROL inbox; only the text one may ever be
// registered for push, or the relay's contentless alert fires for handshake
// blobs that carry no user-visible message.
// ---------------------------------------------------------------------------

class ReferralPushSurfaceTest {

    @Test
    fun allInboundTextInboxes_excludesTheControlInbox_whileAllInboundInboxesKeepsBoth() {
        val vault = InMemoryVault()
        seedReferralContact(vault, "carol", "Carol")
        vault.insertInboxId(InboxIdRecord(EC_MY_IB, "carol", 1L, Long.MAX_VALUE, "inbound", EC_CAP_R))
        vault.insertInboxId(InboxIdRecord(EC_MY_CIB, "carol", 1L, Long.MAX_VALUE, MessageManager.DIR_INBOUND_CTL, EC_CAP_S))
        vault.insertInboxId(InboxIdRecord(EC_PEER_IB, "carol", 1L, Long.MAX_VALUE, "outbound", EC_CAP_W))

        val text = allInboundTextInboxes(vault)
        assertEquals(listOf(EC_MY_IB), text.map { it.inboxId }, "push must never be registered on a control inbox")
        assertEquals(EC_CAP_R, text.single().readCap, "the ref carries the inbox OWNER capability")
        assertEquals(
            setOf(EC_MY_IB, EC_MY_CIB), allInboundInboxes(vault).map { it.inboxId }.toSet(),
            "the full receive surface still covers both inbound directions",
        )
    }

    @Test
    fun aContactWithOnlyAControlInbox_contributesNothingToTheTextSurface() {
        val vault = InMemoryVault()
        seedReferralContact(vault, "carol", "Carol")
        vault.insertInboxId(InboxIdRecord(EC_MY_CIB, "carol", 1L, Long.MAX_VALUE, MessageManager.DIR_INBOUND_CTL, EC_CAP_S))
        assertTrue(allInboundTextInboxes(vault).isEmpty())
        assertEquals(listOf(EC_MY_CIB), allInboundInboxes(vault).map { it.inboxId })
    }
}

// ---------------------------------------------------------------------------
// (12) The batch-ordering guarantee the handshake depends on. An introducer
// sends the OFFER first and relays the peer's ACCEPT later, so within one
// control drain the offer always carries the LOWER counter — and pollChannel
// sorts the drain by counter before surfacing it, so the offer is ingested
// first no matter what order the relay serves the blobs in.
// ---------------------------------------------------------------------------

private const val EC_CTL_IN = "ECCTLinnnnnnnnnnnnnnnnnnnnnnnnnn"

/** Seals [envelopeJson] exactly as the production sender does. */
private fun ecSeal(sharedSecret: ByteArray, envelopeJson: String): String {
    val key = sha256(sharedSecret)
    val ctx = sha256(key + "message-aead".encodeToByteArray())
    return encodeBase64(aesGcmEncrypt(padMessage(envelopeJson.encodeToByteArray()), key, ctx))
}

class ReferralBatchOrderingTest {

    @Test
    fun controlDrain_isSortedByCounter_soTheOfferIsIngestedBeforeTheRelayedAccept() {
        if (!aeadUp()) return
        val shared = generateSecureRandom(32)
        val vault = InMemoryVault()
        val http = RecordingRelayHttp()
        val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)
        vault.insertContact(ContactRecord("alice", shared, 0, "Alice", 0L))
        vault.insertInboxId(
            InboxIdRecord(EC_CTL_IN, "alice", 1L, Long.MAX_VALUE, MessageManager.DIR_INBOUND_CTL, EC_CAP_R)
        )
        val epoch = bytesToHex(sha256(shared + "msg-epoch".encodeToByteArray()).copyOfRange(0, 6))
        fun control(counter: Long, kind: String, body: String) = ecSeal(
            shared,
            """{"e":"$epoch","c":$counter,"t":0,"ch":"${MessageManager.CHANNEL_TAG_CTL}",""" +
                """"di":"$EC_CTL_IN","k":${jsonEscapeString(kind)},"b":${jsonEscapeString(body)},"m":""}""",
        )
        // The relay serves the batch REVERSED — the accept (counter 2) ahead of the
        // offer (counter 1). Without the in-drain sort the offer would look like a
        // replay and be dropped, and the accept would then hit the terminal
        // unknown-introId branch: the whole introduction lost to blob order.
        http.script(
            HttpResult(
                200,
                """{"blobs":["${control(2, EC_ACCEPT, ecAcceptJson("batch1", ByteArray(32) { 9 }))}",""" +
                    """"${control(1, EC_OFFER, referralOfferJson("batch1", "Carol"))}"]}""",
                true,
            )
        )

        val drained = mgr.pollControlMessages("alice")

        assertEquals(listOf(1L, 2L), drained.map { it.counter }, "the drain must be sorted by counter")
        assertEquals(listOf(EC_OFFER, EC_ACCEPT), drained.map { it.controlKind }, "the offer must come first")
    }

    @Test
    fun offerAndPeerAcceptInOneSortedBatch_stashThenFinalize() {
        if (!x25519Up()) return
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        val rm = ReferralManager(vault) { null }
        val carol = x25519GenerateKeypair()

        // One drain, applied in counter order (what the sort above guarantees).
        rm.handleControl("alice", EC_OFFER, referralOfferJson("batch2", "Carol"))
        rm.handleControl("alice", EC_ACCEPT, ecAcceptJson("batch2", carol.publicKey))

        // Consent has not been given, so nothing may pair — but the accept is kept.
        assertEquals(1, vault.getAllContacts().size, "an accept may never auto-pair")
        assertEquals(
            1, metaKeysStartingWith(vault, ReferralMetaKeys.STASH_PREFIX).size,
            "the accept could only be stashed because the OFFER in the same drain was applied first — " +
                "it is the offer that names the introducer this accept is validated against",
        )

        // The user approves; the stashed accept applies at once.
        val bob = x25519GenerateKeypair()
        val expected = hkdfSha256(
            x25519Ecdh(bob.privateKey, carol.publicKey), ByteArray(0),
            "run-referral-v1|batch2".encodeToByteArray(), 32,
        )
        rm.registerAccepted("batch2", rm.pendingOffers().single(), bob, ecMint())

        val c = vault.getAllContacts().single { it.contactId != "alice" }
        assertEquals(expected.toList(), c.sharedSecret.toList(), "both sides derive the same key")
        assertEquals(VaultSeedDefaults.TRUST_REFERRED_CONFIRMED, c.trustLevel)
        assertTrue(metaKeysStartingWith(vault, ReferralMetaKeys.STASH_PREFIX).isEmpty(), "the applied stash leaves no record")
    }
}

package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// Referral TTL, refresh, offer and budget behaviours (TTL + refresh-on-activity + relay ?ttl, the durable
// offer leg, push-visible control inboxes, stash-consumed-early, and
// per-session attempt budgets, and the onIntroFinalized hook).
//
// Each case pins one behaviour: the TTL cases use skews that a 24 h
// bound would have GC'd, the refresh cases assert a stamp actually MOVED, the
// ?ttl cases assert the exact query string, and the stash-consumed-early case asserts `ref_a`
// SURVIVES a finalize that threw.
// ---------------------------------------------------------------------------

private const val FB_OLD_TTL_MS = 86_400_000L          // the pre-fix 24 h bound
private const val FB_RELAY = "http://relay.test"

private val FB_PEER_IB  = "fp" + "A".repeat(30)
private val FB_PEER_CIB = "fp" + "B".repeat(30)
private val FB_MY_IB    = "fm" + "C".repeat(30)
private val FB_MY_CIB   = "fm" + "D".repeat(30)
private val FB_CAP_R = "R".repeat(43)
private val FB_CAP_W = "W".repeat(43)
private val FB_CAP_S = "S".repeat(43)
private val FB_CAP_X = "X".repeat(43)

private fun fbMint() = MintedInboxPair(
    MintedInbox(FB_MY_IB, FB_CAP_R, FB_CAP_W, Long.MAX_VALUE),
    MintedInbox(FB_MY_CIB, FB_CAP_S, FB_CAP_X, Long.MAX_VALUE),
)

private fun fbAcceptJson(introId: String, peerPub: ByteArray) =
    """{"ii":${jsonEscapeString(introId)},"pk":${jsonEscapeString(encodeBase64(peerPub))},""" +
        """"ib":${jsonEscapeString(FB_PEER_IB)},"wc":${jsonEscapeString(FB_CAP_W)},""" +
        """"cib":${jsonEscapeString(FB_PEER_CIB)},"cwc":${jsonEscapeString(FB_CAP_X)}}"""

private fun fbStoredTs(vault: InMemoryVault, key: String): Long? =
    vault.getMeta(key)?.let { firstStringFieldAnywhere(it, "ts")?.toLongOrNull() }


// ---------------------------------------------------------------------------
// The record TTL is 7 days, not 24 h.
// ---------------------------------------------------------------------------

class ReferralRecordTtlTest {

    private val noTransport: () -> MessageManager? = { null }

    /** THE half-pair case: the two introducees accept independently, so one of
     *  them may take longer than a day. Under the old 24 h bound our accept
     *  material was GC'd at the next launch and the peer's later accept hit the
     *  terminal unknown-introId drop — while the peer had already committed a
     *  TRUST_REFERRED_CONFIRMED contact routed at inboxes nobody polls. */
    @Test
    fun peerAcceptAfterMoreThanADay_stillFinalizes() {
        if (!x25519Up()) return
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        val bob = x25519GenerateKeypair()
        val carol = x25519GenerateKeypair()
        val expected = hkdfSha256(
            x25519Ecdh(bob.privateKey, carol.publicKey), ByteArray(0),
            "run-referral-v1|ttl1".encodeToByteArray(), 32,
        )

        // Our accept, staged and CONFIRMED 25 hours ago — past the OLD bound,
        // comfortably inside the new one.
        val old = currentTimeMillis() - FB_OLD_TTL_MS - 3_600_000L
        vault.putMeta(
            ReferralMetaKeys.ACCEPT_PREFIX + "ttl1",
            encodeStoredAccept(
                StoredAccept("alice", "Carol", bob.privateKey, bob.publicKey, fbMint(), true, 0, old)
            ),
        )

        val rm = ReferralManager(vault, noTransport)
        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_ACCEPT, fbAcceptJson("ttl1", carol.publicKey))

        val c = vault.getAllContacts().single { it.contactId != "alice" }
        assertEquals(expected.toList(), c.sharedSecret.toList(), "a >24 h-old handshake must still derive the SAME key")
        assertEquals(VaultSeedDefaults.TRUST_REFERRED_CONFIRMED, c.trustLevel)
        assertTrue(metaKeysStartingWith(vault, ReferralMetaKeys.ACCEPT_PREFIX).isEmpty())
    }

    /** …and an un-consented offer from 25 h ago is still presentable. */
    @Test
    fun offerOlderThanADay_isStillPresentedForConsent() {
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        val old = currentTimeMillis() - FB_OLD_TTL_MS - 3_600_000L
        vault.putMeta(
            ReferralMetaKeys.OFFER_PREFIX + "ttl2",
            encodeStoredOffer(StoredOffer("alice", "Alice", "Carol", old)),
        )
        assertEquals(listOf("ttl2"), ReferralManager(vault, noTransport).pendingOffers().map { it.introId })
    }

    /** The bound still bites — 8 days is past even the new idle TTL. */
    @Test
    fun recordsPastTheSevenDayIdleTtl_areStillGarbageCollected() {
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        val ancient = currentTimeMillis() - REFERRAL_RECORD_TTL_MS - 86_400_000L
        vault.putMeta(
            ReferralMetaKeys.OFFER_PREFIX + "ttl3",
            encodeStoredOffer(StoredOffer("alice", "Alice", "Carol", ancient)),
        )
        vault.putMeta(
            ReferralMetaKeys.ACCEPT_PREFIX + "ttl4",
            encodeStoredAccept(
                StoredAccept("alice", "Carol", ByteArray(32) { 1 }, ByteArray(32) { 2 }, fbMint(), true, 0, ancient)
            ),
        )
        val rm = ReferralManager(vault, noTransport)
        assertTrue(rm.pendingOffers().isEmpty())
        assertTrue(vault.meta.keys.none { isReferralMetaKey(it) }, "found: ${vault.meta.keys}")
    }

    /** The ABSOLUTE ceiling: a record kept alive by activity (fresh `ts`) is
     *  still reclaimed once `t0` — which refresh never moves — is old enough.
     *  Without it, the TTL refresh plus the per-session budget reset would let an
     *  ephemeral X25519 private key live in the vault indefinitely. */
    @Test
    fun aRecordRefreshedForeverIsStillReclaimedAtTheAbsoluteCeiling() {
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        val now = currentTimeMillis()
        vault.putMeta(
            ReferralMetaKeys.ACCEPT_PREFIX + "cap1",
            encodeStoredAccept(
                StoredAccept(
                    "alice", "Carol", ByteArray(32) { 1 }, ByteArray(32) { 2 }, fbMint(), true, 0,
                    createdAt = now,                                                // refreshed a moment ago
                    firstSeenAt = now - REFERRAL_RECORD_MAX_LIFETIME_MS - 60_000L,   // but first seen long ago
                )
            ),
        )
        ReferralManager(vault, noTransport)
        assertNull(
            vault.getMeta(ReferralMetaKeys.ACCEPT_PREFIX + "cap1"),
            "refresh-on-activity must not be able to carry a record past the absolute ceiling",
        )
    }

    /** Flip-check for the case above: the SAME record with a recent `t0` survives. */
    @Test
    fun theSameRecordWithinTheCeiling_survives() {
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        val now = currentTimeMillis()
        vault.putMeta(
            ReferralMetaKeys.ACCEPT_PREFIX + "cap2",
            encodeStoredAccept(
                StoredAccept(
                    "alice", "Carol", ByteArray(32) { 1 }, ByteArray(32) { 2 }, fbMint(), true, 0,
                    createdAt = now, firstSeenAt = now - REFERRAL_RECORD_TTL_MS * 2,
                )
            ),
        )
        ReferralManager(vault, noTransport)
        assertNotNull(vault.getMeta(ReferralMetaKeys.ACCEPT_PREFIX + "cap2"))
    }

    /** A record written by a build that predates `t0` migrates on read (t0 := ts)
     *  and is re-written WITH `t0` on the next persist. */
    @Test
    fun legacyRecordWithoutFirstSeenStamp_migratesOnReadAndOnWrite() {
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        val ts = currentTimeMillis() - 60_000L
        // Hand-built legacy value: exactly the fields the pre-fix encoder emitted.
        val legacy = encodeStoredOffer(StoredOffer("alice", "Alice", "Carol", ts))
            .replace(""","t0":"${ts}"""", "")
        assertFalse(legacy.contains("t0"), "precondition: the legacy value really has no t0")
        vault.putMeta(ReferralMetaKeys.OFFER_PREFIX + "leg1", legacy)

        val decoded = assertNotNull(decodeStoredOffer(legacy))
        assertEquals(ts, decoded.firstSeenAt, "a missing t0 migrates to the record's own createdAt")

        // The manager loads it, and any later persist re-writes it WITH t0.
        val rm = ReferralManager(vault) { null }
        assertEquals(listOf("leg1"), rm.pendingOffers().map { it.introId })
        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_ACCEPT,
            fbAcceptJson("leg1", ByteArray(32) { 9 }))   // a stash arrival re-persists the offer
        val rewritten = assertNotNull(vault.getMeta(ReferralMetaKeys.OFFER_PREFIX + "leg1"))
        assertEquals(ts.toString(), firstStringFieldAnywhere(rewritten, "t0"), "migration-on-write pins the ORIGINAL first-seen")
    }

    /** A crafted `t0` in the FUTURE of `ts` cannot buy extra lifetime. */
    @Test
    fun aFirstSeenStampAheadOfCreatedAt_isClampedDown() {
        val ts = 1_000_000L
        val forged = encodeStoredOffer(StoredOffer("alice", "Alice", "Carol", ts, firstSeenAt = ts + 999_999_999L))
        assertEquals(ts, assertNotNull(decodeStoredOffer(forged)).firstSeenAt)
    }
}

// ---------------------------------------------------------------------------
// Refresh-on-activity, and its deliberate NON-application to rehydrate.
// ---------------------------------------------------------------------------

class ReferralRefreshOnActivityTest {

    private val noTransport: () -> MessageManager? = { null }

    /** A peer accept landing against an un-consented offer is proof the
     *  introduction is live: the offer AND our staged-but-unsent accept are
     *  re-stamped so a slow human cannot age them out from under a peer who has
     *  already committed. */
    @Test
    fun aStashArriving_reStampsTheOfferAndThePendingAccept() {
        if (!x25519Up()) return
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        val stale = currentTimeMillis() - REFERRAL_RECORD_TTL_MS + 3_600_000L   // 1 h left to live
        vault.putMeta(
            ReferralMetaKeys.OFFER_PREFIX + "rf1",
            encodeStoredOffer(StoredOffer("alice", "Alice", "Carol", stale)),
        )
        vault.putMeta(
            ReferralMetaKeys.ACCEPT_PREFIX + "rf1",
            encodeStoredAccept(
                // st=0: staged but never confirmed, so a peer accept is STASHED.
                StoredAccept("alice", "Carol", ByteArray(32) { 5 }, ByteArray(32) { 6 }, fbMint(), false, 0, stale)
            ),
        )
        val rm = ReferralManager(vault, noTransport)
        assertEquals(stale, fbStoredTs(vault, ReferralMetaKeys.OFFER_PREFIX + "rf1"), "rehydrate must not re-stamp")
        assertEquals(stale, fbStoredTs(vault, ReferralMetaKeys.ACCEPT_PREFIX + "rf1"), "rehydrate must not re-stamp")

        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_ACCEPT,
            fbAcceptJson("rf1", x25519GenerateKeypair().publicKey))

        assertEquals(1, metaKeysStartingWith(vault, ReferralMetaKeys.STASH_PREFIX).size, "precondition: the accept was stashed")
        assertTrue(
            assertNotNull(fbStoredTs(vault, ReferralMetaKeys.OFFER_PREFIX + "rf1")) > stale,
            "the offer must be re-stamped: the peer has provably accepted",
        )
        assertTrue(
            assertNotNull(fbStoredTs(vault, ReferralMetaKeys.ACCEPT_PREFIX + "rf1")) > stale,
            "our staged accept must be re-stamped too",
        )
        // The un-refreshable stamp is untouched, so the ceiling still applies.
        assertEquals(
            stale.toString(),
            firstStringFieldAnywhere(assertNotNull(vault.getMeta(ReferralMetaKeys.OFFER_PREFIX + "rf1")), "t0"),
            "refresh must never move firstSeenAt",
        )
    }

    /** Merely relaunching is NOT activity — otherwise the TTL would be
     *  meaningless for anyone who opens the app more often than once a week. */
    @Test
    fun rehydrateAlone_neverReStampsAnything() {
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        seedReferralContact(vault, "dave", "Dave")
        val stale = currentTimeMillis() - REFERRAL_RECORD_TTL_MS + 3_600_000L
        vault.putMeta(
            ReferralMetaKeys.OFFER_PREFIX + "rf2",
            encodeStoredOffer(StoredOffer("alice", "Alice", "Carol", stale)),
        )
        vault.putMeta(
            ReferralMetaKeys.SESSION_PREFIX + "rf3",
            encodeStoredSession(StoredSession("alice", "dave", emptySet(), stale, setOf("alice", "dave"), 0)),
        )
        vault.putMeta(
            ReferralMetaKeys.REDRIVE_PREFIX + "rf4:dave",
            encodeStoredRedrive(StoredRedrive("rf4", "dave", "alice", "{}", 0, stale)),
        )

        ReferralManager(vault, noTransport)
        ReferralManager(vault, noTransport)   // a second relaunch, for good measure

        assertEquals(stale, fbStoredTs(vault, ReferralMetaKeys.OFFER_PREFIX + "rf2"))
        assertEquals(stale, fbStoredTs(vault, ReferralMetaKeys.SESSION_PREFIX + "rf3"))
        assertEquals(stale, fbStoredTs(vault, ReferralMetaKeys.REDRIVE_PREFIX + "rf4:dave"))
    }

    /** An introducer relaying one side's accept re-stamps the session, so the
     *  other side's leg is not aged out while it is still in flight. */
    @Test
    fun relayingAnAccept_reStampsTheIntroducerSession() {
        if (!aeadUp() || !x25519Up()) return
        val f = FbIntroducerFixture()
        val stale = currentTimeMillis() - REFERRAL_RECORD_TTL_MS + 3_600_000L
        f.vault.putMeta(
            ReferralMetaKeys.SESSION_PREFIX + "rf5",
            encodeStoredSession(StoredSession("bb", "cc", emptySet(), stale, setOf("bb", "cc"), 0)),
        )
        val rm = f.newManager()
        assertEquals(stale, fbStoredTs(f.vault, ReferralMetaKeys.SESSION_PREFIX + "rf5"))

        f.http.script(httpAccepted())
        rm.handleControl("bb", MessageManager.CONTROL_KIND_REFERRAL_ACCEPT,
            fbAcceptJson("rf5", x25519GenerateKeypair().publicKey))

        assertTrue(
            assertNotNull(fbStoredTs(f.vault, ReferralMetaKeys.SESSION_PREFIX + "rf5")) > stale,
            "relaying one accept is activity for the whole introduction",
        )
    }

    /** A redrive ATTEMPT is activity for that obligation. */
    @Test
    fun aRedriveAttempt_reStampsTheObligation() {
        if (!aeadUp()) return
        val f = FbIntroducerFixture()
        val stale = currentTimeMillis() - REFERRAL_RECORD_TTL_MS + 3_600_000L
        f.vault.putMeta(
            ReferralMetaKeys.REDRIVE_PREFIX + "rf6:cc",
            encodeStoredRedrive(StoredRedrive("rf6", "cc", "bb", """{"ii":"rf6"}""", 0, stale)),
        )
        val rm = f.newManager()
        f.http.script(httpRefused())
        rm.runMaintenance()

        assertTrue(
            assertNotNull(fbStoredTs(f.vault, ReferralMetaKeys.REDRIVE_PREFIX + "rf6:cc")) > stale,
            "a failed redrive attempt still counts as activity — the idle TTL measures time since the last EVENT",
        )
    }
}

// ---------------------------------------------------------------------------
// Every referral control POST carries ?ttl=604800.
// ---------------------------------------------------------------------------

/** Introducer paired with both introducees on the control channel. */
private class FbIntroducerFixture {
    val vault = InMemoryVault()
    val http = RecordingRelayHttp()
    val mgr = MessageManager(vault, FB_RELAY, http as RelayHttp)
    val bCtlOut = "bbct" + "1".repeat(28)
    val cCtlOut = "ccct" + "2".repeat(28)

    init {
        vault.insertContact(ContactRecord("bb", generateSecureRandom(32), 0, "Bob", 0L))
        vault.insertContact(ContactRecord("cc", generateSecureRandom(32), 0, "Carol", 0L))
        vault.insertInboxId(InboxIdRecord(bCtlOut, "bb", 1L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_CTL, FB_CAP_W))
        vault.insertInboxId(InboxIdRecord(cCtlOut, "cc", 1L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_CTL, FB_CAP_X))
    }

    fun newManager() = ReferralManager(vault) { mgr }
    fun paths() = http.calls.map { it.url.removePrefix(FB_RELAY) }
}

class ReferralRelayTtlTest {

    @Test
    fun bothOffersAskTheRelayForSevenDayRetention() {
        if (!aeadUp()) return
        val f = FbIntroducerFixture()
        f.http.script(httpAccepted(), httpAccepted())
        val introId = assertNotNull(f.newManager().startReferral("bb", "cc"))
        assertTrue(introId.isNotEmpty())
        assertEquals(
            listOf("/inbox/${f.bCtlOut}?ttl=604800", "/inbox/${f.cCtlOut}?ttl=604800"),
            f.paths(),
            "the relay's default is 24 h — an offer that outlives it is exactly the half-pair the TTL fix addresses",
        )
    }

    @Test
    fun theRelayedAcceptAsksForItToo() {
        if (!aeadUp() || !x25519Up()) return
        val f = FbIntroducerFixture()
        f.http.script(httpAccepted(), httpAccepted())
        val rm = f.newManager()
        val introId = assertNotNull(rm.startReferral("bb", "cc"))
        f.http.script(httpAccepted())
        rm.handleControl("bb", MessageManager.CONTROL_KIND_REFERRAL_ACCEPT,
            fbAcceptJson(introId, x25519GenerateKeypair().publicKey))
        assertEquals("/inbox/${f.cCtlOut}?ttl=604800", f.paths().last())
    }

    /** Flip-check: a NON-referral send is byte-identical to what it always was —
     *  the TTL must not leak into the ordinary message path. */
    @Test
    fun anOrdinaryTextSend_carriesNoTtlParameter() {
        if (!aeadUp()) return
        val vault = InMemoryVault()
        val http = RecordingRelayHttp()
        val mgr = MessageManager(vault, FB_RELAY, http as RelayHttp)
        val out = "text" + "9".repeat(28)
        vault.insertContact(ContactRecord("bb", generateSecureRandom(32), 0, "Bob", 0L))
        vault.insertInboxId(InboxIdRecord(out, "bb", 1L, Long.MAX_VALUE, "outbound", FB_CAP_W))
        http.script(httpAccepted())
        assertTrue(mgr.sendMessage("bb", "hi"))
        assertEquals("/inbox/$out", http.calls.single().url.removePrefix(FB_RELAY))
    }
}

// ---------------------------------------------------------------------------
// The offer leg is a durable obligation, not fire-and-forget.
// ---------------------------------------------------------------------------

private fun fbSession(vault: InMemoryVault, introId: String): StoredSession? =
    vault.getMeta(ReferralMetaKeys.SESSION_PREFIX + introId)?.let { decodeStoredSession(it) }

class ReferralDurableOfferTest {

    @Test
    fun aFailedOfferSend_becomesADurableObligation_andIsRedriven() {
        if (!aeadUp()) return
        val f = FbIntroducerFixture()
        // Bob's offer lands; Carol's is refused.
        f.http.script(httpAccepted(), httpRefused())
        val rm = f.newManager()
        val introId = assertNotNull(rm.startReferral("bb", "cc"), "a queued introduction still returns its introId")

        val staged = assertNotNull(fbSession(f.vault, introId), "the session must be persisted")
        assertEquals(setOf("bb"), staged.offered, "only the DELIVERED side may be recorded")
        assertEquals(0, staged.offerAttempts)

        // One control sweep redrives exactly the missing side.
        f.http.script(httpAccepted())
        val before = f.http.calls.size
        rm.runMaintenance()
        assertEquals(before + 1, f.http.calls.size, "the sweep must retry only the undelivered offer")
        assertEquals("/inbox/${f.cCtlOut}?ttl=604800", f.paths().last())
        assertEquals(setOf("bb", "cc"), assertNotNull(fbSession(f.vault, introId)).offered)

        // …and once both are delivered nothing is re-sent.
        val settled = f.http.calls.size
        rm.runMaintenance()
        assertEquals(settled, f.http.calls.size, "a fully delivered introduction must not keep sending")
    }

    @Test
    fun theObligationSurvivesARestart() {
        if (!aeadUp()) return
        val f = FbIntroducerFixture()
        f.http.script(httpRefused(), httpRefused())
        val rm1 = f.newManager()
        val introId = assertNotNull(rm1.startReferral("bb", "cc"))
        assertEquals(emptySet<String>(), assertNotNull(fbSession(f.vault, introId)).offered)
        rm1.scrubInMemory()                             // == backgrounding / process death

        val rm2 = f.newManager()
        f.http.script(httpAccepted(), httpAccepted())
        val before = f.http.calls.size
        rm2.runMaintenance()
        assertEquals(before + 2, f.http.calls.size, "a fresh manager must redrive BOTH undelivered offers")
        assertEquals(setOf("bb", "cc"), assertNotNull(fbSession(f.vault, introId)).offered)
    }

    /** A send that THROWS must not escape startReferral — the record is already
     *  durable, so the failure is an obligation, not an error. Driven through a
     *  vault read that throws (the shape iOS's `execChecked` really produces),
     *  because a THROWING TRANSPORT is already folded to `false` inside
     *  MessageManager's transient-retry and would never reach this catch. */
    @Test
    fun aThrowingOfferSend_isSwallowed_andStillQueuesTheIntroduction() {
        val inner = InMemoryVault()
        inner.insertContact(ContactRecord("bb", generateSecureRandom(32), 0, "Bob", 0L))
        inner.insertContact(ContactRecord("cc", generateSecureRandom(32), 0, "Carol", 0L))
        val vault = object : VaultDatabase by inner {
            override fun getInboxIdForContact(contactId: String, direction: String): InboxIdRecord? =
                throw RuntimeException("vault read exploded mid-send")
        }
        val mgr = MessageManager(vault, FB_RELAY, RecordingRelayHttp() as RelayHttp)
        val introId = assertNotNull(
            ReferralManager(vault) { mgr }.startReferral("bb", "cc"),
            "a throwing send must not take startReferral down — the session is already durable",
        )
        assertEquals(emptySet<String>(), assertNotNull(fbSession(inner, introId)).offered)
    }

    /** Bounded like its two siblings, and the record is KEPT on exhaustion. */
    @Test
    fun theOfferRedrive_stopsAtItsBudget_andKeepsTheRecord() {
        if (!aeadUp()) return
        val f = FbIntroducerFixture()
        f.http.script(httpRefused(), httpRefused())
        val rm = f.newManager()
        val introId = assertNotNull(rm.startReferral("bb", "cc"))

        repeat(60) { f.http.script(httpRefused()) }
        val before = f.http.calls.size
        repeat(20) { rm.runMaintenance() }
        val attempts = f.http.calls.size - before
        // 12 sweeps x 2 undelivered sides.
        assertEquals(24, attempts, "the offer redrive must stop at its 12-sweep budget")
        val kept = assertNotNull(fbSession(f.vault, introId), "an exhausted budget must not delete the session")
        assertEquals(12, kept.offerAttempts)
        assertEquals(emptySet<String>(), kept.offered)
    }

    /** A `ref_s` written before the durable offer leg has no `of` field. It must load (never be
     *  GC'd as unreadable) and heal by re-sending — which the receive side
     *  dedups, so a redundant offer costs nothing and a lost one is recovered. */
    @Test
    fun aLegacySessionRecord_loadsAndHealsByReSendingBothOffers() {
        if (!aeadUp()) return
        val f = FbIntroducerFixture()
        val legacy = encodeStoredSession(StoredSession("bb", "cc", emptySet(), currentTimeMillis()))
            .let { Regex(""","of":"[^"]*"""").replace(it, "") }
            .let { Regex(""","on":"[^"]*"""").replace(it, "") }
        assertFalse(legacy.contains(""""of""""), "precondition: the legacy value really has no offered set")
        f.vault.putMeta(ReferralMetaKeys.SESSION_PREFIX + "leg2", legacy)
        val decoded = assertNotNull(decodeStoredSession(legacy), "a legacy session must still decode")
        assertEquals(emptySet<String>(), decoded.offered)
        assertEquals(0, decoded.offerAttempts)

        val rm = f.newManager()
        f.http.script(httpAccepted(), httpAccepted())
        rm.runMaintenance()
        assertEquals(
            listOf("/inbox/${f.bCtlOut}?ttl=604800", "/inbox/${f.cCtlOut}?ttl=604800"), f.paths(),
            "an in-flight legacy introduction heals by re-offering both sides once",
        )
        assertEquals(setOf("bb", "cc"), assertNotNull(fbSession(f.vault, "leg2")).offered)
    }

    /** The `of` list drives a SEND-SUPPRESSION decision, so a value naming
     *  anyone but the two parties must never be honoured. */
    @Test
    fun anOfferedSetNamingANonParty_isDiscardedOnRead() {
        val forged = encodeStoredSession(
            StoredSession("bb", "cc", emptySet(), 1L, offered = setOf("bb", "mallory"))
        )
        assertEquals(setOf("bb"), assertNotNull(decodeStoredSession(forged)).offered)
    }

    /** The session record is the SAME record `deleteContact` already purges, so
     *  the durable offer leg's new fields need no new clause in the shared classifier. */
    @Test
    fun theDurableOfferState_isStillPurgedWithEitherParty() {
        val now = currentTimeMillis()
        val key = ReferralMetaKeys.SESSION_PREFIX + "pg"
        val value = encodeStoredSession(StoredSession("bb", "cc", setOf("bb"), now, setOf("bb"), 3))
        assertTrue(isReferralMetaResidueForContact(key, value, "bb"))
        assertTrue(isReferralMetaResidueForContact(key, value, "cc"))
        assertFalse(isReferralMetaResidueForContact(key, value, "mallory"))
    }
}

// ---------------------------------------------------------------------------
// The stash is consumed by the finalize TRANSACTION, never before it.
// ---------------------------------------------------------------------------

class ReferralStashNotConsumedEarlyTest {

    /** A vault whose FIRST withTransaction throws — the retryable finalize
     *  branch. Under the old code the stash had already been deleted from RAM
     *  and from `_meta` by then, so this side could never finalize again. */
    private class OneShotFailingVault(val inner: InMemoryVault) : VaultDatabase by inner {
        var failNext = true
        override fun withTransaction(block: () -> Unit) {
            if (failNext) { failNext = false; throw RuntimeException("simulated vault write failure") }
            inner.withTransaction(block)
        }
    }

    /** The confirmAcceptSent path: our accept is confirmed while a peer accept
     *  is already stashed, and the finalize it triggers fails. */
    @Test
    fun aFailedFinalizeFromAStash_keepsRefA_andAReDriveStillFinalizes() {
        if (!x25519Up()) return
        val inner = InMemoryVault()
        seedReferralContact(inner, "alice", "Alice")
        val vault = OneShotFailingVault(inner)
        val rm = ReferralManager(vault) { null }

        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_OFFER, referralOfferJson("f4a", "Carol"))
        val carol = x25519GenerateKeypair()
        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_ACCEPT, fbAcceptJson("f4a", carol.publicKey))
        assertEquals(1, metaKeysStartingWith(inner, ReferralMetaKeys.STASH_PREFIX).size, "precondition: the peer accept is stashed")

        // Approving triggers the stashed-accept apply, whose transaction throws.
        rm.registerAccepted("f4a", rm.pendingOffers().single(), x25519GenerateKeypair(), fbMint())

        assertEquals(1, inner.getAllContacts().size, "a failed transaction must create no contact")
        assertNotNull(
            inner.getMeta(ReferralMetaKeys.STASH_PREFIX + "f4a"),
            "the peer's accept must SURVIVE a failed finalize — consuming it early made the failure permanent",
        )
        assertNotNull(inner.getMeta(ReferralMetaKeys.ACCEPT_PREFIX + "f4a"), "our own material survives too")

        // A relaunch re-drives it from the surviving stash and completes.
        rm.scrubInMemory()
        ReferralManager(vault) { null }
        assertEquals(2, inner.getAllContacts().size, "the surviving stash must finalize on the next launch")
        assertTrue(metaKeysStartingWith(inner, ReferralMetaKeys.STASH_PREFIX).isEmpty(), "the winning transaction drops it")
    }

    /** The rehydrate path, which had the same pre-delete. */
    @Test
    fun aFailedFinalizeAtRehydrate_keepsRefA_andTheNextLaunchFinalizes() {
        if (!x25519Up()) return
        val inner = InMemoryVault()
        seedReferralContact(inner, "alice", "Alice")
        val vault = OneShotFailingVault(inner)
        val bob = x25519GenerateKeypair()
        val carol = x25519GenerateKeypair()
        inner.putMeta(
            ReferralMetaKeys.ACCEPT_PREFIX + "f4b",
            encodeStoredAccept(
                StoredAccept("alice", "Carol", bob.privateKey, bob.publicKey, fbMint(), true, 0, currentTimeMillis())
            ),
        )
        inner.putMeta(
            ReferralMetaKeys.STASH_PREFIX + "f4b",
            encodeStoredStash(StoredStash("alice", fbAcceptJson("f4b", carol.publicKey), currentTimeMillis())),
        )

        ReferralManager(vault) { null }     // its rehydrate-time finalize throws
        assertEquals(1, inner.getAllContacts().size)
        assertNotNull(
            inner.getMeta(ReferralMetaKeys.STASH_PREFIX + "f4b"),
            "a rehydrate-time finalize failure must not destroy the peer's accept",
        )

        ReferralManager(vault) { null }     // the next launch succeeds
        assertEquals(2, inner.getAllContacts().size)
        assertTrue(metaKeysStartingWith(inner, ReferralMetaKeys.STASH_PREFIX).isEmpty())
    }

    /** Flip-check: on the SUCCESS path the stash is still gone — the transaction
     *  deletes it atomically with the contact, so nothing is left behind. */
    @Test
    fun aSuccessfulFinalize_stillLeavesNoStashBehind() {
        if (!x25519Up()) return
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        val rm = ReferralManager(vault) { null }
        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_OFFER, referralOfferJson("f4c", "Carol"))
        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_ACCEPT,
            fbAcceptJson("f4c", x25519GenerateKeypair().publicKey))
        rm.registerAccepted("f4c", rm.pendingOffers().single(), x25519GenerateKeypair(), fbMint())

        assertEquals(2, vault.getAllContacts().size)
        assertTrue(vault.meta.keys.none { it.startsWith(ReferralMetaKeys.STASH_PREFIX) })
        assertTrue(vault.meta.keys.none { it.startsWith(ReferralMetaKeys.ACCEPT_PREFIX) })
    }
}

// ---------------------------------------------------------------------------
// Attempt budgets are PER SESSION.
// ---------------------------------------------------------------------------

class ReferralAttemptBudgetPerSessionTest {

    /** An exhausted accept budget must not permanently disarm the redrive: the
     *  relay being down for one session is exactly when the obligation matters. */
    @Test
    fun anExhaustedAcceptBudget_isRearmedByTheNextSession() {
        if (!aeadUp()) return
        val vault = InMemoryVault()
        val http = RecordingRelayHttp()
        val mgr = MessageManager(vault, FB_RELAY, http as RelayHttp)
        val ctlOut = "acct" + "3".repeat(28)
        vault.insertContact(ContactRecord("aa", generateSecureRandom(32), 0, "Alice", 0L))
        vault.insertInboxId(InboxIdRecord(ctlOut, "aa", 1L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_CTL, FB_CAP_W))
        // A record whose budget was fully spent in a previous session.
        vault.putMeta(
            ReferralMetaKeys.ACCEPT_PREFIX + "f9a",
            encodeStoredAccept(
                StoredAccept("aa", "Carol", ByteArray(32) { 1 }, ByteArray(32) { 2 }, fbMint(), false, 12, currentTimeMillis())
            ),
        )

        val rm = ReferralManager(vault) { mgr }
        http.script(httpAccepted())
        rm.runMaintenance()

        assertEquals(1, http.calls.size, "a spent budget must be re-armed by the new session, not stay disarmed")
        assertTrue(assertNotNull(decodeStoredAccept(assertNotNull(vault.getMeta(ReferralMetaKeys.ACCEPT_PREFIX + "f9a")))).sent)
    }

    /** Same rule for the introducer's relay-forward obligation. */
    @Test
    fun anExhaustedRelayRedriveBudget_isRearmedByTheNextSession() {
        if (!aeadUp()) return
        val f = FbIntroducerFixture()
        f.vault.putMeta(
            ReferralMetaKeys.REDRIVE_PREFIX + "f9b:cc",
            encodeStoredRedrive(StoredRedrive("f9b", "cc", "bb", """{"ii":"f9b"}""", 12, currentTimeMillis())),
        )
        val rm = f.newManager()
        f.http.script(httpAccepted())
        rm.runMaintenance()
        assertEquals(1, f.http.calls.size, "a spent relay-redrive budget must be re-armed by the new session")
    }

    /** …and for the offer leg. */
    @Test
    fun anExhaustedOfferBudget_isRearmedByTheNextSession() {
        if (!aeadUp()) return
        val f = FbIntroducerFixture()
        f.vault.putMeta(
            ReferralMetaKeys.SESSION_PREFIX + "f9c",
            encodeStoredSession(StoredSession("bb", "cc", emptySet(), currentTimeMillis(), emptySet(), 12)),
        )
        val rm = f.newManager()
        f.http.script(httpAccepted(), httpAccepted())
        rm.runMaintenance()
        assertEquals(2, f.http.calls.size, "a spent offer budget must be re-armed by the new session")
    }

    /** WITHIN one session the budget still bites — that is what stops a hot
     *  retry loop against a permanently dead peer. */
    @Test
    fun withinOneSession_theBudgetStillBounds() {
        if (!aeadUp()) return
        val f = FbIntroducerFixture()
        f.vault.putMeta(
            ReferralMetaKeys.REDRIVE_PREFIX + "f9d:cc",
            encodeStoredRedrive(StoredRedrive("f9d", "cc", "bb", """{"ii":"f9d"}""", 0, currentTimeMillis())),
        )
        val rm = f.newManager()
        repeat(40) { f.http.script(httpRefused()) }
        repeat(30) { rm.runMaintenance() }
        assertEquals(12, f.http.calls.size, "a single session must still stop at 12 attempts")
        assertNotNull(f.vault.getMeta(ReferralMetaKeys.REDRIVE_PREFIX + "f9d:cc"), "the record is KEPT on exhaustion")
    }
}

// ---------------------------------------------------------------------------
// The platform contract: onIntroFinalized.
// ---------------------------------------------------------------------------

class ReferralFinalizeHookTest {

    @Test
    fun theHookFiresExactlyOnceOnASuccessfulFinalize() {
        if (!x25519Up()) return
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        val rm = ReferralManager(vault) { null }
        var fired = 0
        rm.onIntroFinalized = { fired++ }

        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_OFFER, referralOfferJson("hk1", "Carol"))
        rm.registerAccepted("hk1", rm.pendingOffers().single(), x25519GenerateKeypair(), fbMint())
        assertEquals(0, fired, "staging our own accept is not a finalize")

        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_ACCEPT,
            fbAcceptJson("hk1", x25519GenerateKeypair().publicKey))
        assertEquals(1, fired, "a committed referred contact must notify the platform")

        // A literal replay of the same body commits nothing, so it notifies nothing.
        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_ACCEPT,
            fbAcceptJson("hk1", x25519GenerateKeypair().publicKey))
        assertEquals(1, fired, "a re-delivered accept must not re-notify")
    }

    @Test
    fun theHookDoesNotFireOnARejectedFinalize() {
        if (!x25519Up()) return
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        // A victim already owns one of the ids the peer will announce → the
        // inbox-in-use rejection (terminal, nothing written).
        seedReferralContact(vault, "victim", "Victim")
        vault.insertInboxId(InboxIdRecord(FB_PEER_IB, "victim", 1L, Long.MAX_VALUE, "outbound", FB_CAP_W))
        val rm = ReferralManager(vault) { null }
        var fired = 0
        rm.onIntroFinalized = { fired++ }

        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_OFFER, referralOfferJson("hk2", "Carol"))
        rm.registerAccepted("hk2", rm.pendingOffers().single(), x25519GenerateKeypair(), fbMint())
        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_ACCEPT,
            fbAcceptJson("hk2", x25519GenerateKeypair().publicKey))

        assertEquals(2, vault.getAllContacts().size, "precondition: the finalize really was rejected")
        assertEquals(0, fired, "a rejected finalize writes nothing and must notify nothing")
    }

    @Test
    fun aMalformedPeerAccept_doesNotFireTheHook() {
        if (!x25519Up()) return
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        val rm = ReferralManager(vault) { null }
        var fired = 0
        rm.onIntroFinalized = { fired++ }
        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_OFFER, referralOfferJson("hk3", "Carol"))
        rm.registerAccepted("hk3", rm.pendingOffers().single(), x25519GenerateKeypair(), fbMint())
        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_ACCEPT,
            fbAcceptJson("hk3", ByteArray(31) { 7 }))   // wrong-size public key
        assertEquals(1, vault.getAllContacts().size)
        assertEquals(0, fired)
    }

    /** The case that matters most: the peer accepted while we were dead, so the
     *  finalize happens inside the CONSTRUCTOR — before any platform code could
     *  have installed a hook. Installing it afterwards must still deliver. */
    @Test
    fun aRehydrateTimeFinalize_notifiesTheHookInstalledAfterConstruction() {
        if (!x25519Up()) return
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        val bob = x25519GenerateKeypair()
        val carol = x25519GenerateKeypair()
        vault.putMeta(
            ReferralMetaKeys.ACCEPT_PREFIX + "hk4",
            encodeStoredAccept(
                StoredAccept("alice", "Carol", bob.privateKey, bob.publicKey, fbMint(), true, 0, currentTimeMillis())
            ),
        )
        vault.putMeta(
            ReferralMetaKeys.STASH_PREFIX + "hk4",
            encodeStoredStash(StoredStash("alice", fbAcceptJson("hk4", carol.publicKey), currentTimeMillis())),
        )

        val rm = ReferralManager(vault) { null }
        assertEquals(2, vault.getAllContacts().size, "precondition: rehydrate finalized it")

        var fired = 0
        rm.onIntroFinalized = { fired++ }
        assertEquals(1, fired, "a finalize that predates the hook must still be announced once it is installed")

        // …and only once.
        rm.onIntroFinalized = { fired++ }
        assertEquals(1, fired, "the deferred notice is one-shot")
    }

    @Test
    fun aThrowingHook_neverBreaksTheFinalize() {
        if (!x25519Up()) return
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        val rm = ReferralManager(vault) { null }
        rm.onIntroFinalized = { throw RuntimeException("UI blew up") }
        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_OFFER, referralOfferJson("hk5", "Carol"))
        rm.registerAccepted("hk5", rm.pendingOffers().single(), x25519GenerateKeypair(), fbMint())
        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_ACCEPT,
            fbAcceptJson("hk5", x25519GenerateKeypair().publicKey))
        assertEquals(2, vault.getAllContacts().size, "the contact is committed regardless of the hook")
    }
}

// ---------------------------------------------------------------------------
// 1C-2 — the done-tombstone must store a HASH of the introId, never the raw
// introId. `referredContactIdFor(introId)` derives the referred contact's id
// DETERMINISTICALLY and SALT-FREE from that same introId, identically on the
// peer's device, so a raw introId surviving a contact delete in `ref_done` was
// a computable cross-device link to the deleted relationship. `doneTokenFor`
// hashes under a DIFFERENT domain-separated prefix so the stored value can
// never be turned back into the contact id, while equality-based dedupe (the
// only thing this list is for) keeps working exactly as before.
// ---------------------------------------------------------------------------
class ReferralDoneTombstoneHashingTest {

    @Test
    fun theDoneTombstone_holdsAHash_neverTheRawIntroIdOrTheContactId() {
        if (!x25519Up()) return
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        val rm = ReferralManager(vault) { null }
        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_OFFER, referralOfferJson("dt1", "Carol"))
        rm.registerAccepted("dt1", rm.pendingOffers().single(), x25519GenerateKeypair(), fbMint())
        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_ACCEPT,
            fbAcceptJson("dt1", x25519GenerateKeypair().publicKey))
        val referred = ReferralManager.referredContactIdFor("dt1")
        assertNotNull(vault.getContact(referred), "precondition: the referral finalized")

        assertNull(vault.getMeta(ReferralMetaKeys.COMPLETED_KEY), "current code never writes the legacy v1 key")
        val doneRaw = assertNotNull(vault.getMeta(ReferralMetaKeys.COMPLETED_KEY_V2))
        assertFalse(doneRaw.contains("dt1"), "the raw introId must never be persisted (1C-2)")
        assertFalse(doneRaw.contains(referred), "the referred contact's id must never be persisted either")
        assertTrue(
            decodeCompletedIntros(doneRaw, 128).contains(ReferralManager.doneTokenFor("dt1")),
            "the hashed done-token must still be present, so dedupe keeps working",
        )
    }

    @Test
    fun dedupe_aReDeliveredOfferAfterFinalize_isDroppedAndNeverReCreatesTheContact() {
        if (!x25519Up()) return
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        val rm = ReferralManager(vault) { null }
        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_OFFER, referralOfferJson("dt2", "Carol"))
        rm.registerAccepted("dt2", rm.pendingOffers().single(), x25519GenerateKeypair(), fbMint())
        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_ACCEPT,
            fbAcceptJson("dt2", x25519GenerateKeypair().publicKey))
        assertEquals(2, vault.getAllContacts().size, "precondition: finalized once (alice + the referred Carol)")

        // The relay re-delivers the same offer blob (it lingers in the inbox).
        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_OFFER, referralOfferJson("dt2", "Carol"))
        assertTrue(rm.pendingOffers().isEmpty(), "a completed introId must never re-raise a consent dialog")
        assertEquals(2, vault.getAllContacts().size, "a re-delivered offer must never mint a second contact")
    }

    @Test
    fun rehydrate_migratesALegacyV1Tombstone_toHashedV2_andDeletesV1() {
        if (!x25519Up()) return
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        // Simulate a vault written by pre-fix code: raw introIds in the v1 key.
        vault.putMeta(ReferralMetaKeys.COMPLETED_KEY, encodeCompletedIntros(listOf("legacy1", "legacy2"), 128))

        val rm = ReferralManager(vault) { null }

        assertNull(vault.getMeta(ReferralMetaKeys.COMPLETED_KEY), "the legacy v1 key must be deleted on migration")
        val v2 = assertNotNull(vault.getMeta(ReferralMetaKeys.COMPLETED_KEY_V2))
        val tokens = decodeCompletedIntros(v2, 128)
        assertTrue(tokens.contains(ReferralManager.doneTokenFor("legacy1")))
        assertTrue(tokens.contains(ReferralManager.doneTokenFor("legacy2")))
        assertFalse(v2.contains("legacy1"), "the migrated value must never contain the raw introId")
        assertFalse(v2.contains("legacy2"))

        // The migrated tombstone still dedupes: a re-delivered offer for the
        // now-hashed legacy introId must be dropped just like before migration.
        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_OFFER, referralOfferJson("legacy1", "Carol"))
        assertTrue(rm.pendingOffers().isEmpty(), "a migrated completed introId must still dedupe")
    }

    @Test
    fun rehydrate_withNoLegacyV1Key_writesNothingAndStaysEmpty() {
        if (!x25519Up()) return
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        ReferralManager(vault) { null }
        assertNull(vault.getMeta(ReferralMetaKeys.COMPLETED_KEY))
        assertNull(vault.getMeta(ReferralMetaKeys.COMPLETED_KEY_V2), "a fresh vault must not gain a tombstone from rehydrate alone")
    }
}

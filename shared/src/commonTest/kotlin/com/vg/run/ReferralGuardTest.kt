package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// Referral GUARDS — the creation-time null paths (self-referral, unknown
// contact, no transport: all previously untested), the wrong-party rejections
// on BOTH roles, the reflected-inbox-id micro-branches, offer replay/alias
// hygiene, and the best-effort store degradation (a `_meta` write/delete
// failure must degrade to RAM-only, never fail the handshake).
//
// Everything here is either an authorization/authenticity guard (a paired but
// misbehaving introducer/peer must not be able to bind an introduction to the
// wrong party, swap the consent text, or reflect our own inbox ids back) or a
// robustness guard (malformed input and store failures degrade, never throw,
// never brick).
// ---------------------------------------------------------------------------

private val RG_OFFER = MessageManager.CONTROL_KIND_REFERRAL_OFFER
private val RG_ACCEPT = MessageManager.CONTROL_KIND_REFERRAL_ACCEPT

/** 32-char inbox ids / 43-char caps — the shapes the validators demand. */
private val RG_PEER_IB  = "gp" + "A".repeat(30)
private val RG_PEER_CIB = "gp" + "B".repeat(30)
private val RG_MY_IB    = "gm" + "C".repeat(30)
private val RG_MY_CIB   = "gm" + "D".repeat(30)
private val RG_CAP_R = "R".repeat(43)
private val RG_CAP_W = "W".repeat(43)
private val RG_CAP_S = "S".repeat(43)
private val RG_CAP_X = "X".repeat(43)

private fun rgMint() = MintedInboxPair(
    MintedInbox(RG_MY_IB, RG_CAP_R, RG_CAP_W, Long.MAX_VALUE),
    MintedInbox(RG_MY_CIB, RG_CAP_S, RG_CAP_X, Long.MAX_VALUE),
)

private fun rgAcceptJson(
    introId: String,
    peerPub: ByteArray,
    ib: String = RG_PEER_IB,
    cib: String = RG_PEER_CIB,
) = """{"ii":${jsonEscapeString(introId)},"pk":${jsonEscapeString(encodeBase64(peerPub))},""" +
    """"ib":${jsonEscapeString(ib)},"wc":${jsonEscapeString(RG_CAP_W)},""" +
    """"cib":${jsonEscapeString(cib)},"cwc":${jsonEscapeString(RG_CAP_X)}}"""

/** Introducer paired with both introducees AND an unrelated third contact. */
private class RgIntroducerFixture {
    val vault = InMemoryVault()
    val http = RecordingRelayHttp()
    val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)

    init {
        seedReferralContact(vault, "bb", "Bob")
        seedReferralContact(vault, "cc", "Carol")
        seedReferralContact(vault, "dave", "Dave")
        vault.insertInboxId(InboxIdRecord("gbct" + "1".repeat(28), "bb", 1L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_CTL, RG_CAP_W))
        vault.insertInboxId(InboxIdRecord("gcct" + "2".repeat(28), "cc", 1L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_CTL, RG_CAP_X))
        vault.insertInboxId(InboxIdRecord("gdct" + "3".repeat(28), "dave", 1L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_CTL, RG_CAP_W))
    }

    fun newManager() = ReferralManager(vault) { mgr }
}


// ---------------------------------------------------------------------------
// startReferral's refusal paths — all previously untested. Each must return
// null AND leave nothing behind: no session record, no relay traffic.
// ---------------------------------------------------------------------------

class ReferralStartGuardTest {

    @Test
    fun selfReferral_isRefused_andWritesNothing() {
        val f = RgIntroducerFixture()
        val rm = f.newManager()

        assertNull(rm.startReferral("bb", "bb"), "a contact cannot be introduced to itself")

        assertTrue(metaKeysStartingWith(f.vault, ReferralMetaKeys.SESSION_PREFIX).isEmpty(), "no session may be persisted")
        assertEquals(0, f.http.calls.size, "no offer may leave for a refused introduction")
    }

    @Test
    fun unknownContactInEitherPosition_isRefused_andWritesNothing() {
        val f = RgIntroducerFixture()
        val rm = f.newManager()

        assertNull(rm.startReferral("bb", "ghost"), "an unknown introducee B must refuse")
        assertNull(rm.startReferral("ghost", "cc"), "an unknown introducee A must refuse")

        assertTrue(metaKeysStartingWith(f.vault, ReferralMetaKeys.SESSION_PREFIX).isEmpty(), "no session may be persisted")
        assertEquals(0, f.http.calls.size, "no offer may leave when a party does not exist")
    }

    @Test
    fun noTransport_isRefused_beforeAnythingIsPersisted() {
        val vault = InMemoryVault()
        seedReferralContact(vault, "bb", "Bob")
        seedReferralContact(vault, "cc", "Carol")

        assertNull(
            ReferralManager(vault) { null }.startReferral("bb", "cc"),
            "with no transport at all the introduction must refuse (offer-time-closed, unit half)",
        )
        assertTrue(
            vault.meta.keys.none { isReferralMetaKey(it) },
            "the refusal happens before the session is persisted — nothing to redrive later",
        )
    }

    /** A party deleted while its offer leg is still undelivered: the redrive
     *  must skip it without a crash and without a send — and must not
     *  resurrect the session record `deleteContact` just purged. */
    @Test
    fun aDeletedParty_stopsTheOfferRedrive_withoutCrashOrSend() {
        if (!aeadUp()) return
        val f = RgIntroducerFixture()
        val rm = f.newManager()
        f.http.script(httpRefused(), httpRefused())        // both offer legs undelivered
        val introId = assertNotNull(rm.startReferral("bb", "cc"))

        f.vault.deleteContact("cc")                    // purges ref_s via the shared classifier
        assertNull(
            f.vault.getMeta(ReferralMetaKeys.SESSION_PREFIX + introId),
            "precondition: the delete purged the session record",
        )

        repeat(5) { f.http.script(httpAccepted(), httpAccepted()) }    // generous script — it must all go unused
        val before = f.http.calls.size
        repeat(5) { rm.runMaintenance() }

        assertEquals(before, f.http.calls.size, "no offer may be sent toward, or about, a deleted party")
        assertNull(
            f.vault.getMeta(ReferralMetaKeys.SESSION_PREFIX + introId),
            "the redrive must not resurrect the purged session record",
        )
    }
}

// ---------------------------------------------------------------------------
// Wrong-party guards, on both roles, plus the forged-stash rehydrate check.
// ---------------------------------------------------------------------------

class ReferralWrongPartyTest {

    /** INTRODUCER role: an accept from a known contact who is NOT one of the
     *  two parties must be dropped — not relayed, and no redrive queued. */
    @Test
    fun introducerSide_anAcceptFromANonParty_isDroppedNotRelayed() {
        if (!aeadUp()) return
        val f = RgIntroducerFixture()
        val rm = f.newManager()
        f.http.script(httpAccepted(), httpAccepted())
        val introId = assertNotNull(rm.startReferral("bb", "cc"))
        val before = f.http.calls.size

        rm.handleControl("dave", RG_ACCEPT, rgAcceptJson(introId, ByteArray(32) { 7 }))

        assertEquals(before, f.http.calls.size, "an accept from a non-party must not be relayed to either side")
        assertTrue(
            metaKeysStartingWith(f.vault, ReferralMetaKeys.REDRIVE_PREFIX).isEmpty(),
            "…and must not queue a redrive obligation",
        )
        val ses = assertNotNull(decodeStoredSession(assertNotNull(f.vault.getMeta(ReferralMetaKeys.SESSION_PREFIX + introId))))
        assertTrue(ses.relayed.isEmpty(), "the session must not record a relay that never happened")
    }

    /** INTRODUCEE role, PRE-consent: only the introducer who made the offer may
     *  stash an accept against it. (The post-accept sibling is pinned by
     *  accept_notFromMyIntroducer_isIgnored; this is the stash path.) */
    @Test
    fun introduceeSide_aPreConsentAcceptFromANonIntroducer_isNotStashed() {
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        seedReferralContact(vault, "mallory", "Mallory")
        val rm = ReferralManager(vault) { null }
        rm.handleControl("alice", RG_OFFER, referralOfferJson("wp1", "Carol"))
        val tsBefore = firstStringFieldAnywhere(assertNotNull(vault.getMeta(ReferralMetaKeys.OFFER_PREFIX + "wp1")), "ts")

        rm.handleControl("mallory", RG_ACCEPT, rgAcceptJson("wp1", ByteArray(32) { 7 }))

        assertTrue(
            metaKeysStartingWith(vault, ReferralMetaKeys.STASH_PREFIX).isEmpty(),
            "only the introducer who made the offer may stash an accept against it",
        )
        assertEquals(2, vault.getAllContacts().size, "nothing may pair")
        assertEquals(listOf("wp1"), rm.pendingOffers().map { it.introId }, "the offer stays pending, untouched")
        assertEquals(
            tsBefore,
            firstStringFieldAnywhere(assertNotNull(vault.getMeta(ReferralMetaKeys.OFFER_PREFIX + "wp1")), "ts"),
            "an impostor's accept is not activity — it must not re-stamp the offer",
        )
    }

    /** A persisted stash whose relayer is NOT our introducer (only reachable via
     *  a corrupted/crafted `ref_a` record — handleAccept validates before it
     *  ever stashes) must not be applied at rehydrate, and must not poison the
     *  handshake: the genuine relayed accept still finalizes. */
    @Test
    fun aForgedStashNamingTheWrongRelayer_isNotAppliedAtRehydrate() {
        if (!x25519Up()) return
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        val bob = x25519GenerateKeypair()
        val carol = x25519GenerateKeypair()
        vault.putMeta(
            ReferralMetaKeys.ACCEPT_PREFIX + "fs1",
            encodeStoredAccept(
                StoredAccept("alice", "Carol", bob.privateKey, bob.publicKey, rgMint(), true, 0, currentTimeMillis())
            ),
        )
        vault.putMeta(
            ReferralMetaKeys.STASH_PREFIX + "fs1",
            encodeStoredStash(StoredStash("mallory", rgAcceptJson("fs1", carol.publicKey), currentTimeMillis())),
        )

        val rm = ReferralManager(vault) { null }

        assertEquals(
            1, vault.getAllContacts().size,
            "a stash claiming a relayer other than our introducer must not finalize at rehydrate",
        )
        // The handshake is not poisoned: the genuine accept from the real
        // introducer still completes this introduction.
        rm.handleControl("alice", RG_ACCEPT, rgAcceptJson("fs1", carol.publicKey))
        assertEquals(2, vault.getAllContacts().size, "the genuine relayed accept must still finalize")
        assertNotNull(vault.getContact(ReferralManager.referredContactIdFor("fs1")))
    }
}

// ---------------------------------------------------------------------------
// The reflected-inbox-id guard: a peer (or a hostile introducer editing the
// relayed body) announcing OUR freshly-minted ids back at us — straight or
// cross — must be rejected, and the rejection must stay RECOVERABLE.
// ---------------------------------------------------------------------------

class ReferralEchoedInboxGuardTest {

    private class Staged(val vault: InMemoryVault, val rm: ReferralManager, val introId: String)

    private fun staged(introId: String): Staged {
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        val rm = ReferralManager(vault) { null }
        rm.handleControl("alice", RG_OFFER, referralOfferJson(introId, "Carol"))
        rm.registerAccepted(introId, rm.pendingOffers().single(), x25519GenerateKeypair(), rgMint())
        return Staged(vault, rm, introId)
    }

    private fun assertRejectedButRecoverable(s: Staged) {
        assertEquals(1, s.vault.getAllContacts().size, "a reflected inbox id must never finalize")
        assertEquals(0, s.vault.inboxes.size, "a rejected accept must write no inbox rows")
        assertNotNull(
            s.vault.getMeta(ReferralMetaKeys.ACCEPT_PREFIX + s.introId),
            "our own material must be kept — the real peer may still send a good accept",
        )
        s.rm.handleControl("alice", RG_ACCEPT, rgAcceptJson(s.introId, x25519GenerateKeypair().publicKey))
        assertEquals(2, s.vault.getAllContacts().size, "a well-formed accept must still finalize the same introId")
    }

    @Test
    fun aPeerEchoingOurMintedMainInbox_isRejectedButRecoverable() {
        if (!x25519Up()) return
        val s = staged("eb1")
        s.rm.handleControl(
            "alice", RG_ACCEPT,
            rgAcceptJson("eb1", x25519GenerateKeypair().publicKey, ib = RG_MY_IB),
        )
        assertRejectedButRecoverable(s)
    }

    @Test
    fun aPeerCrossEchoingOurInboxes_isRejectedButRecoverable() {
        if (!x25519Up()) return
        val s = staged("eb2")
        // Their MAIN naming our CONTROL id…
        s.rm.handleControl(
            "alice", RG_ACCEPT,
            rgAcceptJson("eb2", x25519GenerateKeypair().publicKey, ib = RG_MY_CIB),
        )
        assertEquals(1, s.vault.getAllContacts().size, "cross-reflection (main←ctl) must be rejected")
        // …and their CONTROL naming our MAIN id.
        s.rm.handleControl(
            "alice", RG_ACCEPT,
            rgAcceptJson("eb2", x25519GenerateKeypair().publicKey, cib = RG_MY_IB),
        )
        assertRejectedButRecoverable(s)
    }
}

// ---------------------------------------------------------------------------
// Offer replay/alias hygiene — the consent text and the introducer binding are
// fixed at FIRST receipt; a re-delivery can change neither.
// ---------------------------------------------------------------------------

class ReferralOfferHygieneTest {

    private val noTransport: () -> MessageManager? = { null }

    @Test
    fun aReDeliveredOfferWithADifferentAlias_cannotSwapTheConsentText() {
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        val rm = ReferralManager(vault, noTransport)
        rm.handleControl("alice", RG_OFFER, referralOfferJson("oh1", "Carol"))
        // "Carol" does not conform to ContactAliasGenerator's format, so it
        // was replaced with a freshly generated alias rather than rejecting the
        // offer — capture what was actually stored instead of hardcoding it.
        val firstAlias = rm.pendingOffers().single().peerAlias
        assertTrue(
            ContactAliasGenerator.matchesGeneratedFormat(firstAlias),
            "a non-conforming pa must be replaced by a generated alias",
        )

        rm.handleControl("alice", RG_OFFER, referralOfferJson("oh1", "Definitely Not Carol"))

        val offer = rm.pendingOffers().single()
        assertEquals(firstAlias, offer.peerAlias, "the consent text is fixed at first receipt — no alias swap")
        assertEquals(
            firstAlias,
            firstStringFieldAnywhere(assertNotNull(vault.getMeta(ReferralMetaKeys.OFFER_PREFIX + "oh1")), "pa"),
            "the persisted record must keep the original alias too",
        )
    }

    @Test
    fun theSameIntroIdFromASecondIntroducer_cannotRebindTheIntroduction() {
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        seedReferralContact(vault, "dave", "Dave")
        val rm = ReferralManager(vault, noTransport)
        rm.handleControl("alice", RG_OFFER, referralOfferJson("oh2", "Carol"))

        rm.handleControl("dave", RG_OFFER, referralOfferJson("oh2", "Eve"))

        val offer = rm.pendingOffers().single()
        assertEquals("alice", offer.introducerContactId, "an introId in flight stays bound to its FIRST introducer")
        assertEquals(
            "alice",
            firstStringFieldAnywhere(assertNotNull(vault.getMeta(ReferralMetaKeys.OFFER_PREFIX + "oh2")), "ic"),
            "the persisted binding must not move either",
        )
    }

    /** The in-session sibling of rehydrate's supersede rule: once we accepted
     *  (offer consumed, accept in flight), a re-delivered offer must not
     *  re-raise the consent prompt — the `pending` guard, not the tombstone. */
    @Test
    fun aReDeliveredOffer_whileOurAcceptIsInFlight_doesNotResurrectTheConsentPrompt() {
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        val rm = ReferralManager(vault, noTransport)
        rm.handleControl("alice", RG_OFFER, referralOfferJson("oh3", "Carol"))
        rm.registerAccepted(
            "oh3", rm.pendingOffers().single(),
            X25519Keypair(ByteArray(32) { 1 }, ByteArray(32) { 2 }), rgMint(),
        )
        assertTrue(rm.pendingOffers().isEmpty(), "precondition: the accept consumed the offer")

        rm.handleControl("alice", RG_OFFER, referralOfferJson("oh3", "Carol"))

        assertTrue(rm.pendingOffers().isEmpty(), "an in-flight introId must not re-raise consent")
        assertNull(vault.getMeta(ReferralMetaKeys.OFFER_PREFIX + "oh3"), "no offer record may be re-created")
    }

    /** Rehydrate's half of the same rule: a persisted offer whose accept record
     *  is already SENT is superseded — dropped from RAM and from the vault. */
    @Test
    fun rehydrate_dropsAnOfferWhoseAcceptAlreadyLeft() {
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        val now = currentTimeMillis()
        vault.putMeta(
            ReferralMetaKeys.OFFER_PREFIX + "oh4",
            encodeStoredOffer(StoredOffer("alice", "Alice", "Carol", now)),
        )
        vault.putMeta(
            ReferralMetaKeys.ACCEPT_PREFIX + "oh4",
            encodeStoredAccept(
                StoredAccept("alice", "Carol", ByteArray(32) { 1 }, ByteArray(32) { 2 }, rgMint(), true, 0, now)
            ),
        )

        val rm = ReferralManager(vault, noTransport)

        assertTrue(rm.pendingOffers().isEmpty(), "a sent accept supersedes its offer — no consent prompt")
        assertNull(vault.getMeta(ReferralMetaKeys.OFFER_PREFIX + "oh4"), "the superseded offer record is GC'd")
        assertNotNull(vault.getMeta(ReferralMetaKeys.ACCEPT_PREFIX + "oh4"), "the accept record itself is kept")
    }

    /** An oversized/garbage `pa` used to be stored
     *  VERBATIM, just truncated at MAX_ALIAS_CHARS — a hostile introducer's
     *  alias became the new contact's displayed name outright. It must now be
     *  REPLACED with a freshly generated, format-conforming alias instead. */
    @Test
    fun aNonConformingPeerAlias_isReplacedWithAGeneratedOne_neverStoredVerbatim() {
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        val rm = ReferralManager(vault, noTransport)

        rm.handleControl("alice", RG_OFFER, referralOfferJson("oh5", "A".repeat(100)))

        val stored = rm.pendingOffers().single().peerAlias
        assertNotEquals(
            "A".repeat(64), stored,
            "an attacker-controlled non-conforming alias must never be stored verbatim, even truncated",
        )
        assertTrue(
            ContactAliasGenerator.matchesGeneratedFormat(stored),
            "a non-conforming pa is replaced by a freshly generated, format-conforming alias",
        )
    }

    /** The companion positive case: exotic Unicode (bidi overrides, zero-width
     *  joiners, control characters) never survives either — matchesGeneratedFormat
     *  rejects anything that isn't an exact word from the fixed lists, so these
     *  are all replaced exactly like the oversized-ASCII case above. */
    @Test
    fun aHostileUnicodePeerAlias_isReplacedWithAGeneratedOne() {
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        val rm = ReferralManager(vault, noTransport)

        val hostile = "Running\u200B Fox\u202E\u0000"  // ZWSP + RLO + NUL smuggled into an otherwise-plausible name
        rm.handleControl("alice", RG_OFFER, referralOfferJson("oh5b", hostile))

        val stored = rm.pendingOffers().single().peerAlias
        assertNotEquals(hostile, stored, "an alias carrying bidi/zero-width/control characters must never survive")
        assertTrue(
            ContactAliasGenerator.matchesGeneratedFormat(stored),
            "it is replaced by a freshly generated, format-conforming alias",
        )
    }

    /** An empty/blank `pa` is non-conforming too —
     *  it must never leave the new contact with a blank displayed name. */
    @Test
    fun anEmptyPeerAlias_isReplacedWithAGeneratedOne() {
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        val rm = ReferralManager(vault, noTransport)

        rm.handleControl("alice", RG_OFFER, referralOfferJson("oh5c", ""))

        val stored = rm.pendingOffers().single().peerAlias
        assertTrue(stored.isNotBlank(), "an empty pa must never leave the alias blank")
        assertTrue(ContactAliasGenerator.matchesGeneratedFormat(stored))
    }

    /** a `pa` that collides (case-insensitively) with
     *  an EXISTING contact's alias must be re-rolled to something else — a
     *  Sybil-named introduction must never visually shadow a real contact. */
    @Test
    fun aPeerAlias_collidingWithAnExistingContact_isRerolled() {
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        // An existing contact already holds a generated-format alias, deliberately
        // lowercased + with extra whitespace-adjacent casing to prove the
        // comparison is case-insensitive, not a literal match.
        seedReferralContact(vault, "existing", "running fox")
        val rm = ReferralManager(vault, noTransport)

        rm.handleControl("alice", RG_OFFER, referralOfferJson("oh5d", "Running Fox"))

        val stored = rm.pendingOffers().single().peerAlias
        assertNotEquals(
            "running fox", ContactAliasGenerator.normalizeForCompare(stored),
            "a colliding alias must be re-rolled, never left to shadow an existing contact",
        )
        assertTrue(ContactAliasGenerator.matchesGeneratedFormat(stored))
    }

    /** An introId that fails the key-shape gate degrades to the documented
     *  RAM-only behaviour: usable this session, never persisted, gone after a
     *  restart — it must not contaminate a `_meta` key name.
     *
     *  A LEGITIMATE per-introducer rate-limit
     *  `_meta` key (`ref_off_rl:<introducerContactId>`) that every accepted
     *  offer writes regardless of its introId — it is keyed by the (already
     *  vault-known, trusted) introducer contact id, never by the introId, so
     *  it cannot be contaminated by a hostile introId. The assertion below is
     *  narrowed to that specific property (no key/value anywhere references
     *  the unsafe introId) rather than "no referral _meta key of any kind". */
    @Test
    fun aHostileIntroId_degradesToRamOnly_andNeverReachesTheVault() {
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        val rm = ReferralManager(vault, noTransport)

        rm.handleControl("alice", RG_OFFER, referralOfferJson("bad:intro", "Carol"))

        assertEquals(listOf("bad:intro"), rm.pendingOffers().map { it.introId }, "the offer is still usable in RAM")
        assertNull(
            vault.getMeta(ReferralMetaKeys.OFFER_PREFIX + "bad:intro"),
            "an unsafe introId must never be persisted as an offer record",
        )
        assertTrue(
            vault.meta.keys.none { it.contains("bad:intro") } && vault.meta.values.none { it.contains("bad:intro") },
            "an unsafe introId must never contaminate any _meta key OR value, found: ${vault.meta}",
        )

        rm.scrubInMemory()
        assertTrue(
            ReferralManager(vault, noTransport).pendingOffers().isEmpty(),
            "the RAM-only degradation means the offer does not survive a restart",
        )
    }

    @Test
    fun malformedBodiesAndUnknownKinds_areDroppedWithoutStateOrThrow() {
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        val rm = ReferralManager(vault, noTransport)

        rm.handleControl("alice", RG_OFFER, """{"pa":"Carol"}""")            // no introId
        rm.handleControl("alice", RG_OFFER, """{"ii":"oh6"}""")              // no alias
        rm.handleControl("alice", RG_ACCEPT, """{"pk":"AAAA"}""")            // no introId
        rm.handleControl("alice", "ref-bogus", """{"ii":"oh6"}""")           // unknown kind

        assertTrue(rm.pendingOffers().isEmpty(), "no malformed body may park an offer")
        assertTrue(vault.meta.keys.none { isReferralMetaKey(it) }, "no malformed body may persist anything")
        assertEquals(1, vault.getAllContacts().size)

        // …and the manager is still fully usable afterwards.
        rm.handleControl("alice", RG_OFFER, referralOfferJson("oh7", "Carol"))
        assertEquals(listOf("oh7"), rm.pendingOffers().map { it.introId })
    }
}

// ---------------------------------------------------------------------------
// Store degradation — every referral `_meta` writer/deleter is best-effort:
// a failing store degrades the manager to RAM-only, it never fails the
// user-visible operation and never throws out of the receive path.
// ---------------------------------------------------------------------------

class ReferralStoreDegradeTest {

    /** Throws on every REFERRAL `_meta` write; everything else (the finalize
     *  transaction's contact/inbox/ratchet writes) works normally. */
    private class RefMetaWriteFailingVault(val inner: InMemoryVault) : VaultDatabase by inner {
        override fun putMeta(key: String, value: String) {
            if (key.startsWith(ReferralMetaKeys.PREFIX)) throw RuntimeException("simulated _meta write failure")
            inner.putMeta(key, value)
        }
    }

    /** Throws on every REFERRAL `_meta` delete instead. */
    private class RefMetaDeleteFailingVault(val inner: InMemoryVault) : VaultDatabase by inner {
        override fun deleteMeta(key: String) {
            if (key.startsWith(ReferralMetaKeys.PREFIX)) throw RuntimeException("simulated _meta delete failure")
            inner.deleteMeta(key)
        }
    }

    @Test
    fun aFailingMetaWrite_degradesToRamOnly_andTheReferralStillCompletesInSession() {
        if (!x25519Up()) return
        val inner = InMemoryVault()
        seedReferralContact(inner, "alice", "Alice")
        val vault = RefMetaWriteFailingVault(inner)
        val rm = ReferralManager(vault) { null }

        rm.handleControl("alice", RG_OFFER, referralOfferJson("sd1", "Carol"))
        assertEquals(1, rm.pendingOffers().size, "the offer must still be usable in RAM")
        assertTrue(inner.meta.keys.none { isReferralMetaKey(it) }, "precondition: nothing reached the store")

        rm.registerAccepted("sd1", rm.pendingOffers().single(), x25519GenerateKeypair(), rgMint())
        rm.handleControl("alice", RG_ACCEPT, rgAcceptJson("sd1", x25519GenerateKeypair().publicKey))

        val referred = ReferralManager.referredContactIdFor("sd1")
        assertNotNull(inner.getContact(referred), "the referral must still complete in-session (RAM-only degrade)")
        assertEquals(4, inner.inboxes.size, "all four inbox rows must be written")
        assertEquals("1", inner.getMeta(MessageManager.drIntentKey(referred)), "the ratchet marker still lands")
    }

    @Test
    fun aFailingMetaDelete_neverBreaksADecline_andTheTombstoneStillSettlesIt() {
        val inner = InMemoryVault()
        seedReferralContact(inner, "alice", "Alice")
        val vault = RefMetaDeleteFailingVault(inner)
        val rm = ReferralManager(vault) { null }
        rm.handleControl("alice", RG_OFFER, referralOfferJson("sd2", "Carol"))

        rm.declineOffer("sd2")   // dropRecord throws internally — must be swallowed

        assertTrue(rm.pendingOffers().isEmpty(), "the decline must succeed in RAM despite the failing delete")
        rm.handleControl("alice", RG_OFFER, referralOfferJson("sd2", "Carol"))
        assertTrue(rm.pendingOffers().isEmpty(), "the tombstone must keep a re-delivery declined")
        // The offer record itself could NOT be deleted (that is the simulated
        // failure) — but the persisted tombstone keeps the NEXT session settled.
        assertTrue(
            ReferralManager(vault) { null }.pendingOffers().isEmpty(),
            "the next session must not re-present an offer whose introduction was declined",
        )
    }
}

// ---------------------------------------------------------------------------
// Codec degenerates + derivation hygiene.
// ---------------------------------------------------------------------------

class ReferralCodecDegenerateTest {

    @Test
    fun storedAccept_refusesDegenerateRecords() {
        val now = 1_234L
        // Our two minted inboxes sharing one id can never be a valid pairing.
        val sameId = MintedInboxPair(
            MintedInbox(RG_MY_IB, RG_CAP_R, RG_CAP_W, 1L),
            MintedInbox(RG_MY_IB, RG_CAP_S, RG_CAP_X, 1L),
        )
        assertNull(
            decodeStoredAccept(
                encodeStoredAccept(StoredAccept("alice", "C", ByteArray(32), ByteArray(32), sameId, true, 0, now))
            ),
            "a record whose two minted inboxes share one id must not decode",
        )
        // An empty introducer id can name no contact.
        assertNull(
            decodeStoredAccept(
                encodeStoredAccept(StoredAccept("", "C", ByteArray(32), ByteArray(32), rgMint(), true, 0, now))
            ),
            "an empty introducer id must not decode",
        )
        // X25519 keys must be exactly 32 bytes, both of them.
        assertNull(
            decodeStoredAccept(
                encodeStoredAccept(StoredAccept("alice", "C", ByteArray(31), ByteArray(32), rgMint(), true, 0, now))
            ),
            "a truncated private key must not decode",
        )
        assertNull(
            decodeStoredAccept(
                encodeStoredAccept(StoredAccept("alice", "C", ByteArray(32), ByteArray(33), rgMint(), true, 0, now))
            ),
            "an oversized public key must not decode",
        )
        // Flip-check: the same record well-formed decodes.
        assertNotNull(
            decodeStoredAccept(
                encodeStoredAccept(StoredAccept("alice", "C", ByteArray(32), ByteArray(32), rgMint(), true, 0, now))
            ),
        )
    }

    /** The 1C-2 property rests on the two introId derivations being DIFFERENT
     *  domains; pin that they can never collapse into one another, and that a
     *  locally-minted introId is always key-shape-safe (so a local introduction
     *  never degrades to the RAM-only path). */
    @Test
    fun derivationsAreDomainSeparated_andMintedIntroIdsAreKeySafe() {
        assertNotEquals(
            ReferralManager.doneTokenFor("intro-abc"),
            ReferralManager.referredContactIdFor("intro-abc"),
            "the done-token and the referred-contact-id derivations must never coincide (1C-2)",
        )
        assertEquals(24, ReferralManager.doneTokenFor("intro-abc").length, "18 bytes → 24-char base64url")

        val id = ReferralManager.newIntroId()
        assertEquals(22, id.length, "16 random bytes → 22-char base64url")
        assertTrue(isValidIntroId(id), "a locally-minted introId must always pass the key-shape gate")
        assertNotEquals(ReferralManager.newIntroId(), ReferralManager.newIntroId(), "introIds are random")
    }
}

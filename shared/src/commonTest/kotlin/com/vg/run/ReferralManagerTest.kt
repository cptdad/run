package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// ReferralManager protocol tests. The handshake is driven through
// handleControl with constructed bodies + a null transport, so consent/finalize
// logic runs with no relay. The finalize cases derive a real X25519 shared key
// and are bridge-guarded (skipped on the iOS unit-test target).
// ---------------------------------------------------------------------------

/** The two inbox ids [acceptBodyFor] announces on the peer's behalf. */
private val PEER_IB  = "in" + "A".repeat(30)
private val PEER_CIB = "ct" + "B".repeat(30)
/** The two ids the injected [MintedInboxPair] in these tests mints for US. */
private val MY_IB  = "in" + "M".repeat(30)
private val MY_CIB = "ct" + "N".repeat(30)
/** An unrelated victim contact's own inbound inbox id. */
private val VICTIM_IN = "vi" + "C".repeat(30)

/** Build a ref-accept body as the PEER would send it (their pub + inbox offer). */
private fun acceptBodyFor(
    introId: String,
    peerPub: ByteArray,
    ib: String = PEER_IB,
    cib: String = PEER_CIB,
): String {
    val wc = "W".repeat(43)
    val cwc = "X".repeat(43)
    return """{"ii":${jsonEscapeString(introId)},"pk":${jsonEscapeString(encodeBase64(peerPub))},""" +
        """"ib":${jsonEscapeString(ib)},"wc":${jsonEscapeString(wc)},"cib":${jsonEscapeString(cib)},"cwc":${jsonEscapeString(cwc)}}"""
}

class ReferralManagerTest {

    private val noTransport: () -> MessageManager? = { null }

    private fun offerBody(introId: String, peerAlias: String) =
        """{"ii":${jsonEscapeString(introId)},"pa":${jsonEscapeString(peerAlias)}}"""

    @Test
    fun offer_fromKnownContact_isStoredForConsent_andDedup() {
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        val rm = ReferralManager(vault, noTransport)
        // A conforming alias (ContactAliasGenerator.matchesGeneratedFormat)
        // survives sanitization verbatim — no collision, nothing to re-roll.
        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_OFFER, offerBody("intro1", "Running Fox"))
        val offers = rm.pendingOffers()
        assertEquals(1, offers.size)
        assertEquals("intro1", offers[0].introId)
        assertEquals("alice", offers[0].introducerContactId)
        assertEquals("Running Fox", offers[0].peerAlias)
        // Duplicate offer ignored.
        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_OFFER, offerBody("intro1", "Running Fox"))
        assertEquals(1, rm.pendingOffers().size)
    }

    @Test
    fun offer_fromUnknownContact_isIgnored() {
        val vault = InMemoryVault()
        val rm = ReferralManager(vault, noTransport)
        // No "stranger" contact seeded → offer must be dropped (no auto-trust).
        rm.handleControl("stranger", MessageManager.CONTROL_KIND_REFERRAL_OFFER, offerBody("x", "Carol"))
        assertTrue(rm.pendingOffers().isEmpty())
    }

    @Test
    fun offerAlone_neverCreatesAContact_consentRequired() {
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        val rm = ReferralManager(vault, noTransport)
        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_OFFER, offerBody("i", "Carol"))
        // Receiving an accept BEFORE we accepted (no keypair) must not pair.
        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_ACCEPT, acceptBodyFor("i", ByteArray(32)))
        assertEquals(1, vault.getAllContacts().size)  // only the seeded introducer
    }

    @Test
    fun finalize_derivesSharedKey_writesReferredContact_andInboxes() {
        if (!x25519Up()) return
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        val rm = ReferralManager(vault, noTransport)

        // Bob (this device) gets the offer and accepts (inject material, no mint).
        // A conforming alias survives sanitization verbatim.
        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_OFFER, offerBody("i7", "Running Fox"))
        val offer = rm.pendingOffers().single()
        val bob = x25519GenerateKeypair()
        val carol = x25519GenerateKeypair()
        // Snapshot expected BEFORE finalize — finalize wipes bob.privateKey once finalize runs.
        val expected = hkdfSha256(x25519Ecdh(bob.privateKey, carol.publicKey), ByteArray(0), "run-referral-v1|i7".encodeToByteArray(), 32)
        val minted = MintedInboxPair(
            MintedInbox("in" + "M".repeat(30), "R".repeat(43), "w".repeat(43), Long.MAX_VALUE),
            MintedInbox("ct" + "N".repeat(30), "S".repeat(43), "x".repeat(43), Long.MAX_VALUE),
        )
        rm.registerAccepted("i7", offer, bob, minted)

        // Carol's accept arrives, relayed by Alice.
        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_ACCEPT, acceptBodyFor("i7", carol.publicKey))

        val contacts = vault.getAllContacts().filter { it.contactId != "alice" }
        assertEquals(1, contacts.size)
        val c = contacts.single()
        // Shared secret == HKDF(ECDH(bobPriv, carolPub)) — same Carol derives.
        // The HKDF info is transcript-bound with the introId.
        // (expected snapshotted above, before finalize wiped bob.privateKey.)
        assertEquals(expected.toList(), c.sharedSecret.toList())
        assertEquals(VaultSeedDefaults.TRUST_REFERRED_CONFIRMED, c.trustLevel)  // usable immediately (transitive trust)
        assertEquals("alice", c.vouchedByContactId)
        assertEquals("Running Fox", c.alias)
        // Four inbox records wired (inbound = mine, outbound = peer's).
        assertNotNull(vault.getInboxIdForContact(c.contactId, "inbound"))
        assertNotNull(vault.getInboxIdForContact(c.contactId, "outbound"))
        assertNotNull(vault.getInboxIdForContact(c.contactId, "inbound-ctl"))
        assertNotNull(vault.getInboxIdForContact(c.contactId, "outbound-ctl"))
        // a referred contact MUST be ratchet-capable, exactly
        // like a QR-paired one — else its text channel never gets forward secrecy.
        assertEquals("1", vault.getMeta(MessageManager.drIntentKey(c.contactId)))
    }

    /** a referral finalize whose deterministic contactId collides with an
     *  EXISTING contact must NOT overwrite it (insertContact is INSERT-OR-REPLACE, so a
     *  malicious introducer could otherwise hijack a real contact). */
    @Test
    fun finalize_doesNotOverwrite_existingContactAtDeterministicId() {
        if (!x25519Up()) return
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        val rm = ReferralManager(vault, noTransport)

        // A real "victim" contact already sits at the id this introId deterministically maps to.
        val victimId = ReferralManager.referredContactIdFor("i7")
        val victimSecret = generateSecureRandom(32)
        vault.insertContact(
            ContactRecord(
                contactId = victimId, sharedSecret = victimSecret,
                trustLevel = 99, alias = "Victim", aliasLastRotated = 0L,
            )
        )

        // Drive a full finalize for "i7" (would upsert onto victimId without the guard).
        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_OFFER, offerBody("i7", "Carol"))
        val offer = rm.pendingOffers().single()
        val bob = x25519GenerateKeypair()
        val carol = x25519GenerateKeypair()
        val minted = MintedInboxPair(
            MintedInbox("in" + "M".repeat(30), "R".repeat(43), "w".repeat(43), Long.MAX_VALUE),
            MintedInbox("ct" + "N".repeat(30), "S".repeat(43), "x".repeat(43), Long.MAX_VALUE),
        )
        rm.registerAccepted("i7", offer, bob, minted)
        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_ACCEPT, acceptBodyFor("i7", carol.publicKey))

        // The victim contact is UNTOUCHED — secret, trust, and alias unchanged — and no
        // colliding contact was minted (only alice + the victim remain).
        val v = vault.getContact(victimId)
        assertNotNull(v)
        assertEquals(victimSecret.toList(), v.sharedSecret.toList(), "finalize must NOT overwrite an existing contact")
        assertEquals("Victim", v.alias)
        assertEquals(99, v.trustLevel)
        assertEquals(2, vault.getAllContacts().size, "referral must not add a colliding contact")
    }

    // --- a referral finalize must never steal an inbox row ---------------
    //
    // `inbox_ids` is keyed by inboxId with replace-on-conflict, and finalize writes
    // FOUR rows — two ids the peer supplies (relayed verbatim through a possibly
    // hostile introducer) and two we minted. The pre-existing guards only compare
    // the peer's ids against THIS referral's own mint; neither looks at the vault.

    /** Drives a full accept + peer-accept for [introId] with the standard injected mint. */
    private fun driveFinalize(
        rm: ReferralManager, introId: String, carolPub: ByteArray,
        peerIb: String = PEER_IB, peerCib: String = PEER_CIB,
    ) {
        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_OFFER, offerBody(introId, "Carol"))
        val offer = rm.pendingOffers().single()
        rm.registerAccepted(introId, offer, x25519GenerateKeypair(), MintedInboxPair(
            MintedInbox(MY_IB, "R".repeat(43), "w".repeat(43), Long.MAX_VALUE),
            MintedInbox(MY_CIB, "S".repeat(43), "x".repeat(43), Long.MAX_VALUE),
        ))
        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_ACCEPT,
            acceptBodyFor(introId, carolPub, ib = peerIb, cib = peerCib))
    }

    @Test
    fun finalize_doesNotStealAnotherContactsOutboundInbox() {
        if (!x25519Up()) return
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        // A real, fully-paired contact we already send to, at the id the "peer"
        // will announce (the introducer sees it in the relayed accept body).
        seedReferralContact(vault, "victim", "Victim")
        vault.insertInboxId(InboxIdRecord(VICTIM_IN, "victim", 1L, Long.MAX_VALUE, "inbound", "U".repeat(43)))
        vault.insertInboxId(InboxIdRecord(PEER_IB, "victim", 1L, Long.MAX_VALUE, "outbound", "V".repeat(43)))
        assertTrue(contactFullyPaired(vault, "victim"), "precondition: the victim starts sendable")

        val rm = ReferralManager(vault, noTransport)
        driveFinalize(rm, "h2a", x25519GenerateKeypair().publicKey)

        // The victim's outbound route is untouched — same owner, direction and cap.
        val row = assertNotNull(vault.getInboxId(PEER_IB))
        assertEquals("victim", row.contactId, "the victim's row must not be reassigned")
        assertEquals("outbound", row.direction)
        assertEquals("V".repeat(43), row.cap, "the victim's write cap must not be replaced")
        assertTrue(contactFullyPaired(vault, "victim"), "the victim must stay sendable")
        // …and no referred contact was created (only alice + victim remain).
        assertEquals(2, vault.getAllContacts().size, "a refused finalize must create no contact")
        assertEquals(2, vault.inboxes.size, "a refused finalize must write no inbox rows")
    }

    @Test
    fun finalize_doesNotOverwriteOurOwnInboundReadCapRow() {
        if (!x25519Up()) return
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        // OUR inbound inbox for alice — it holds our READ capability (the inbox
        // OWNER capability). A peer naming it would turn it into an outbound row
        // carrying the peer's WRITE cap, destroying our read cap for alice.
        vault.insertInboxId(InboxIdRecord(PEER_IB, "alice", 1L, Long.MAX_VALUE, "inbound", "A".repeat(43)))

        val rm = ReferralManager(vault, noTransport)
        driveFinalize(rm, "h2b", x25519GenerateKeypair().publicKey)

        val row = assertNotNull(vault.getInboxId(PEER_IB))
        assertEquals("alice", row.contactId)
        assertEquals("inbound", row.direction, "our own inbound row must not be flipped to outbound")
        assertEquals("A".repeat(43), row.cap, "our READ capability must survive")
        assertEquals(1, vault.getAllContacts().size, "a refused finalize must create no contact")
    }

    @Test
    fun finalize_rejects_whenOurOwnMintCollidesWithAnExistingRow() {
        if (!x25519Up()) return
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        seedReferralContact(vault, "victim", "Victim")
        // The mint we inject collides with a row another contact already owns —
        // vanishingly unlikely from a healthy relay, but the write would be just as
        // destructive, so the gate covers OUR ids too, not only the peer's.
        vault.insertInboxId(InboxIdRecord(MY_IB, "victim", 1L, Long.MAX_VALUE, "inbound", "V".repeat(43)))

        val rm = ReferralManager(vault, noTransport)
        driveFinalize(rm, "h2c", x25519GenerateKeypair().publicKey)

        val row = assertNotNull(vault.getInboxId(MY_IB))
        assertEquals("victim", row.contactId)
        assertEquals("inbound", row.direction)
        assertEquals(2, vault.getAllContacts().size, "a refused finalize must create no contact")
        assertEquals(1, vault.inboxes.size, "a refused finalize must write no inbox rows")
    }

    @Test
    fun finalize_rejection_isTerminal_andLeavesNoStrandedOffer() {
        // The conflict is deterministic in the peer's ids, so a retry would loop.
        // The handshake settles exactly like the already-exists branch: offer
        // consumed, intro marked completed, re-delivery dropped.
        if (!x25519Up()) return
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        seedReferralContact(vault, "victim", "Victim")
        vault.insertInboxId(InboxIdRecord(PEER_IB, "victim", 1L, Long.MAX_VALUE, "outbound", "V".repeat(43)))

        val rm = ReferralManager(vault, noTransport)
        val carol = x25519GenerateKeypair()
        driveFinalize(rm, "h2d", carol.publicKey)
        assertTrue(rm.pendingOffers().isEmpty(), "the offer must not be left pending")

        // A re-delivered offer for the same introId must not resurrect the prompt…
        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_OFFER, offerBody("h2d", "Carol"))
        assertTrue(rm.pendingOffers().isEmpty(), "a rejected referral must stay rejected")
        // …and a re-delivered peer accept must not re-attempt the write.
        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_ACCEPT, acceptBodyFor("h2d", carol.publicKey))
        assertEquals(2, vault.getAllContacts().size)
        assertEquals(1, vault.inboxes.size)
    }

    @Test
    fun reDeliveredOffer_afterFinalize_isDropped_noAlertResurrected() {
        if (!x25519Up()) return
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        val rm = ReferralManager(vault, noTransport)

        // Full finalize (as above), leaving a referred contact and no offers.
        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_OFFER, offerBody("i7", "Carol"))
        val offer = rm.pendingOffers().single()
        val bob = x25519GenerateKeypair()
        val carol = x25519GenerateKeypair()
        rm.registerAccepted("i7", offer, bob, MintedInboxPair(
            MintedInbox("in" + "M".repeat(30), "R".repeat(43), "w".repeat(43), Long.MAX_VALUE),
            MintedInbox("ct" + "N".repeat(30), "S".repeat(43), "x".repeat(43), Long.MAX_VALUE),
        ))
        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_ACCEPT, acceptBodyFor("i7", carol.publicKey))
        assertEquals(1, vault.getAllContacts().filter { it.contactId != "alice" }.size)
        assertTrue(rm.pendingOffers().isEmpty())

        // The introducer's inbox still holds the offer blob; a later control poll
        // re-delivers it. It must be DROPPED — not re-create the offer (which on
        // iOS re-raises the consent alert and blocks the settings sheet).
        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_OFFER, offerBody("i7", "Carol"))
        assertTrue(rm.pendingOffers().isEmpty(), "re-delivered offer after finalize must not resurrect the consent prompt")
    }

    @Test
    fun reDeliveredOffer_afterDecline_isDropped() {
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        val rm = ReferralManager(vault, noTransport)

        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_OFFER, offerBody("d1", "Carol"))
        assertEquals(1, rm.pendingOffers().size)
        rm.declineOffer("d1")
        assertTrue(rm.pendingOffers().isEmpty())

        // A re-delivery after an explicit decline must stay declined.
        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_OFFER, offerBody("d1", "Carol"))
        assertTrue(rm.pendingOffers().isEmpty(), "re-delivered offer after decline must not reappear")
    }

    @Test
    fun finalize_malformedPeerCap_isRejected_noReferredContact() {
        // a NON-EMPTY but malformed peer inbox/cap must be
        // shape-rejected (not stored) — else the TRUST_REFERRED_CONFIRMED contact
        // is created permanently un-sendable with no re-pair UX.
        if (!x25519Up()) return
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        val rm = ReferralManager(vault, noTransport)
        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_OFFER, offerBody("i8", "Carol"))
        val offer = rm.pendingOffers().single()
        val bob = x25519GenerateKeypair()
        val carol = x25519GenerateKeypair()
        val minted = MintedInboxPair(
            MintedInbox("in" + "M".repeat(30), "R".repeat(43), "w".repeat(43), Long.MAX_VALUE),
            MintedInbox("ct" + "N".repeat(30), "S".repeat(43), "x".repeat(43), Long.MAX_VALUE),
        )
        rm.registerAccepted("i8", offer, bob, minted)
        // Non-empty but malformed write-cap ("tooshort" fails the capability regex).
        val badBody = """{"ii":"i8","pk":${jsonEscapeString(encodeBase64(carol.publicKey))},""" +
            """"ib":${jsonEscapeString("in" + "A".repeat(30))},"wc":"tooshort",""" +
            """"cib":${jsonEscapeString("ct" + "B".repeat(30))},"cwc":${jsonEscapeString("X".repeat(43))}}"""
        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_ACCEPT, badBody)
        // Dropped: no referred contact created (only the seeded introducer remains).
        assertEquals(1, vault.getAllContacts().size)
    }

    @Test
    fun peerAccept_beforeOurConsent_isStashed_thenFinalizesOnAccept() {
        if (!x25519Up()) return
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        val rm = ReferralManager(vault, noTransport)

        // A conforming alias survives sanitization verbatim.
        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_OFFER, offerBody("i9", "Running Fox"))
        val offer = rm.pendingOffers().single()
        val bob = x25519GenerateKeypair()
        val carol = x25519GenerateKeypair()
        // Snapshot expected BEFORE finalize — finalize wipes bob.privateKey once finalize runs.
        val expected = hkdfSha256(x25519Ecdh(bob.privateKey, carol.publicKey), ByteArray(0), "run-referral-v1|i9".encodeToByteArray(), 32)

        // Carol's accept (relayed by Alice) arrives BEFORE we accept — it must
        // be stashed, not dropped, and must NOT finalize anything yet.
        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_ACCEPT, acceptBodyFor("i9", carol.publicKey))
        assertEquals(1, vault.getAllContacts().size)  // only Alice — nothing finalized

        // Now we accept (inject material): the stashed accept applies → finalize,
        // with no re-send needed. This is the ordering fix that lets the two
        // introducees accept serially without losing the early accepter's pair.
        rm.registerAccepted("i9", offer, bob, MintedInboxPair(
            MintedInbox("in" + "M".repeat(30), "R".repeat(43), "w".repeat(43), Long.MAX_VALUE),
            MintedInbox("ct" + "N".repeat(30), "S".repeat(43), "x".repeat(43), Long.MAX_VALUE),
        ))

        val contacts = vault.getAllContacts().filter { it.contactId != "alice" }
        assertEquals(1, contacts.size)
        val c = contacts.single()
        // HKDF info transcript-bound with the introId ("i9" here).
        // (expected snapshotted above, before finalize wiped bob.privateKey.)
        assertEquals(expected.toList(), c.sharedSecret.toList())
        assertEquals(VaultSeedDefaults.TRUST_REFERRED_CONFIRMED, c.trustLevel)  // usable immediately (transitive trust)
        assertEquals("Running Fox", c.alias)
        assertNotNull(vault.getInboxIdForContact(c.contactId, "outbound"))
    }

    @Test
    fun accept_notFromMyIntroducer_isIgnored() {
        if (!x25519Up()) return
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        seedReferralContact(vault, "mallory", "Mallory")
        val rm = ReferralManager(vault, noTransport)
        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_OFFER, offerBody("i", "Carol"))
        val offer = rm.pendingOffers().single()
        rm.registerAccepted("i", offer, x25519GenerateKeypair(),
            MintedInboxPair(
                MintedInbox("in" + "M".repeat(30), "R".repeat(43), "w".repeat(43), Long.MAX_VALUE),
                MintedInbox("ct" + "N".repeat(30), "S".repeat(43), "x".repeat(43), Long.MAX_VALUE),
            ))
        // An accept on the same introId but from MALLORY (not our introducer) → ignored.
        rm.handleControl("mallory", MessageManager.CONTROL_KIND_REFERRAL_ACCEPT, acceptBodyFor("i", x25519GenerateKeypair().publicKey))
        assertEquals(2, vault.getAllContacts().size)  // only the two seeded contacts
    }

    /** An accepted-but-never-finalized handshake leaves its
     *  ephemeral X25519 private key resident in `pending` with no TTL. scrubInMemory (the
     *  lock/panic-wipe path) must OVERWRITE those bytes (fill(0)), not just drop the map. */
    @Test
    fun scrubInMemory_zeroesAcceptedButUnfinalizedEphemeralPrivateKey() {
        if (!x25519Up()) return
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        val rm = ReferralManager(vault, noTransport)
        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_OFFER, offerBody("iz", "Carol"))
        val offer = rm.pendingOffers().single()
        val bob = x25519GenerateKeypair()
        val minted = MintedInboxPair(
            MintedInbox("in" + "M".repeat(30), "R".repeat(43), "w".repeat(43), Long.MAX_VALUE),
            MintedInbox("ct" + "N".repeat(30), "S".repeat(43), "x".repeat(43), Long.MAX_VALUE),
        )
        // Accept; the peer NEVER accepts → the Pending (with a live private key) lingers.
        rm.registerAccepted("iz", offer, bob, minted)
        assertTrue(bob.privateKey.any { it != 0.toByte() }, "precondition: fresh key has nonzero bytes")

        rm.scrubInMemory()

        assertTrue(bob.privateKey.all { it == 0.toByte() }, "abandoned ephemeral private key must be zeroized on scrub")
        assertTrue(rm.pendingOffers().isEmpty(), "scrub also clears parked offers")
    }

    /** Sibling case: the SUCCESSFUL finalize path already wipes the ephemeral key once
     *  HKDF has consumed the ECDH output — assert that "zeroed after use" invariant directly. */
    @Test
    fun finalize_zeroesEphemeralPrivateKey_afterDerivingSharedSecret() {
        if (!x25519Up()) return
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        val rm = ReferralManager(vault, noTransport)
        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_OFFER, offerBody("iw", "Carol"))
        val offer = rm.pendingOffers().single()
        val bob = x25519GenerateKeypair()
        val carol = x25519GenerateKeypair()
        val minted = MintedInboxPair(
            MintedInbox("in" + "M".repeat(30), "R".repeat(43), "w".repeat(43), Long.MAX_VALUE),
            MintedInbox("ct" + "N".repeat(30), "S".repeat(43), "x".repeat(43), Long.MAX_VALUE),
        )
        rm.registerAccepted("iw", offer, bob, minted)
        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_ACCEPT, acceptBodyFor("iw", carol.publicKey))

        assertTrue(bob.privateKey.all { it == 0.toByte() }, "ephemeral private key must be zeroized after finalize")
    }

    /** a SAME-KEY overwrite in capInsert (two concurrent
     *  acceptOffer(introId) racing → registerAccepted twice for one introId) replaces the
     *  first racer's Pending in place. That dropped Pending's live ephemeral X25519 private
     *  key must be OVERWRITTEN (fill(0)) before the reference is discarded — otherwise it
     *  becomes unreachable heap residue scrubInMemory() can never find. */
    @Test
    fun capInsertSameKeyOverwrite_zeroesReplacedEphemeralPrivateKey() {
        if (!x25519Up()) return
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        val rm = ReferralManager(vault, noTransport)
        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_OFFER, offerBody("ir", "Carol"))
        val offer = rm.pendingOffers().single()
        val minted = MintedInboxPair(
            MintedInbox("in" + "M".repeat(30), "R".repeat(43), "w".repeat(43), Long.MAX_VALUE),
            MintedInbox("ct" + "N".repeat(30), "S".repeat(43), "x".repeat(43), Long.MAX_VALUE),
        )
        val first = x25519GenerateKeypair()
        val second = x25519GenerateKeypair()
        // First accept parks `first`'s keypair in pending["ir"] (peer never accepts → it lingers).
        rm.registerAccepted("ir", offer, first, minted)
        assertTrue(first.privateKey.any { it != 0.toByte() }, "precondition: first key has nonzero bytes")

        // A racing second accept for the SAME introId overwrites pending["ir"]: capInsert
        // replaces the Pending in place, dropping `first`. Its private key must be wiped first.
        rm.registerAccepted("ir", offer, second, minted)
        assertTrue(first.privateKey.all { it == 0.toByte() },
            "replaced entry's ephemeral private key must be zeroized on same-key overwrite")
        // The replacing key stays live (it is the current handshake) until its own teardown.
        assertTrue(second.privateKey.any { it != 0.toByte() }, "the replacing key is still live")
        rm.scrubInMemory()
        assertTrue(second.privateKey.all { it == 0.toByte() }, "scrub then zeroes the surviving key")
    }

    /** finalizeFromPeerAccept must zero the DERIVED contact
     *  message key (`shared`) after it is persisted — it is the new contact's live AEAD
     *  key and, once SQLCipher has its own copy, pure RAM residue. A spy vault captures
     *  the exact ByteArray handed to insertContact (== the derived `shared`) and asserts
     *  it is fill(0)'d once finalize returns, while the persisted copy stays intact. */
    @Test
    fun finalize_zeroesDerivedSharedMessageKey_afterPersist() {
        if (!x25519Up()) return
        val vault = CapturingVault()
        seedReferralContact(vault, "alice", "Alice")
        val rm = ReferralManager(vault, noTransport)
        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_OFFER, offerBody("is", "Carol"))
        val offer = rm.pendingOffers().single()
        val bob = x25519GenerateKeypair()
        val carol = x25519GenerateKeypair()
        val expected = hkdfSha256(x25519Ecdh(bob.privateKey, carol.publicKey), ByteArray(0), "run-referral-v1|is".encodeToByteArray(), 32)
        val minted = MintedInboxPair(
            MintedInbox("in" + "M".repeat(30), "R".repeat(43), "w".repeat(43), Long.MAX_VALUE),
            MintedInbox("ct" + "N".repeat(30), "S".repeat(43), "x".repeat(43), Long.MAX_VALUE),
        )
        rm.registerAccepted("is", offer, bob, minted)
        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_ACCEPT, acceptBodyFor("is", carol.publicKey))

        // The contact persisted with the CORRECT key (the fake's defensive copy survived)…
        val c = vault.getAllContacts().single { it.contactId != "alice" }
        assertEquals(expected.toList(), c.sharedSecret.toList())
        // …but the derived `shared` array handed to insertContact is zeroed in RAM.
        val captured = assertNotNull(vault.capturedSharedSecret, "finalize must have inserted the referred contact")
        assertTrue(captured.all { it == 0.toByte() },
            "derived contact message key (shared secret) must be zeroized after persist")
    }

}

/** Spy vault recording the exact sharedSecret ByteArray reference handed to
 *  insertContact — the LIVE derived `shared`, captured BEFORE the base fake copies it
 *  for storage — so [ReferralManagerTest.finalize_zeroesDerivedSharedMessageKey_afterPersist]
 *  can assert ReferralManager fill(0)'d that key after persisting. */
private class CapturingVault : InMemoryVault() {
    var capturedSharedSecret: ByteArray? = null
    override fun insertContact(contact: ContactRecord): Long {
        capturedSharedSecret = contact.sharedSecret   // live derived `shared`, pre-copy
        return super.insertContact(contact)           // super stores a defensive copy
    }
}

/** The referred contactId is deterministic from the introId so a
 *  re-driven finalize upserts idempotently instead of minting a duplicate/orphan. */
class ReferredContactIdTest {
    @Test
    fun deterministicFromIntroId_distinctAcrossIntroIds_wellFormed() {
        assertEquals(
            ReferralManager.referredContactIdFor("intro-abc"),
            ReferralManager.referredContactIdFor("intro-abc"),
            "same introId must map to the same contactId (idempotent retry)",
        )
        assertTrue(
            ReferralManager.referredContactIdFor("intro-abc") != ReferralManager.referredContactIdFor("intro-xyz"),
            "distinct introIds must map to distinct contactIds",
        )
        val id = ReferralManager.referredContactIdFor("intro-abc")
        assertEquals(24, id.length)   // 18 bytes → base64url, same shape as the random id
        assertTrue(id.all { it.isLetterOrDigit() || it == '-' || it == '_' })
    }
}

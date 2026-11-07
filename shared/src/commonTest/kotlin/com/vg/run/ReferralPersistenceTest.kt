package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// Referral handshake PERSISTENCE (referral.md "Handshake persistence &
// ephemerality"). Every case here models the real failure: a manager is torn
// down (scrubInMemory, exactly what ordinary backgrounding and process death do
// on both platforms) and a SECOND manager is constructed over the SAME vault
// double — which is what `createSessionManagers` does on the next unlock.
//
// The property under test is that the handshake survives that, because the
// relay's control drain is destructive and a lost record is permanent: the peer
// commits a TRUST_REFERRED_CONFIRMED contact whose outbound inboxes route at
// inboxes nobody polls.
// ---------------------------------------------------------------------------

private fun seed(vault: InMemoryVault, id: String, alias: String) {
    vault.insertContact(
        ContactRecord(
            contactId = id, sharedSecret = generateSecureRandom(32),
            trustLevel = 0, alias = alias, aliasLastRotated = 0L,
        )
    )
}

/** 32-char inbox ids / 43-char caps — the shapes the validators demand. */
private val P_IB = "pi" + "A".repeat(30)
private val P_CIB = "pc" + "B".repeat(30)
private val M_IB = "mi" + "M".repeat(30)
private val M_CIB = "mc" + "N".repeat(30)
private const val CAP43 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
private const val CAP43B = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
private const val CAP43C = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
private const val CAP43D = "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"

private fun myMint() = MintedInboxPair(
    MintedInbox(M_IB, CAP43, CAP43B, Long.MAX_VALUE),
    MintedInbox(M_CIB, CAP43C, CAP43D, Long.MAX_VALUE),
)

private fun offerJson(introId: String, peerAlias: String) =
    """{"ii":${jsonEscapeString(introId)},"pa":${jsonEscapeString(peerAlias)}}"""

private fun acceptJson(introId: String, peerPub: ByteArray) =
    """{"ii":${jsonEscapeString(introId)},"pk":${jsonEscapeString(encodeBase64(peerPub))},""" +
        """"ib":${jsonEscapeString(P_IB)},"wc":${jsonEscapeString(CAP43B)},""" +
        """"cib":${jsonEscapeString(P_CIB)},"cwc":${jsonEscapeString(CAP43D)}}"""

private fun refKeys(vault: InMemoryVault, prefix: String) =
    vault.meta.keys.filter { it.startsWith(prefix) }

class ReferralPersistenceTest {

    private val noTransport: () -> MessageManager? = { null }

    // -- (a) restart ACROSS an accept: the black-hole case ---------------------

    @Test
    fun restartAfterAccept_finalizesOnTheNewManager_andClearsTheRecord() {
        if (!x25519Up()) return
        val vault = InMemoryVault()
        seed(vault, "alice", "Alice")

        val bob = x25519GenerateKeypair()
        val carol = x25519GenerateKeypair()
        // Snapshot before anything can wipe bob's private key.
        val expected = hkdfSha256(
            x25519Ecdh(bob.privateKey, carol.publicKey), ByteArray(0),
            "run-referral-v1|rp1".encodeToByteArray(), 32,
        )

        // SESSION 1 — offer, accept (sent), then the process dies.
        val rm1 = ReferralManager(vault, noTransport)
        // A conforming alias survives sanitization verbatim.
        rm1.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_OFFER, offerJson("rp1", "Running Fox"))
        rm1.registerAccepted("rp1", rm1.pendingOffers().single(), bob, myMint())
        assertEquals(1, refKeys(vault, ReferralMetaKeys.ACCEPT_PREFIX).size, "the accept must be mirrored to the vault")
        rm1.scrubInMemory()   // == ordinary backgrounding / process death

        // SESSION 2 — a fresh manager over the same vault gets Carol's accept.
        val rm2 = ReferralManager(vault, noTransport)
        rm2.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_ACCEPT, acceptJson("rp1", carol.publicKey))

        val c = vault.getAllContacts().single { it.contactId != "alice" }
        assertEquals(expected.toList(), c.sharedSecret.toList(), "the rehydrated keypair must derive the SAME shared key")
        assertEquals(VaultSeedDefaults.TRUST_REFERRED_CONFIRMED, c.trustLevel)
        assertEquals("Running Fox", c.alias)
        assertEquals("alice", c.vouchedByContactId)
        assertNotNull(vault.getInboxIdForContact(c.contactId, "outbound"))
        assertNotNull(vault.getInboxIdForContact(c.contactId, MessageManager.DIR_INBOUND_CTL))
        // The record dies inside the finalize transaction — no ephemeral private
        // key and no inbox read-cap left behind in `_meta`.
        assertTrue(refKeys(vault, ReferralMetaKeys.ACCEPT_PREFIX).isEmpty(), "the accept record must be gone after finalize")
        assertTrue(refKeys(vault, ReferralMetaKeys.OFFER_PREFIX).isEmpty())
        assertTrue(refKeys(vault, ReferralMetaKeys.STASH_PREFIX).isEmpty())
    }

    /** Without persistence this is the exact log line the defect produced. */
    @Test
    fun restartAfterAccept_doesNotHitTheUnknownIntroIdDrop() {
        if (!x25519Up()) return
        val vault = InMemoryVault()
        seed(vault, "alice", "Alice")
        val rm1 = ReferralManager(vault, noTransport)
        rm1.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_OFFER, offerJson("rp2", "Carol"))
        rm1.registerAccepted("rp2", rm1.pendingOffers().single(), x25519GenerateKeypair(), myMint())
        rm1.scrubInMemory()

        val rm2 = ReferralManager(vault, noTransport)
        rm2.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_ACCEPT,
            acceptJson("rp2", x25519GenerateKeypair().publicKey))
        assertEquals(2, vault.getAllContacts().size, "the referred contact must materialise after the restart")
    }

    // -- (b) restart BEFORE consent -------------------------------------------

    @Test
    fun restartBeforeConsent_offerSurvives_andCanStillBeApproved() {
        if (!x25519Up()) return
        val vault = InMemoryVault()
        seed(vault, "alice", "Alice")

        val rm1 = ReferralManager(vault, noTransport)
        // A conforming alias survives sanitization verbatim.
        rm1.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_OFFER, offerJson("rp3", "Running Fox"))
        assertEquals(1, rm1.pendingOffers().size)
        rm1.scrubInMemory()

        val rm2 = ReferralManager(vault, noTransport)
        val offer = assertNotNull(
            rm2.pendingOffers().singleOrNull(),
            "a backgrounded-before-consent offer must survive the relaunch",
        )
        assertEquals("rp3", offer.introId)
        assertEquals("alice", offer.introducerContactId)
        assertEquals("Alice", offer.introducerAlias)
        assertEquals("Running Fox", offer.peerAlias)

        // …and approving it on the SECOND manager still completes the handshake.
        val carol = x25519GenerateKeypair()
        rm2.registerAccepted("rp3", offer, x25519GenerateKeypair(), myMint())
        rm2.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_ACCEPT, acceptJson("rp3", carol.publicKey))
        assertEquals(2, vault.getAllContacts().size)
        assertTrue(refKeys(vault, ReferralMetaKeys.OFFER_PREFIX).isEmpty(), "a consumed offer leaves no record")
    }

    /** A peer accept that landed before our consent must survive the relaunch too. */
    @Test
    fun restartWithStashedPeerAccept_appliesOnTheNextManagersAccept() {
        if (!x25519Up()) return
        val vault = InMemoryVault()
        seed(vault, "alice", "Alice")
        val carol = x25519GenerateKeypair()

        val rm1 = ReferralManager(vault, noTransport)
        rm1.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_OFFER, offerJson("rp4", "Carol"))
        rm1.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_ACCEPT, acceptJson("rp4", carol.publicKey))
        assertEquals(1, vault.getAllContacts().size, "an early peer accept must not pair without consent")
        assertEquals(1, refKeys(vault, ReferralMetaKeys.STASH_PREFIX).size, "the stash must be mirrored")
        rm1.scrubInMemory()

        val rm2 = ReferralManager(vault, noTransport)
        rm2.registerAccepted("rp4", rm2.pendingOffers().single(), x25519GenerateKeypair(), myMint())
        assertEquals(2, vault.getAllContacts().size, "the rehydrated stash must finalize on accept")
        assertTrue(refKeys(vault, ReferralMetaKeys.STASH_PREFIX).isEmpty())
    }

    /** completedIntros persists, so a re-delivered offer cannot re-raise consent. */
    @Test
    fun restartAfterDecline_reDeliveredOfferStaysDeclined() {
        val vault = InMemoryVault()
        seed(vault, "alice", "Alice")
        val rm1 = ReferralManager(vault, noTransport)
        rm1.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_OFFER, offerJson("rp5", "Carol"))
        rm1.declineOffer("rp5")
        assertTrue(refKeys(vault, ReferralMetaKeys.OFFER_PREFIX).isEmpty(), "a declined offer leaves no record")
        rm1.scrubInMemory()

        val rm2 = ReferralManager(vault, noTransport)
        assertTrue(rm2.pendingOffers().isEmpty(), "a declined offer must not come back at the next unlock")
        rm2.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_OFFER, offerJson("rp5", "Carol"))
        assertTrue(rm2.pendingOffers().isEmpty(), "the persisted tombstone must drop the re-delivery")
    }

    @Test
    fun restartAfterFinalize_reDeliveredOfferDoesNotResurrectTheConsentPrompt() {
        if (!x25519Up()) return
        val vault = InMemoryVault()
        seed(vault, "alice", "Alice")
        val rm1 = ReferralManager(vault, noTransport)
        rm1.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_OFFER, offerJson("rp6", "Carol"))
        rm1.registerAccepted("rp6", rm1.pendingOffers().single(), x25519GenerateKeypair(), myMint())
        rm1.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_ACCEPT,
            acceptJson("rp6", x25519GenerateKeypair().publicKey))
        assertEquals(2, vault.getAllContacts().size)
        rm1.scrubInMemory()

        val rm2 = ReferralManager(vault, noTransport)
        rm2.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_OFFER, offerJson("rp6", "Carol"))
        assertTrue(rm2.pendingOffers().isEmpty(), "a finalized intro must stay settled across a relaunch")
    }

    // -- (e) TTL + malformed records ------------------------------------------

    @Test
    fun expiredRecords_areGarbageCollectedAtRehydration() {
        val vault = InMemoryVault()
        seed(vault, "alice", "Alice")
        val old = currentTimeMillis() - REFERRAL_RECORD_TTL_MS - 60_000L
        vault.putMeta(
            ReferralMetaKeys.ACCEPT_PREFIX + "stale",
            encodeStoredAccept(
                StoredAccept("alice", "Carol", ByteArray(32) { 7 }, ByteArray(32) { 9 }, myMint(), true, 0, old)
            ),
        )
        vault.putMeta(
            ReferralMetaKeys.OFFER_PREFIX + "stale2",
            encodeStoredOffer(StoredOffer("alice", "Alice", "Carol", old)),
        )
        vault.putMeta(
            ReferralMetaKeys.SESSION_PREFIX + "stale3",
            encodeStoredSession(StoredSession("b", "c", emptySet(), old)),
        )
        vault.putMeta(
            ReferralMetaKeys.STASH_PREFIX + "stale4",
            encodeStoredStash(StoredStash("alice", "{}", old)),
        )
        vault.putMeta(
            ReferralMetaKeys.REDRIVE_PREFIX + "stale5:c",
            encodeStoredRedrive(StoredRedrive("stale5", "c", "b", "{}", 0, old)),
        )

        val rm = ReferralManager(vault, noTransport)
        assertTrue(rm.pendingOffers().isEmpty(), "an expired offer must not be presented")
        assertTrue(
            vault.meta.keys.none { isReferralMetaKey(it) },
            "every record past STASHED_ACCEPT_TTL_MS must be GC'd on load, found: ${vault.meta.keys}",
        )
    }

    @Test
    fun malformedRecords_neverThrowOutOfConstruction_andAreGarbageCollected() {
        val vault = InMemoryVault()
        seed(vault, "alice", "Alice")
        vault.putMeta(ReferralMetaKeys.ACCEPT_PREFIX + "bad1", "{not json at all")
        vault.putMeta(ReferralMetaKeys.OFFER_PREFIX + "bad2", "")
        vault.putMeta(ReferralMetaKeys.SESSION_PREFIX + "bad3", """{"a":"x"}""")
        vault.putMeta(ReferralMetaKeys.STASH_PREFIX + "bad4", """{"fr":"alice"}""")
        vault.putMeta(ReferralMetaKeys.REDRIVE_PREFIX + "bad5", """{"ii":"bad5"}""")
        // A truncated accept: valid JSON, but the minted caps fail shape validation,
        // so it can never be written into `inbox_ids` and must not be loaded.
        vault.putMeta(
            ReferralMetaKeys.ACCEPT_PREFIX + "bad6",
            encodeStoredAccept(
                StoredAccept(
                    "alice", "Carol", ByteArray(32), ByteArray(32),
                    MintedInboxPair(
                        MintedInbox(M_IB, "short", CAP43B, 0L),
                        MintedInbox(M_CIB, CAP43C, CAP43D, 0L),
                    ),
                    true, 0, currentTimeMillis(),
                )
            ),
        )

        val rm = ReferralManager(vault, noTransport)   // must not throw
        assertTrue(rm.pendingOffers().isEmpty())
        assertTrue(
            vault.meta.keys.none { isReferralMetaKey(it) },
            "unreadable records must be GC'd, found: ${vault.meta.keys}",
        )
        // …and the manager is still fully usable afterwards.
        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_OFFER, offerJson("ok1", "Carol"))
        assertEquals(1, rm.pendingOffers().size)
    }

    // A READ that throws at rehydrate is ambiguous, not absent: deleting the row
    // would destroy (for `ref_a:`) the ephemeral private key and our minted read
    // caps, orphaning the minted inboxes on the relay. The row must survive and the
    // next construction must install it.
    @Test
    fun aTransientMetaReadFailure_atRehydrate_keepsTheRecord_andTheNextConstructionInstallsIt() {
        var failReads = false
        val vault = object : InMemoryVault() {
            override fun getMeta(key: String): String? {
                if (failReads && (key.startsWith(ReferralMetaKeys.ACCEPT_PREFIX) ||
                        key.startsWith(ReferralMetaKeys.OFFER_PREFIX))
                ) throw RuntimeException("transient")
                return super.getMeta(key)
            }
        }
        seed(vault, "alice", "Alice")
        val acceptKey = ReferralMetaKeys.ACCEPT_PREFIX + "live1"
        val acceptValue = encodeStoredAccept(
            StoredAccept("alice", "Carol", ByteArray(32) { 7 }, ByteArray(32) { 9 }, myMint(), true, 0, currentTimeMillis())
        )
        vault.putMeta(acceptKey, acceptValue)
        val offerKey = ReferralMetaKeys.OFFER_PREFIX + "live2"
        val offerValue = encodeStoredOffer(StoredOffer("alice", "Alice", "Carol", currentTimeMillis()))
        vault.putMeta(offerKey, offerValue)

        failReads = true
        val rm1 = ReferralManager(vault, noTransport)   // must not throw
        assertTrue(rm1.pendingOffers().isEmpty(), "an unreadable offer is not presented")
        assertEquals(acceptValue, vault.meta[acceptKey], "the ref_a row must survive a failed read byte for byte")
        assertEquals(offerValue, vault.meta[offerKey], "the offer row must survive a failed read byte for byte")
        rm1.scrubInMemory()

        failReads = false
        val rm2 = ReferralManager(vault, noTransport)
        assertEquals(listOf("live2"), rm2.pendingOffers().map { it.introId }, "the next construction installs it")
        assertEquals(acceptValue, vault.meta[acceptKey], "a live accept record is installed, not dropped")
    }

    @Test
    fun aFailedV2TombstoneRead_neverOverwritesV2DuringTheV1Migration() {
        var failV2 = false
        val vault = object : InMemoryVault() {
            override fun getMeta(key: String): String? {
                if (failV2 && key == ReferralMetaKeys.COMPLETED_KEY_V2) throw RuntimeException("transient")
                return super.getMeta(key)
            }
        }
        val v2Token = ReferralManager.doneTokenFor("settled-v2")
        val v2Value = encodeCompletedIntros(listOf(v2Token), 128)
        vault.putMeta(ReferralMetaKeys.COMPLETED_KEY_V2, v2Value)
        vault.putMeta(ReferralMetaKeys.COMPLETED_KEY, encodeCompletedIntros(listOf("settledv1"), 128))

        failV2 = true
        ReferralManager(vault, noTransport).scrubInMemory()
        assertEquals(v2Value, vault.meta[ReferralMetaKeys.COMPLETED_KEY_V2], "v2 must not be overwritten while unreadable")
        assertNotNull(vault.meta[ReferralMetaKeys.COMPLETED_KEY], "v1 waits for a launch that can read v2")

        failV2 = false
        ReferralManager(vault, noTransport)
        val merged = decodeCompletedIntros(vault.meta[ReferralMetaKeys.COMPLETED_KEY_V2]!!, 128)
        assertTrue(v2Token in merged, "the stored v2 tombstone survives: $merged")
        assertTrue(ReferralManager.doneTokenFor("settledv1") in merged, "the v1 entry is migrated: $merged")
        assertNull(vault.meta[ReferralMetaKeys.COMPLETED_KEY], "v1 is dropped once migrated")
    }

    @Test
    fun staleOfferRateWindows_arePrunedByMaintenance_liveOnesAreUntouched() {
        val vault = InMemoryVault()
        val rm = ReferralManager(vault, noTransport)
        val now = 1_700_000_000_000L
        rm.clockMs = { now }
        val w = ReferralManager.OFFER_RATE_WINDOW_MS
        val stale = ReferralMetaKeys.OFFER_RATE_LIMIT_PREFIX + "old"
        val live = ReferralMetaKeys.OFFER_RATE_LIMIT_PREFIX + "live"
        val liveValue = "${now - w - 5},${now - 60_000}"
        vault.putMeta(stale, "${now - w - 1}")
        vault.putMeta(live, liveValue)

        rm.runMaintenance()

        assertNull(vault.getMeta(stale), "a row whose stamps all aged out is deleted")
        assertEquals(liveValue, vault.getMeta(live), "a live row keeps its exact bytes")
    }

    /** An unknown `ref_*` key (a future record type seen by an older build) is
     *  left alone — deleting state we cannot interpret is not ours to do. */
    @Test
    fun unknownReferralKeys_areLeftUntouched() {
        val vault = InMemoryVault()
        vault.putMeta("ref_future:xyz", "{}")
        ReferralManager(vault, noTransport)
        assertEquals("{}", vault.getMeta("ref_future:xyz"))
    }

    // -- (f) delete-contact purge coupling ------------------------------------

    @Test
    fun deletingTheIntroducer_purgesEveryReferralRecordThatNamesIt() {
        if (!x25519Up()) return
        val vault = InMemoryVault()
        seed(vault, "alice", "Alice")
        seed(vault, "dave", "Dave")

        val rm = ReferralManager(vault, noTransport)
        // An accepted-but-unfinalized handshake from alice (holds a live X25519
        // private key + our own inbox read-caps) …
        rm.handleControl("alice", ReferralManagerKinds.OFFER, offerJson("pg1", "Carol"))
        rm.registerAccepted("pg1", rm.pendingOffers().single(), x25519GenerateKeypair(), myMint())
        // … an un-consented offer from alice …
        rm.handleControl("alice", ReferralManagerKinds.OFFER, offerJson("pg2", "Erin"))
        // … a stash relayed by alice …
        rm.handleControl("alice", ReferralManagerKinds.ACCEPT, acceptJson("pg2", x25519GenerateKeypair().publicKey))
        // … plus unrelated records naming only DAVE, which must survive.
        vault.putMeta(
            ReferralMetaKeys.OFFER_PREFIX + "pg3",
            encodeStoredOffer(StoredOffer("dave", "Dave", "Frank", currentTimeMillis())),
        )
        vault.putMeta(
            ReferralMetaKeys.SESSION_PREFIX + "pg4",
            encodeStoredSession(StoredSession("dave", "zed", emptySet(), currentTimeMillis())),
        )
        // A session naming alice as one of the two parties, and a redrive to her.
        vault.putMeta(
            ReferralMetaKeys.SESSION_PREFIX + "pg5",
            encodeStoredSession(StoredSession("dave", "alice", emptySet(), currentTimeMillis())),
        )
        vault.putMeta(
            ReferralMetaKeys.REDRIVE_PREFIX + "pg6:alice",
            encodeStoredRedrive(StoredRedrive("pg6", "alice", "dave", "{}", 0, currentTimeMillis())),
        )
        // A decline writes the tombstone list, which references no contact at all.
        rm.handleControl("dave", ReferralManagerKinds.OFFER, offerJson("pg7", "Zed"))
        rm.declineOffer("pg7")
        assertNotNull(vault.getMeta(ReferralMetaKeys.COMPLETED_KEY_V2))
        assertTrue(refKeys(vault, ReferralMetaKeys.ACCEPT_PREFIX).isNotEmpty())

        vault.deleteContact("alice")   // routes through the shared classifier

        assertTrue(
            refKeys(vault, ReferralMetaKeys.ACCEPT_PREFIX).isEmpty(),
            "an ephemeral X25519 private key must not outlive the contact it was minted for",
        )
        assertNull(vault.getMeta(ReferralMetaKeys.OFFER_PREFIX + "pg2"))
        assertNull(vault.getMeta(ReferralMetaKeys.STASH_PREFIX + "pg2"))
        assertNull(vault.getMeta(ReferralMetaKeys.SESSION_PREFIX + "pg5"))
        assertNull(vault.getMeta(ReferralMetaKeys.REDRIVE_PREFIX + "pg6:alice"))
        // Records naming a DIFFERENT contact are untouched…
        assertNotNull(vault.getMeta(ReferralMetaKeys.OFFER_PREFIX + "pg3"))
        assertNotNull(vault.getMeta(ReferralMetaKeys.SESSION_PREFIX + "pg4"))
        // …and the tombstone list is never contact-scoped.
        assertNotNull(vault.getMeta(ReferralMetaKeys.COMPLETED_KEY_V2))
    }

    /** The classifier itself — the single thing both `VaultDatabase` actuals
     *  iterate, so it is pinned independently of either platform. */
    @Test
    fun referralPurgeClassifier_matchesEveryContactReference_andNothingElse() {
        val now = currentTimeMillis()
        val acceptKey = ReferralMetaKeys.ACCEPT_PREFIX + "i"
        val acceptVal = encodeStoredAccept(
            StoredAccept("alice", "Carol", ByteArray(32), ByteArray(32), myMint(), true, 0, now)
        )
        assertTrue(isReferralMetaResidueForContact(acceptKey, acceptVal, "alice"))
        assertFalse(isReferralMetaResidueForContact(acceptKey, acceptVal, "bob"))

        val offerKey = ReferralMetaKeys.OFFER_PREFIX + "i"
        val offerVal = encodeStoredOffer(StoredOffer("alice", "Alice", "Carol", now))
        assertTrue(isReferralMetaResidueForContact(offerKey, offerVal, "alice"))
        assertFalse(isReferralMetaResidueForContact(offerKey, offerVal, "Carol"))

        val sessKey = ReferralMetaKeys.SESSION_PREFIX + "i"
        val sessVal = encodeStoredSession(StoredSession("bb", "cc", setOf("bb"), now))
        assertTrue(isReferralMetaResidueForContact(sessKey, sessVal, "bb"))
        assertTrue(isReferralMetaResidueForContact(sessKey, sessVal, "cc"))
        assertFalse(isReferralMetaResidueForContact(sessKey, sessVal, "dd"))

        val stashKey = ReferralMetaKeys.STASH_PREFIX + "i"
        val stashVal = encodeStoredStash(StoredStash("alice", "{}", now))
        assertTrue(isReferralMetaResidueForContact(stashKey, stashVal, "alice"))

        val redriveKey = ReferralMetaKeys.REDRIVE_PREFIX + "i:cc"
        val redriveVal = encodeStoredRedrive(StoredRedrive("i", "cc", "bb", "{}", 0, now))
        assertTrue(isReferralMetaResidueForContact(redriveKey, redriveVal, "cc"))
        assertTrue(isReferralMetaResidueForContact(redriveKey, redriveVal, "bb"))
        assertFalse(isReferralMetaResidueForContact(redriveKey, redriveVal, "zz"))

        // The tombstone list references no contact and must never be purged —
        // neither the legacy v1 key nor the current hashed v2 key (1C-2).
        assertFalse(isReferralMetaResidueForContact(ReferralMetaKeys.COMPLETED_KEY, "a\nb", "a"))
        assertFalse(isReferralMetaResidueForContact(ReferralMetaKeys.COMPLETED_KEY_V2, "a\nb", "a"))
        // Nor may a ratchet/group key ever be classified as referral residue.
        for (k in ratchetMetaKeysForContact("alice")) assertFalse(isReferralMetaKey(k))
        assertFalse(isReferralMetaResidueForContact("dr/alice/text", "alice", "alice"))
        // A null/unreadable value classifies as "not this contact" (the TTL GC owns it).
        assertFalse(isReferralMetaResidueForContact(acceptKey, null, "alice"))

        // The per-introducer offer rate-limit key is keyed by contactId
        // DIRECTLY (not introId), so — unlike every case above — it must match
        // on the KEY ALONE, even with a null value (the same shape as
        // isGroupMetaResidueForContact's INVITE_RL_PREFIX case).
        val rlKey = ReferralMetaKeys.OFFER_RATE_LIMIT_PREFIX + "alice"
        assertTrue(isReferralMetaResidueForContact(rlKey, "1,2,3", "alice"))
        assertTrue(isReferralMetaResidueForContact(rlKey, null, "alice"), "keyed by contactId — matches even with no value")
        assertFalse(isReferralMetaResidueForContact(rlKey, "1,2,3", "bob"), "must not match a DIFFERENT contact's rate key")
        // Prefix-sharing must not straddle the boundary: "alice2" must not be
        // treated as a residue of "alice".
        assertFalse(isReferralMetaResidueForContact(ReferralMetaKeys.OFFER_RATE_LIMIT_PREFIX + "alice2", "1", "alice"))
    }

    // -- codec round-trips -----------------------------------------------------

    @Test
    fun storedAccept_roundTrips_includingTheEphemeralKeypair() {
        val kp = ByteArray(32) { (it * 7).toByte() }
        val pub = ByteArray(32) { (it * 3 + 1).toByte() }
        val enc = encodeStoredAccept(
            StoredAccept("alice", "Ca\"rol\n", kp, pub, myMint(), false, 3, 1234L)
        )
        val dec = assertNotNull(decodeStoredAccept(enc))
        assertEquals("alice", dec.introducerContactId)
        assertEquals("Ca\"rol\n", dec.peerAlias, "aliases are attacker-influenced: escaping must round-trip")
        assertEquals(kp.toList(), dec.privateKey.toList())
        assertEquals(pub.toList(), dec.publicKey.toList())
        assertEquals(M_IB, dec.minted.main.inboxId)
        assertEquals(CAP43, dec.minted.main.readCapability)
        assertEquals(CAP43D, dec.minted.ctl.writeCapability)
        assertFalse(dec.sent)
        assertEquals(3, dec.attempts)
        assertEquals(1234L, dec.createdAt)
    }

    @Test
    fun completedIntros_encodingIsBoundedAndRejectsUnsafeIds() {
        val ids = (1..200).map { "id$it" } + listOf("bad\nid", "bad:id", "")
        val enc = encodeCompletedIntros(ids, 128)
        val dec = decodeCompletedIntros(enc, 128)
        assertEquals(128, dec.size, "the tombstone list stays bounded")
        assertTrue(dec.none { it.contains("\n") || it.contains(":") || it.isEmpty() })
        assertTrue(dec.contains("id200"), "the NEWEST entries are the ones kept")
    }
}

/** Local aliases so the long qualified names don't dominate the cases above. */
private object ReferralManagerKinds {
    val OFFER = MessageManager.CONTROL_KIND_REFERRAL_OFFER
    val ACCEPT = MessageManager.CONTROL_KIND_REFERRAL_ACCEPT
}

// ---------------------------------------------------------------------------
// Redrive cases — these need a REAL MessageManager so a send can be made to
// fail, so they run over a scripted RelayHttp double.
// ---------------------------------------------------------------------------

private val B_CTL_OUT = "bctl" + "1".repeat(28)
private val C_CTL_OUT = "cctl" + "2".repeat(28)
private val A_CTL_OUT = "actl" + "3".repeat(28)

/** Introducer paired with both introducees (control channel only — that is all
 *  the referral handshake ever uses). */
private class IntroducerFixture {
    val vault = InMemoryVault()
    val http = RecordingRelayHttp()
    val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)

    init {
        vault.insertContact(ContactRecord("bb", generateSecureRandom(32), 0, "Bob", 0L))
        vault.insertContact(ContactRecord("cc", generateSecureRandom(32), 0, "Carol", 0L))
        vault.insertInboxId(InboxIdRecord(B_CTL_OUT, "bb", 1L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_CTL, CAP43))
        vault.insertInboxId(InboxIdRecord(C_CTL_OUT, "cc", 1L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_CTL, CAP43))
    }

    fun newManager() = ReferralManager(vault) { mgr }
}

private fun ok() = HttpResult(202, "", true)
private fun refused() = HttpResult(500, "nope", false)

class ReferralRedriveTest {

    /** (c) INTRODUCER restart between the two accepts — the relay still completes. */
    @Test
    fun introducerRestart_stillRelaysTheAccept() {
        if (!aeadUp() || !x25519Up()) return
        val f = IntroducerFixture()
        f.http.script(ok(), ok())                       // the two referral offers
        val rm1 = f.newManager()
        val introId = assertNotNull(rm1.startReferral("bb", "cc"))
        assertEquals(1, refKeys(f.vault, ReferralMetaKeys.SESSION_PREFIX).size, "the intro session must be mirrored")
        rm1.scrubInMemory()                             // introducer backgrounded / killed

        val rm2 = f.newManager()
        f.http.script(ok())                             // the relayed accept
        val before = f.http.calls.size
        rm2.handleControl("bb", ReferralManagerKinds.ACCEPT, acceptJson(introId, x25519GenerateKeypair().publicKey))

        assertEquals(before + 1, f.http.calls.size, "the rehydrated session must relay Bob's accept")
        assertEquals(
            "/inbox/$C_CTL_OUT?ttl=604800", f.http.calls.last().url.removePrefix("http://relay.test"),
            "it must go to the OTHER introducee, with the 7-day relay retention",
        )
    }

    /** (d) A failed relay-forward is redriven on a later control sweep. */
    @Test
    fun failedRelayForward_isRedrivenOnALaterSweep() {
        if (!aeadUp() || !x25519Up()) return
        val f = IntroducerFixture()
        f.http.script(ok(), ok())
        val rm = f.newManager()
        val introId = assertNotNull(rm.startReferral("bb", "cc"))

        f.http.script(refused())                        // the forward is dropped
        rm.handleControl("bb", ReferralManagerKinds.ACCEPT, acceptJson(introId, x25519GenerateKeypair().publicKey))
        val redriveKeys = refKeys(f.vault, ReferralMetaKeys.REDRIVE_PREFIX)
        assertEquals(1, redriveKeys.size, "a swallowed forward must become a durable redrive obligation")
        assertEquals(ReferralMetaKeys.REDRIVE_PREFIX + "$introId:cc", redriveKeys.single())

        f.http.script(ok())
        val before = f.http.calls.size
        rm.runMaintenance()                             // == one control sweep
        assertEquals(before + 1, f.http.calls.size, "the sweep must retry the forward")
        assertEquals("/inbox/$C_CTL_OUT?ttl=604800", f.http.calls.last().url.removePrefix("http://relay.test"))
        assertTrue(refKeys(f.vault, ReferralMetaKeys.REDRIVE_PREFIX).isEmpty(), "a delivered redrive is dropped")
    }

    /** …and the obligation survives a restart, not just a later sweep. */
    @Test
    fun failedRelayForward_survivesARestart_andIsRedrivenByTheNewManager() {
        if (!aeadUp() || !x25519Up()) return
        val f = IntroducerFixture()
        f.http.script(ok(), ok())
        val rm1 = f.newManager()
        val introId = assertNotNull(rm1.startReferral("bb", "cc"))
        f.http.script(refused())
        rm1.handleControl("bb", ReferralManagerKinds.ACCEPT, acceptJson(introId, x25519GenerateKeypair().publicKey))
        assertEquals(1, refKeys(f.vault, ReferralMetaKeys.REDRIVE_PREFIX).size)
        rm1.scrubInMemory()

        val rm2 = f.newManager()
        f.http.script(ok())
        val before = f.http.calls.size
        rm2.runMaintenance()
        assertEquals(before + 1, f.http.calls.size)
        assertEquals("/inbox/$C_CTL_OUT?ttl=604800", f.http.calls.last().url.removePrefix("http://relay.test"))
        assertTrue(refKeys(f.vault, ReferralMetaKeys.REDRIVE_PREFIX).isEmpty())
    }

    /**
     * Redrives are BOUNDED — a permanently dead peer never becomes a hot loop.
     *
     * The bound is PER SESSION. This case drives all 20
     * sweeps on ONE manager, so it is unaffected; a NEW manager over the same
     * vault re-arms the counter (pinned by
     * ReferralAttemptBudgetPerSessionTest.anExhaustedRelayRedriveBudget_isRearmedByTheNextSession),
     * because a transport outage during one session must not disarm the
     * obligation for the record's whole life.
     */
    @Test
    fun relayRedrive_stopsAfterItsAttemptBudget() {
        if (!aeadUp() || !x25519Up()) return
        val f = IntroducerFixture()
        f.http.script(ok(), ok())
        val rm = f.newManager()
        val introId = assertNotNull(rm.startReferral("bb", "cc"))
        f.http.script(refused())
        rm.handleControl("bb", ReferralManagerKinds.ACCEPT, acceptJson(introId, x25519GenerateKeypair().publicKey))

        // 20 sweeps, every send refused: attempts stop at the budget (12).
        repeat(20) { f.http.script(refused()) }
        val before = f.http.calls.size
        repeat(20) { rm.runMaintenance() }
        val attempts = f.http.calls.size - before
        assertTrue(attempts in 1..12, "redrive attempts must be bounded, saw $attempts")
        // The record is KEPT (only the TTL reclaims it) so nothing is silently lost.
        assertEquals(1, refKeys(f.vault, ReferralMetaKeys.REDRIVE_PREFIX).size)
    }

    /**
     * The st=0 crash window: an accept was staged into the vault but its delivery
     * was never confirmed. The next sweep must re-send THE SAME material and flip
     * the record to st=1 — never mint a fresh keypair, which would derive a secret
     * the peer can never match.
     */
    @Test
    fun unconfirmedAccept_isReSentWithTheSameMaterial_andConfirmed() {
        if (!aeadUp()) return
        val vault = InMemoryVault()
        val http = RecordingRelayHttp()
        val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)
        vault.insertContact(ContactRecord("aa", generateSecureRandom(32), 0, "Alice", 0L))
        vault.insertInboxId(InboxIdRecord(A_CTL_OUT, "aa", 1L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_CTL, CAP43))

        val priv = ByteArray(32) { (it + 1).toByte() }
        val pub = ByteArray(32) { (it + 100).toByte() }
        vault.putMeta(
            ReferralMetaKeys.ACCEPT_PREFIX + "cw1",
            encodeStoredAccept(StoredAccept("aa", "Carol", priv, pub, myMint(), false, 0, currentTimeMillis())),
        )

        val rm = ReferralManager(vault) { mgr }
        http.script(ok())
        rm.runMaintenance()

        assertEquals(1, http.calls.size, "the unconfirmed accept must be re-sent")
        assertEquals("/inbox/$A_CTL_OUT?ttl=604800", http.calls.last().url.removePrefix("http://relay.test"))
        val rec = assertNotNull(decodeStoredAccept(assertNotNull(vault.getMeta(ReferralMetaKeys.ACCEPT_PREFIX + "cw1"))))
        assertTrue(rec.sent, "a confirmed delivery must flip the record to st=1")
        assertEquals(pub.toList(), rec.publicKey.toList(), "the re-send must reuse the SAME public key")
        assertEquals(priv.toList(), rec.privateKey.toList(), "the re-send must reuse the SAME private key")
    }

    /** An unsent accept is NOT finalizable: a peer accept against it is stashed,
     *  so a referred contact is only committed once both sides exchanged material. */
    @Test
    fun peerAcceptAgainstAnUnsentAccept_isStashed_notFinalized() {
        if (!x25519Up()) return
        val vault = InMemoryVault()
        seed(vault, "alice", "Alice")
        vault.putMeta(
            ReferralMetaKeys.ACCEPT_PREFIX + "us1",
            encodeStoredAccept(
                StoredAccept("alice", "Carol", ByteArray(32) { 5 }, ByteArray(32) { 6 },
                    myMint(), false, 0, currentTimeMillis())
            ),
        )
        val rm = ReferralManager(vault) { null }
        rm.handleControl("alice", ReferralManagerKinds.ACCEPT, acceptJson("us1", x25519GenerateKeypair().publicKey))

        assertEquals(1, vault.getAllContacts().size, "no contact may be committed while our accept is unconfirmed")
        assertEquals(1, refKeys(vault, ReferralMetaKeys.STASH_PREFIX).size, "the peer accept must be stashed instead")
    }
}

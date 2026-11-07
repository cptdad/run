package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// Referral STASH sender-guard + stash-lifecycle hardening.
//
// Two isolated properties, both defense-in-depth (the precondition for the
// first is not reachable over the wire today — the sole stash writer already
// gates on the introducer — so this pins the belt to the existing braces):
//
//  1. confirmAcceptSent finalizes from a stashed peer-accept ONLY when the stash
//     was relayed by the SAME introducer the pending was created for — the exact
//     guard rehydrate's apply loop and handleAccept's live path already enforce.
//     A mismatched stash is discarded (RAM + vault) and MUST NOT brick the
//     pairing: the genuine accept from the real introducer still finalizes.
//
//  2. A stash never outlives BOTH the offer and the pending it could finalize
//     against. The MAX_OFFERS eviction co-removes an evicted offer's stash, and
//     the gcExpired TTL/absolute-ceiling teardown prunes an orphaned stash that a
//     re-delivered peer-accept re-stamped fresh past its offer's ceiling.
//
// Hermetic: reuses the in-memory InMemoryVault fake, the clockMs seam, and the
// no-transport `{ null }` provider the sibling referral suites use. Bridge-guard
// the X25519/HKDF finalize cases exactly like ReferralGuardTest.
// ---------------------------------------------------------------------------

private val SG_OFFER = MessageManager.CONTROL_KIND_REFERRAL_OFFER
private val SG_ACCEPT = MessageManager.CONTROL_KIND_REFERRAL_ACCEPT

/** 32-char inbox ids / 43-char caps — the shapes the validators demand. */
private val SG_PEER_IB  = "sp" + "A".repeat(30)
private val SG_PEER_CIB = "sp" + "B".repeat(30)
private val SG_MY_IB    = "sm" + "C".repeat(30)
private val SG_MY_CIB   = "sm" + "D".repeat(30)
private val SG_CAP_R = "R".repeat(43)
private val SG_CAP_W = "W".repeat(43)
private val SG_CAP_S = "S".repeat(43)
private val SG_CAP_X = "X".repeat(43)

private fun sgMint() = MintedInboxPair(
    MintedInbox(SG_MY_IB, SG_CAP_R, SG_CAP_W, Long.MAX_VALUE),
    MintedInbox(SG_MY_CIB, SG_CAP_S, SG_CAP_X, Long.MAX_VALUE),
)

private fun sgAcceptJson(introId: String, peerPub: ByteArray) =
    """{"ii":${jsonEscapeString(introId)},"pk":${jsonEscapeString(encodeBase64(peerPub))},""" +
        """"ib":${jsonEscapeString(SG_PEER_IB)},"wc":${jsonEscapeString(SG_CAP_W)},""" +
        """"cib":${jsonEscapeString(SG_PEER_CIB)},"cwc":${jsonEscapeString(SG_CAP_X)}}"""

// ---------------------------------------------------------------------------
// FIX 1 — confirmAcceptSent's sender guard.
// ---------------------------------------------------------------------------

class ReferralConfirmAcceptSenderGuardTest {

    /** A stash whose relayer is NOT our introducer (only reachable via a crafted
     *  `ref_a` record — the live writer validates the sender before it stashes)
     *  must NOT finalize when we confirm our accept, and must be discarded. The
     *  mismatch must not poison the pairing: the genuine relayed accept from our
     *  real introducer still finalizes afterward (brick-safety). */
    @Test
    fun aStashFromTheWrongIntroducer_doesNotFinalize_andTheGenuineAcceptStillDoes() {
        if (!x25519Up()) return
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")   // our real introducer

        val introId = "sg-mismatch-1"
        val carol = x25519GenerateKeypair()   // the real peer's key

        // Plant a WELL-FORMED, otherwise-finalizable stash relayed by "mallory",
        // not our introducer: valid peer pubkey + peer inbox ids that do not
        // collide with our own mint. Absent the sender guard, confirmAcceptSent
        // would derive a referred contact from this.
        vault.putMeta(
            ReferralMetaKeys.STASH_PREFIX + introId,
            encodeStoredStash(
                StoredStash("mallory", sgAcceptJson(introId, carol.publicKey), currentTimeMillis())
            ),
        )

        // rehydrate loads the stash into RAM; with no `pending` yet it is not applied.
        val rm = ReferralManager(vault) { null }
        assertNotNull(
            vault.getMeta(ReferralMetaKeys.STASH_PREFIX + introId),
            "precondition: the planted stash survived rehydrate (RAM + vault)",
        )
        assertEquals(1, vault.getAllContacts().size, "precondition: rehydrate did not finalize the mismatched stash")

        // Accept the offer with our own material. registerAccepted =
        // stageAccept + confirmAcceptSent, so this drives confirmAcceptSent's
        // stash-apply against the mismatched relayer.
        rm.registerAccepted(
            introId,
            ReferralOffer(introId, "alice", "Alice", "Carol", currentTimeMillis()),
            x25519GenerateKeypair(), sgMint(),
        )

        assertEquals(1, vault.getAllContacts().size, "a stash from the wrong introducer must not create a contact")
        assertNull(
            vault.getContact(ReferralManager.referredContactIdFor(introId)),
            "no referred contact may be derived from the bogus stash",
        )
        assertNull(
            vault.getMeta(ReferralMetaKeys.STASH_PREFIX + introId),
            "the mismatched stash must be discarded from RAM and the vault",
        )

        // BRICK-SAFETY: the mismatch did not poison the pairing. Our accept is
        // marked sent, so the GENUINE relayed accept from our real introducer
        // still finalizes the real contact.
        rm.handleControl("alice", SG_ACCEPT, sgAcceptJson(introId, carol.publicKey))
        assertEquals(2, vault.getAllContacts().size, "the genuine accept from our introducer must still finalize")
        assertNotNull(
            vault.getContact(ReferralManager.referredContactIdFor(introId)),
            "the real referred contact is committed after the genuine accept",
        )
    }

    /** No regression: a stash whose relayer IS our introducer still finalizes on
     *  confirmAcceptSent, exactly as before — driven through the sole legitimate
     *  stash writer (a pre-consent peer accept). */
    @Test
    fun aMatchingStash_stillFinalizesOnConfirm_exactlyAsBefore() {
        if (!x25519Up()) return
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        val rm = ReferralManager(vault) { null }

        val introId = "sg-match-1"
        val carol = x25519GenerateKeypair()

        // The offer, then the peer's accept arriving BEFORE our consent — the
        // only legitimate stash writer, which records fromContactId = introducer.
        rm.handleControl("alice", SG_OFFER, referralOfferJson(introId, "Carol"))
        rm.handleControl("alice", SG_ACCEPT, sgAcceptJson(introId, carol.publicKey))
        assertNotNull(
            vault.getMeta(ReferralMetaKeys.STASH_PREFIX + introId),
            "precondition: the pre-consent peer accept was stashed against our introducer",
        )
        assertEquals(1, vault.getAllContacts().size, "precondition: nothing finalizes before we accept")

        // We accept: confirmAcceptSent applies the MATCHING stash and finalizes.
        rm.registerAccepted(introId, rm.pendingOffers().single(), x25519GenerateKeypair(), sgMint())

        assertEquals(2, vault.getAllContacts().size, "a matching stash finalizes on confirmAcceptSent, unchanged")
        assertNotNull(vault.getContact(ReferralManager.referredContactIdFor(introId)))
        assertNull(vault.getMeta(ReferralMetaKeys.STASH_PREFIX + introId), "the applied stash is consumed by the finalize")
        assertNull(vault.getMeta(ReferralMetaKeys.OFFER_PREFIX + introId), "the offer is consumed")
        assertNull(vault.getMeta(ReferralMetaKeys.ACCEPT_PREFIX + introId), "the accept record dies with the finalize")
    }
}

// ---------------------------------------------------------------------------
// FIX 2 — a stash must not outlive its offer.
// ---------------------------------------------------------------------------

class ReferralStashOutlivesOfferTest {

    /** ABSOLUTE-CEILING teardown (gcExpired reconciliation): a peer accept that
     *  first lands long after its offer's absolute ceiling stashes FRESH,
     *  so the stash's OWN TTL sweep would keep it. Once the offer is reclaimed at
     *  its ceiling the stash is orphaned (no offer, no pending), and the
     *  reconciliation is the only thing that removes it. */
    @Test
    fun absoluteCeilingExpiry_prunesTheOrphanedStash() {
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        val rm = ReferralManager(vault) { null }

        val introId = "sg-ceiling-1"
        val base = currentTimeMillis()
        rm.handleControl("alice", SG_OFFER, referralOfferJson(introId, "Carol"))

        // Advance past the offer's absolute ceiling, THEN let a peer accept land:
        // the offer stamp is frozen (refresh is refused past the ceiling) while
        // the stash is written FRESH at the advanced clock.
        val past = base + REFERRAL_RECORD_MAX_LIFETIME_MS + 5_000L
        rm.clockMs = { past }
        rm.handleControl("alice", SG_ACCEPT, sgAcceptJson(introId, ByteArray(32) { 9 }))
        assertNotNull(vault.getMeta(ReferralMetaKeys.OFFER_PREFIX + introId), "precondition: offer still on disk pre-GC")
        assertNotNull(
            vault.getMeta(ReferralMetaKeys.STASH_PREFIX + introId),
            "precondition: a FRESH stash exists past the offer's ceiling",
        )

        rm.runMaintenance()   // gcExpired

        assertNull(
            vault.getMeta(ReferralMetaKeys.OFFER_PREFIX + introId),
            "the offer is reclaimed at its absolute ceiling",
        )
        // The stash's own stamp is fresh, so the stash-TTL sweep keeps it — the
        // reconciliation is the ONLY thing that removes it, because its offer is gone.
        assertNull(
            vault.getMeta(ReferralMetaKeys.STASH_PREFIX + introId),
            "a stash must not outlive its offer — the orphan is pruned with the offer teardown",
        )
        // A later relaunch cannot resurrect an orphan that no longer exists.
        assertTrue(
            ReferralManager(vault) { null }.pendingOffers().isEmpty(),
            "nothing survives to be acted on after the prune",
        )
        assertTrue(
            vault.meta.keys.none { it.startsWith(ReferralMetaKeys.STASH_PREFIX) },
            "no orphan stash record remains in the vault",
        )
    }

    /** A re-delivered peer accept must NOT re-stamp a live stash: its first-seen
     *  stamp is both its idle and its absolute bound (rehydrate and gcExpired pass
     *  it as createdAt AND firstSeenAt). Before the fix every re-delivery wrote
     *  `now`, so a relay re-delivering inside the idle TTL kept the stash alive
     *  forever while each re-delivery also refreshed the offer. */
    @Test
    fun reDeliveredPeerAccept_keepsTheStashFirstSeenStamp_andItStillAgesOut() {
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        val rm = ReferralManager(vault) { null }

        val introId = "sg-sticky-1"
        val t0 = currentTimeMillis()
        rm.clockMs = { t0 }
        rm.handleControl("alice", SG_OFFER, referralOfferJson(introId, "Carol"))
        rm.handleControl("alice", SG_ACCEPT, sgAcceptJson(introId, ByteArray(32) { 9 }))
        fun stashStamp(): Long? = vault.getMeta(ReferralMetaKeys.STASH_PREFIX + introId)
            ?.let { decodeStoredStash(it) }?.createdAt
        assertEquals(t0, stashStamp(), "precondition: the first accept stashes at its arrival")

        // Re-delivered twice inside the idle TTL: each one refreshes the OFFER (the
        // introduction is live), never the stash.
        val step = REFERRAL_RECORD_TTL_MS / 2
        for (i in 1..2) {
            rm.clockMs = { t0 + i * step - 1_000L }
            rm.handleControl("alice", SG_ACCEPT, sgAcceptJson(introId, ByteArray(32) { 9 }))
            assertEquals(t0, stashStamp(), "re-delivery $i must keep the stash's first-seen stamp")
        }

        // Past the stash's own bound (first-seen + TTL), with the offer still live
        // because the last re-delivery refreshed it: the stash ages out.
        rm.clockMs = { t0 + REFERRAL_RECORD_TTL_MS + 1 }
        rm.runMaintenance()
        assertNotNull(
            vault.getMeta(ReferralMetaKeys.OFFER_PREFIX + introId),
            "precondition: the refreshed offer is still live",
        )
        assertNull(
            vault.getMeta(ReferralMetaKeys.STASH_PREFIX + introId),
            "the stash is bounded by its FIRST arrival, not its last re-delivery",
        )
    }

    /** MAX_OFFERS eviction: the oldest offer is dropped for capacity; the
     *  peer-accept stashed against it (no pending, so no in-flight finalize) must
     *  be co-removed, not left as TTL-only residue.
     *
     *  A per-introducer cap of 8 pending offers,
     *  so the 200 filler offers here now come from 200 DISTINCT introducers
     *  (one each — nowhere near their own per-introducer cap) rather than one
     *  flooding sender, to isolate this test's GLOBAL-capacity concern from the
     *  per-introducer flood defense (see ReferralOfferFloodTest). */
    @Test
    fun maxOffersEviction_coRemovesTheEvictedOffersStash() {
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        val rm = ReferralManager(vault) { null }

        // The oldest offer, with a peer accept stashed against it (pre-consent).
        val victim = "sg-evict-victim"
        rm.handleControl("alice", SG_OFFER, referralOfferJson(victim, "Carol"))
        rm.handleControl("alice", SG_ACCEPT, sgAcceptJson(victim, ByteArray(32) { 9 }))
        assertNotNull(
            vault.getMeta(ReferralMetaKeys.STASH_PREFIX + victim),
            "precondition: the oldest offer has a stash and no pending",
        )

        // Over-fill the offer map so the oldest slot (the victim) is evicted for
        // capacity. MAX_OFFERS is 128; 200 fresh offers (from 200 distinct
        // introducers) guarantees the eviction.
        for (i in 0 until 200) {
            val filler = "sg-filler-intro-$i"
            seedReferralContact(vault, filler, "Filler$i")
            rm.handleControl(filler, SG_OFFER, referralOfferJson("sg-filler-$i", "Running Fox"))
        }

        assertNull(
            vault.getMeta(ReferralMetaKeys.OFFER_PREFIX + victim),
            "precondition: the victim offer was evicted for capacity",
        )
        assertNull(
            vault.getMeta(ReferralMetaKeys.STASH_PREFIX + victim),
            "the evicted offer's stash must be co-removed, not left as TTL-only residue",
        )
    }
}

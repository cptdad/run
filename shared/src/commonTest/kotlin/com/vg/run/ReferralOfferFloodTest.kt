package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// Referral-offer flood caps. Before this fix,
// handleOffer had ONLY the global MAX_OFFERS=128 cap, shared across every
// introducer and evicting oldest-across-ALL-SENDERS — a single introducer
// could mint attacker-chosen introIds and either fill the whole consent queue
// or push every OTHER introducer's genuine pending offer out via eviction.
//
// These tests mirror the ones GroupManager already has for its sibling
// handleInvite caps (GroupInvitePersistenceTest / GroupManagerGuardsTest):
// per-introducer standing cap, per-introducer hourly rate, and — new here,
// because the group path's cap is a clock-independent "already joined" count
// with no cross-sender eviction concern at the group cap — global-cap eviction
// FAIRNESS: a flooder must only ever evict their OWN oldest offer.
// ---------------------------------------------------------------------------

private fun rofSeed(vault: InMemoryVault, id: String, alias: String) {
    vault.insertContact(
        ContactRecord(
            contactId = id, sharedSecret = generateSecureRandom(32),
            trustLevel = 0, alias = alias, aliasLastRotated = 0L,
        )
    )
}

private fun rofOfferJson(introId: String, peerAlias: String) =
    """{"ii":${jsonEscapeString(introId)},"pa":${jsonEscapeString(peerAlias)}}"""

private val ROF_OFFER = MessageManager.CONTROL_KIND_REFERRAL_OFFER
private val noTransport: () -> MessageManager? = { null }

class ReferralOfferFloodTest {

    // -- per-introducer standing cap ------------------------------------

    @Test
    fun perIntroducerCap_dropsTheOfferOverEight_leavingEarlierOnesIntact() {
        val vault = InMemoryVault()
        rofSeed(vault, "alice", "Alice")
        val rm = ReferralManager(vault, noTransport)

        repeat(ReferralManager.MAX_OFFERS_PER_INTRODUCER) { i ->
            rm.handleControl("alice", ROF_OFFER, rofOfferJson("cap$i", "Running Fox"))
        }
        assertEquals(
            ReferralManager.MAX_OFFERS_PER_INTRODUCER, rm.pendingOffers().size,
            "exactly MAX_OFFERS_PER_INTRODUCER offers from one introducer must be accepted",
        )

        // The (cap+1)th offer from the SAME introducer is dropped — not persisted,
        // and it must not evict any of the earlier eight to make room for itself.
        rm.handleControl("alice", ROF_OFFER, rofOfferJson("overflow", "Running Fox"))

        assertEquals(
            ReferralManager.MAX_OFFERS_PER_INTRODUCER, rm.pendingOffers().size,
            "an offer over the per-introducer cap must be dropped, not swapped in",
        )
        assertTrue(
            rm.pendingOffers().none { it.introId == "overflow" },
            "the over-cap offer itself must never appear",
        )
        assertNull(vault.getMeta(ReferralMetaKeys.OFFER_PREFIX + "overflow"), "a dropped offer persists nothing")
        for (i in 0 until ReferralManager.MAX_OFFERS_PER_INTRODUCER) {
            assertTrue(
                rm.pendingOffers().any { it.introId == "cap$i" },
                "an earlier, WITHIN-cap offer from the same introducer must survive untouched",
            )
        }
    }

    @Test
    fun perIntroducerCap_isPerIntroducer_notGlobal() {
        val vault = InMemoryVault()
        rofSeed(vault, "alice", "Alice")
        rofSeed(vault, "dave", "Dave")
        val rm = ReferralManager(vault, noTransport)

        // Alice fills her own cap...
        repeat(ReferralManager.MAX_OFFERS_PER_INTRODUCER) { i ->
            rm.handleControl("alice", ROF_OFFER, rofOfferJson("a$i", "Running Fox"))
        }
        // ...and Dave's very next offer must still be accepted — the cap is
        // per-introducer, so Alice being at her ceiling must not block Dave.
        rm.handleControl("dave", ROF_OFFER, rofOfferJson("d0", "Silent Wolf"))

        assertTrue(rm.pendingOffers().any { it.introId == "d0" }, "a different introducer is unaffected by Alice's cap")
        assertEquals(ReferralManager.MAX_OFFERS_PER_INTRODUCER + 1, rm.pendingOffers().size)
    }

    // -- per-introducer hourly rate --------------------------------------

    @Test
    fun perIntroducerRate_dropsTheNinthOfferWithinTheHour_evenWithNothingPending() {
        val vault = InMemoryVault()
        rofSeed(vault, "alice", "Alice")
        val rm = ReferralManager(vault, noTransport)

        // Eight offers, each DECLINED immediately so the standing pending-count
        // cap never engages — only the rate window should be at play here.
        repeat(ReferralManager.MAX_OFFERS_PER_INTRODUCER_PER_WINDOW) { i ->
            rm.handleControl("alice", ROF_OFFER, rofOfferJson("rate$i", "Running Fox"))
            rm.declineOffer("rate$i")
        }
        assertEquals(0, rm.pendingOffers().size, "precondition: every prior offer was declined")

        // The ninth offer inside the same hour must still be dropped by the
        // sliding-window rate, independent of the (now-empty) standing cap.
        rm.handleControl("alice", ROF_OFFER, rofOfferJson("rate-over", "Running Fox"))

        assertTrue(rm.pendingOffers().isEmpty(), "the rate-limited offer must not be accepted")
        assertNull(vault.getMeta(ReferralMetaKeys.OFFER_PREFIX + "rate-over"), "a rate-dropped offer persists nothing")
    }

    @Test
    fun perIntroducerRate_prunesStampsOutsideTheWindow_soAnOldBurstDoesNotPermanentlyBlock() {
        val vault = InMemoryVault()
        rofSeed(vault, "alice", "Alice")
        val rm = ReferralManager(vault, noTransport)

        // Pre-seed the rate meta with a full window's worth of stamps that are
        // all already outside the 1-hour window (mirrors
        // GroupMembershipEdgeCaseTest's futureStamps-pruning shape, but aged
        // BACKWARD here instead of forward).
        val now = currentTimeMillis()
        val stale = (1..ReferralManager.MAX_OFFERS_PER_INTRODUCER_PER_WINDOW)
            .joinToString(",") { (now - ReferralManager.OFFER_RATE_WINDOW_MS - 1000L).toString() }
        vault.putMeta(ReferralMetaKeys.OFFER_RATE_LIMIT_PREFIX + "alice", stale)

        rm.handleControl("alice", ROF_OFFER, rofOfferJson("fresh", "Running Fox"))

        assertTrue(
            rm.pendingOffers().any { it.introId == "fresh" },
            "stamps aged out of the window must not count against the live rate limit",
        )
    }

    // -- global-cap eviction fairness (the flooder evicts ONLY themselves) --

    @Test
    fun globalCapEviction_evictsTheInsertingIntroducersOwnOldest_neverAnotherIntroducers() {
        val vault = InMemoryVault()
        val rm = ReferralManager(vault, noTransport)

        // "flooder" gets MAX_OFFERS_PER_INTRODUCER - 1 pending offers first — one
        // short of their own cap, so their next offer is still individually
        // ALLOWED (passes offerAllowed) and only then hits the GLOBAL cap logic.
        rofSeed(vault, "flooder", "Flooder")
        val flooderCount = ReferralManager.MAX_OFFERS_PER_INTRODUCER - 1
        repeat(flooderCount) { i ->
            rm.handleControl("flooder", ROF_OFFER, rofOfferJson("f$i", "Running Fox"))
        }
        assertEquals(flooderCount, rm.pendingOffers().count { it.introducerContactId == "flooder" })

        // Fill the rest of the GLOBAL 128 slots with ONE offer each from many
        // DIFFERENT, unrelated introducers — each well within their own
        // per-introducer cap and rate, so none of these are refused.
        val othersNeeded = 128 - flooderCount
        val otherIntroIds = (0 until othersNeeded).map { "other$it" }
        for (i in 0 until othersNeeded) {
            val cid = "intro$i"
            rofSeed(vault, cid, "Contact$i")
            rm.handleControl(cid, ROF_OFFER, rofOfferJson(otherIntroIds[i], "Silent Wolf"))
        }
        assertEquals(128, rm.pendingOffers().size, "precondition: the global cap is exactly full")

        // flooder's NEXT offer is allowed by offerAllowed (still one under their
        // own per-introducer cap) but the map is now at the GLOBAL cap — eviction
        // must take flooder's OWN oldest ("f0"), never one of the 128 "other*"
        // introducers' single pending offers.
        rm.handleControl("flooder", ROF_OFFER, rofOfferJson("f-new", "Running Fox"))

        assertEquals(128, rm.pendingOffers().size, "the map stays at the global cap after the evict+insert")
        assertFalse(
            rm.pendingOffers().any { it.introId == "f0" },
            "flooder's own oldest offer must be the one evicted",
        )
        assertTrue(
            rm.pendingOffers().any { it.introId == "f-new" },
            "flooder's new offer must have been admitted after the self-eviction",
        )
        for (id in otherIntroIds) {
            assertTrue(
                rm.pendingOffers().any { it.introId == id },
                "no OTHER introducer's pending offer may be evicted to make room for the flooder",
            )
        }
        assertNull(
            vault.getMeta(ReferralMetaKeys.OFFER_PREFIX + "f0"),
            "the evicted offer's vault record must go with it, not linger as TTL-only residue",
        )
    }
}

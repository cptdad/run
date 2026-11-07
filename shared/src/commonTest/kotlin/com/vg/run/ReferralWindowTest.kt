package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

// ---------------------------------------------------------------------------
// Referral WINDOW semantics — the exact TTL/ceiling boundaries and the
// window-CLOSED behaviour at each stage of the handshake.
//
// The existing TTL suites (ReferralRecordTtlTest, ReferralMidSessionGcTest,
// expiredRecords_areGarbageCollectedAtRehydration) drive comfortably past the
// bounds; nothing pins the BOUNDARY itself. `isRecordLive` uses `<=` on both
// the idle TTL and the absolute ceiling, and `withinAbsoluteLifetime` uses
// `<=` too — so "exactly at the bound" is LIVE and one millisecond past it is
// not. These cases pin that line deterministically through the [clockMs] seam
// (rehydrate reads the real clock by design, so the boundary is driven through
// gcExpired / handleAccept, which share `isRecordLive`/`withinAbsoluteLifetime`
// with rehydrate).
//
// The window-closed cases are the unit analog of the closed-window e2e spec:
// once an introduction's window has closed — by TTL at any stage, or by an
// explicit decline — every late input must be dropped WITHOUT residue (no
// stash, no contact, no relay traffic), because there is no live handshake
// left to apply it to.
// ---------------------------------------------------------------------------

private val RW_OFFER = MessageManager.CONTROL_KIND_REFERRAL_OFFER
private val RW_ACCEPT = MessageManager.CONTROL_KIND_REFERRAL_ACCEPT

/** 32-char inbox ids / 43-char caps — the shapes the validators demand. */
private val RW_PEER_IB  = "wp" + "A".repeat(30)
private val RW_PEER_CIB = "wp" + "B".repeat(30)
private val RW_MY_IB    = "wm" + "C".repeat(30)
private val RW_MY_CIB   = "wm" + "D".repeat(30)
private val RW_CAP_R = "R".repeat(43)
private val RW_CAP_W = "W".repeat(43)
private val RW_CAP_S = "S".repeat(43)
private val RW_CAP_X = "X".repeat(43)

private fun rwMint() = MintedInboxPair(
    MintedInbox(RW_MY_IB, RW_CAP_R, RW_CAP_W, Long.MAX_VALUE),
    MintedInbox(RW_MY_CIB, RW_CAP_S, RW_CAP_X, Long.MAX_VALUE),
)

private fun rwAcceptJson(introId: String, peerPub: ByteArray) =
    """{"ii":${jsonEscapeString(introId)},"pk":${jsonEscapeString(encodeBase64(peerPub))},""" +
        """"ib":${jsonEscapeString(RW_PEER_IB)},"wc":${jsonEscapeString(RW_CAP_W)},""" +
        """"cib":${jsonEscapeString(RW_PEER_CIB)},"cwc":${jsonEscapeString(RW_CAP_X)}}"""

private fun rwTs(vault: InMemoryVault, key: String): Long? =
    vault.getMeta(key)?.let { firstStringFieldAnywhere(it, "ts")?.toLongOrNull() }

// ---------------------------------------------------------------------------
// The exact boundaries. `<=` is live, `+1 ms` is dead — pinned on the record's
// OWN persisted stamp (read back from the vault) so no wall-clock skew between
// arrange and act can move the boundary under the test.
// ---------------------------------------------------------------------------

class ReferralTtlBoundaryTest {

    private val noTransport: () -> MessageManager? = { null }

    @Test
    fun aRecordExactlyAtTheIdleTtl_isStillLive_oneMsPastItIsReclaimed() {
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        val rm = ReferralManager(vault, noTransport)
        rm.handleControl("alice", RW_OFFER, referralOfferJson("tb1", "Carol"))
        val ts = assertNotNull(
            rwTs(vault, ReferralMetaKeys.OFFER_PREFIX + "tb1"),
            "precondition: the offer is persisted with its receipt stamp",
        )

        // EXACTLY the idle TTL since the last activity: still live (`<=` bound).
        rm.clockMs = { ts + REFERRAL_RECORD_TTL_MS }
        rm.runMaintenance()
        assertNotNull(
            vault.getMeta(ReferralMetaKeys.OFFER_PREFIX + "tb1"),
            "a record exactly AT the idle TTL is still live — the bound is inclusive",
        )
        assertEquals(listOf("tb1"), rm.pendingOffers().map { it.introId })

        // One millisecond past it: reclaimed, RAM and vault together.
        rm.clockMs = { ts + REFERRAL_RECORD_TTL_MS + 1 }
        rm.runMaintenance()
        assertNull(
            vault.getMeta(ReferralMetaKeys.OFFER_PREFIX + "tb1"),
            "one ms past the idle TTL the record must be reclaimed",
        )
        assertTrue(rm.pendingOffers().isEmpty(), "an expired offer must stop being presented")
    }

    /** The absolute ceiling's boundary, and the refresh refusal past it: a peer
     *  accept arriving exactly AT firstSeen+ceiling may still re-stamp (the
     *  `<=` bound), one ms past it the refresh is REFUSED (the stamp does not
     *  move) and the next sweep reclaims the record — activity can ride the
     *  ceiling but never cross it. */
    @Test
    fun refreshExactlyAtTheAbsoluteCeiling_isHonoured_oneMsPastItIsRefusedAndReclaimed() {
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        // A live handshake first seen 1 s ago: an un-consented offer plus our
        // staged-but-UNSENT accept (st=0, so a peer accept is stashed and both
        // halves are re-stamped through the refresh-on-activity path).
        val t0 = currentTimeMillis() - 1_000L
        vault.putMeta(
            ReferralMetaKeys.OFFER_PREFIX + "tb2",
            encodeStoredOffer(StoredOffer("alice", "Alice", "Carol", t0)),
        )
        vault.putMeta(
            ReferralMetaKeys.ACCEPT_PREFIX + "tb2",
            encodeStoredAccept(
                StoredAccept("alice", "Carol", ByteArray(32) { 5 }, ByteArray(32) { 6 }, rwMint(), false, 0, t0)
            ),
        )
        val rm = ReferralManager(vault, noTransport)
        assertEquals(listOf("tb2"), rm.pendingOffers().map { it.introId }, "precondition: the offer rehydrated")

        // A peer accept lands EXACTLY at the ceiling: the refresh is honoured…
        val atCeiling = t0 + REFERRAL_RECORD_MAX_LIFETIME_MS
        rm.clockMs = { atCeiling }
        rm.handleControl("alice", RW_ACCEPT, rwAcceptJson("tb2", ByteArray(32) { 9 }))
        assertEquals(atCeiling, rwTs(vault, ReferralMetaKeys.OFFER_PREFIX + "tb2"), "a refresh exactly AT the ceiling is still honoured")
        assertEquals(atCeiling, rwTs(vault, ReferralMetaKeys.ACCEPT_PREFIX + "tb2"), "…for the staged accept too")
        // …and the record itself is still live at exactly the ceiling.
        rm.runMaintenance()
        assertNotNull(vault.getMeta(ReferralMetaKeys.OFFER_PREFIX + "tb2"), "exactly AT the ceiling is still live")
        assertNotNull(vault.getMeta(ReferralMetaKeys.ACCEPT_PREFIX + "tb2"))

        // One ms past the ceiling: another accept arrival must NOT re-stamp…
        rm.clockMs = { atCeiling + 1 }
        rm.handleControl("alice", RW_ACCEPT, rwAcceptJson("tb2", ByteArray(32) { 8 }))
        assertEquals(
            atCeiling, rwTs(vault, ReferralMetaKeys.OFFER_PREFIX + "tb2"),
            "past the ceiling a refresh must be refused — no amount of activity may extend the record",
        )
        assertEquals(atCeiling, rwTs(vault, ReferralMetaKeys.ACCEPT_PREFIX + "tb2"))
        // …and the sweep reclaims both halves despite the second-fresh idle stamp.
        rm.runMaintenance()
        assertNull(
            vault.getMeta(ReferralMetaKeys.OFFER_PREFIX + "tb2"),
            "one ms past the absolute ceiling the record must be reclaimed even though its idle stamp is fresh",
        )
        assertNull(vault.getMeta(ReferralMetaKeys.ACCEPT_PREFIX + "tb2"))
        assertTrue(rm.pendingOffers().isEmpty())
    }

    /** The record TTL and the relay `?ttl` retention age out the SAME window,
     *  and the ceiling is defined as 4x the idle TTL — pin the lockstep so a
     *  future edit to one constant cannot silently re-open the half-pair gap
     *  (record alive with its relay blob expired, or vice versa). */
    @Test
    fun recordTtl_relayRetention_andCeiling_stayInLockstep() {
        assertEquals(
            REFERRAL_RECORD_TTL_MS, REFERRAL_CONTROL_TTL_SECONDS * 1000L,
            "the vault record and the relay blob must age out on the same bound",
        )
        assertEquals(
            4L * REFERRAL_RECORD_TTL_MS, REFERRAL_RECORD_MAX_LIFETIME_MS,
            "the absolute ceiling is defined as 4x the idle TTL",
        )
    }
}

// ---------------------------------------------------------------------------
// Window-closed at each stage. Late input against a settled/expired
// introduction must be inert: no stash, no contact, no relay traffic.
// ---------------------------------------------------------------------------

class ReferralWindowClosedTest {

    /** CONSENT stage: the offer aged out before the user answered. Approving it
     *  afterwards must refuse without ever touching the relay (no PoW mint). */
    @Test
    fun windowClosedBeforeConsent_acceptOfferRefuses_andNeverTouchesTheRelay() = runTest {
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        val http = RecordingRelayHttp()
        val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)
        val rm = ReferralManager(vault) { mgr }
        rm.handleControl("alice", RW_OFFER, referralOfferJson("wc1", "Carol"))
        val ts = assertNotNull(rwTs(vault, ReferralMetaKeys.OFFER_PREFIX + "wc1"))

        rm.clockMs = { ts + REFERRAL_RECORD_TTL_MS + 1 }
        rm.runMaintenance()
        assertTrue(rm.pendingOffers().isEmpty(), "precondition: the offer aged out")

        assertFalse(rm.acceptOffer("wc1"), "an offer whose window closed must not be approvable")
        assertEquals(0, http.calls.size, "no mint may start for a closed window — the transport was live")
        assertTrue(
            vault.meta.keys.none { it.startsWith(ReferralMetaKeys.ACCEPT_PREFIX) },
            "nothing may be staged for a closed window",
        )
    }

    /** FINALIZE stage: our accept was sent, then the whole record aged out. The
     *  peer's late accept must hit the unknown-introId drop — dropped outright,
     *  NOT stashed (there is no live handshake left to validate it against). */
    @Test
    fun windowClosedAfterOurAcceptWasSent_aLatePeerAcceptIsDroppedWithoutResidue() {
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        val expired = currentTimeMillis() - REFERRAL_RECORD_TTL_MS - 3_600_000L
        vault.putMeta(
            ReferralMetaKeys.ACCEPT_PREFIX + "wc2",
            encodeStoredAccept(
                StoredAccept("alice", "Carol", ByteArray(32) { 1 }, ByteArray(32) { 2 }, rwMint(), true, 0, expired)
            ),
        )
        val rm = ReferralManager(vault) { null }
        assertTrue(
            vault.meta.keys.none { it.startsWith(ReferralMetaKeys.ACCEPT_PREFIX) },
            "precondition: rehydration reclaimed the expired accept",
        )

        rm.handleControl("alice", RW_ACCEPT, rwAcceptJson("wc2", ByteArray(32) { 9 }))

        assertEquals(1, vault.getAllContacts().size, "a peer accept whose introduction expired must never pair")
        assertTrue(
            vault.meta.keys.none { it.startsWith(ReferralMetaKeys.STASH_PREFIX) },
            "a late accept for a closed window must not be stashed — nothing could ever apply it",
        )
    }

    /** USER-closed window: the offer was declined. A peer accept relayed after
     *  the decline must be dropped without residue — the maps were cleared and
     *  the tombstone keeps the introduction settled. */
    @Test
    fun windowClosedByDecline_aLatePeerAcceptIsDroppedWithoutResidue() {
        val vault = InMemoryVault()
        seedReferralContact(vault, "alice", "Alice")
        val rm = ReferralManager(vault) { null }
        rm.handleControl("alice", RW_OFFER, referralOfferJson("wc3", "Carol"))
        rm.declineOffer("wc3")
        assertTrue(rm.pendingOffers().isEmpty(), "precondition: the offer is declined")

        rm.handleControl("alice", RW_ACCEPT, rwAcceptJson("wc3", ByteArray(32) { 9 }))

        assertEquals(1, vault.getAllContacts().size, "a peer accept after our decline must never pair")
        assertTrue(
            vault.meta.keys.none { it.startsWith(ReferralMetaKeys.STASH_PREFIX) },
            "a declined introduction must not accumulate a stash",
        )
        assertTrue(rm.pendingOffers().isEmpty(), "the accept must not resurrect the declined offer")
    }
}

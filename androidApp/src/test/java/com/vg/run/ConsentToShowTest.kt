package com.vg.run

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Test

/**
 * The contact list's consent-dialog rule ([consentToShow]): which referral
 * offer / group invite is on screen, given what the managers hold pending.
 * Pins the five rules of the former 4 s screen poller plus the
 * introduce-picker freeze.
 */
class ConsentToShowTest {

    private val offerA = ReferralOffer("intro-a", "c1", "Introducer", "Peer A")
    private val offerB = ReferralOffer("intro-b", "c1", "Introducer", "Peer B")
    private fun invite(id: String) = GroupInvite(
        groupId = id, inviterContactId = "c2", inviterAlias = "Inviter", groupName = "G",
        epoch = 1L, adminMemberId = "m0", myMemberId = "m1", memberIds = listOf("m0", "m1"),
    )
    private val inviteA = invite("g-a")
    private val inviteB = invite("g-b")
    private val none = ConsentShown(null, null)

    private fun run(
        pending: PendingConsent,
        shown: ConsentShown = none,
        introduceOpen: Boolean = false,
        referralBusy: Boolean = false,
        groupInviteBusy: Boolean = false,
    ) = consentToShow(pending, shown, introduceOpen, referralBusy, groupInviteBusy)

    @Test
    fun introducePickerOpen_freezesBothDialogs() {
        val shown = ConsentShown(null, inviteA)
        assertSame(shown, run(PendingConsent(offerA, inviteB), shown, introduceOpen = true))
        assertSame(none, run(PendingConsent(offerA, null), none, introduceOpen = true))
    }

    @Test
    fun pendingOffer_isAdoptedWhenNoneShown_andTheShownOneIsKept() {
        assertSame(offerA, run(PendingConsent(offerA, null)).offer)
        assertSame(offerA, run(PendingConsent(offerB, null), ConsentShown(offerA, null)).offer)
    }

    @Test
    fun noPendingOffer_dismissesUnlessAnAcceptIsInFlight() {
        assertNull(run(PendingConsent(null, null), ConsentShown(offerA, null)).offer)
        assertSame(offerA, run(PendingConsent(null, null), ConsentShown(offerA, null), referralBusy = true).offer)
    }

    @Test
    fun anOfferOnScreen_clearsTheInviteUnlessAJoinIsInFlight() {
        assertNull(run(PendingConsent(offerA, inviteA), ConsentShown(null, inviteA)).invite)
        assertSame(inviteA, run(PendingConsent(offerA, inviteA), ConsentShown(null, inviteA), groupInviteBusy = true).invite)
    }

    @Test
    fun noOffer_adoptsKeepsOrClearsTheInvite() {
        // adopt when none shown and not busy
        assertSame(inviteA, run(PendingConsent(null, inviteA)).invite)
        // keep the shown one over a different pending one
        assertSame(inviteA, run(PendingConsent(null, inviteB), ConsentShown(null, inviteA)).invite)
        // busy: do not adopt
        assertNull(run(PendingConsent(null, inviteA), groupInviteBusy = true).invite)
        // consumed and not busy: clear
        assertNull(run(PendingConsent(null, null), ConsentShown(null, inviteA)).invite)
        // consumed but busy: keep
        assertSame(inviteA, run(PendingConsent(null, null), ConsentShown(null, inviteA), groupInviteBusy = true).invite)
    }

    @Test
    fun offersOutrankInvites_onePromptAtATime() {
        assertEquals(ConsentShown(offerA, null), run(PendingConsent(offerA, inviteA)))
    }
    @Test
    fun laterDefersTheInvite_theNextOnePresents_andNothingLoops() {
        val both = PendingConsent(null, inviteA, listOf(inviteA, inviteB))
        // A closed with Later: B presents instead; with both deferred, nothing.
        assertSame(inviteB, consentToShow(both, none, false, false, false, setOf("g-a")).invite)
        assertNull(consentToShow(both, none, false, false, false, setOf("g-a", "g-b")).invite)
        // Deferred set cleared (new session): A presents again.
        assertSame(inviteA, consentToShow(both, none, false, false, false, emptySet()).invite)
        // A deferred invite the user reopened from its row stays up.
        assertSame(inviteA, consentToShow(both, ConsentShown(null, inviteA), false, false, false, setOf("g-a")).invite)
    }

    @Test
    fun groupInviteRows_areTheDeferredPendingInvitesNotShown() {
        val both = PendingConsent(null, inviteA, listOf(inviteA, inviteB))
        assertEquals(emptyList<GroupInvite>(), groupInviteRows(both, emptySet(), null, false))
        assertEquals(listOf(inviteA), groupInviteRows(both, setOf("g-a"), null, false))
        assertEquals(listOf(inviteB), groupInviteRows(both, setOf("g-a", "g-b"), inviteA, false))
        assertEquals(emptyList<GroupInvite>(), groupInviteRows(both, setOf("g-a"), null, true))
    }

    @Test
    fun laterDefersTheOffer_theInvitePresents_andNothingLoops() {
        val p = PendingConsent(offerA, inviteA, listOf(inviteA), listOf(offerA, offerB))
        // A deferred: B presents; both deferred: no offer, so the invite presents.
        assertSame(offerB, consentToShow(p, none, false, false, false, deferredOfferIds = setOf("intro-a")).offer)
        val both = consentToShow(p, none, false, false, false, deferredOfferIds = setOf("intro-a", "intro-b"))
        assertNull(both.offer)
        assertSame(inviteA, both.invite)
        // And the reverse: invite deferred, offer still presents and outranks it.
        val rev = consentToShow(p, none, false, false, false, deferredInviteIds = setOf("g-a"))
        assertSame(offerA, rev.offer)
        assertNull(rev.invite)
        // Reopened from its row: stays up while deferred.
        assertSame(offerA, consentToShow(p, ConsentShown(offerA, null), false, false, false, deferredOfferIds = setOf("intro-a")).offer)
        // Deferred set cleared (new session): presents again.
        assertSame(offerA, consentToShow(p, none, false, false, false).offer)
    }

    @Test
    fun anAcceptInFlight_stillReAdoptsTheUndeferredOffer_asConnecting() {
        // Existing retry/Connecting flow: after Approve the offer is un-deferred and
        // still pending, shown is null, busy: the dialog comes back showing Connecting.
        assertSame(offerA, run(PendingConsent(offerA, null), none, referralBusy = true).offer)
        assertSame(offerA, run(PendingConsent(null, null), ConsentShown(offerA, null), referralBusy = true).offer)
    }

    @Test
    fun referralOfferRows_areTheDeferredPendingOffersNotShown() {
        val p = PendingConsent(offerA, null, emptyList(), listOf(offerA, offerB))
        assertEquals(emptyList<ReferralOffer>(), referralOfferRows(p, emptySet(), null, false))
        assertEquals(listOf(offerA), referralOfferRows(p, setOf("intro-a"), null, false))
        assertEquals(listOf(offerB), referralOfferRows(p, setOf("intro-a", "intro-b"), offerA, false))
        assertEquals(emptyList<ReferralOffer>(), referralOfferRows(p, setOf("intro-a"), null, true))
    }
}

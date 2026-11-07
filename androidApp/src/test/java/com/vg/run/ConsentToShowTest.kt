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
}

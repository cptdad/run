package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class GroupInvitePresentationTest {
    private fun present(pending: List<String>, deferred: List<String> = emptyList(), shown: String? = null, busy: Boolean = false) =
        GroupInvitePresentation.toAutoPresent(pending, deferred, shown, busy)

    private fun rows(pending: List<String>, deferred: List<String> = emptyList(), shown: String? = null, busy: Boolean = false) =
        GroupInvitePresentation.rowIds(pending, deferred, shown, busy)

    @Test fun firstSight_presentsTheFirstPendingInvite() {
        assertEquals("a", present(listOf("a", "b")))
        assertNull(present(emptyList()))
    }

    @Test fun later_defersAndDoesNotRePresent() {
        // The dialog for "a" was closed with Later: shown is null, "a" deferred.
        assertNull(present(listOf("a"), deferred = listOf("a")))
        // Poll ticks keep returning null: no loop.
        repeat(3) { assertNull(present(listOf("a"), deferred = listOf("a"))) }
    }

    @Test fun secondInvitePresents_afterTheFirstIsDeferred() {
        assertEquals("b", present(listOf("a", "b"), deferred = listOf("a")))
        // Both deferred: nothing, and no loop.
        assertNull(present(listOf("a", "b"), deferred = listOf("a", "b")))
    }

    @Test fun deferredSetCleared_presentsAgain() {
        assertEquals("a", present(listOf("a"), deferred = emptyList()))
    }

    @Test fun busy_presentsNothingNew() {
        assertNull(present(listOf("a", "b"), busy = true))
        assertEquals("a", present(listOf("a", "b"), shown = "a", busy = true))
        // Even a stale shown id is held while busy (the in-flight join).
        assertEquals("a", present(emptyList(), shown = "a", busy = true))
    }

    @Test fun shownInvite_staysWhileAnythingIsPending_dismissedWhenNothingIs() {
        // A manually reopened deferred invite stays up.
        assertEquals("a", present(listOf("a", "b"), deferred = listOf("a"), shown = "a"))
        // The dialog's subject never swaps to another invite under the user's finger.
        assertEquals("a", present(listOf("b"), shown = "a"))
        // Nothing pending any more (accepted / declined / withdrawn): dismissed.
        assertNull(present(emptyList(), shown = "a"))
    }

    @Test fun rows_areTheDeferredPendingInvitesNotShown() {
        assertEquals(listOf("a", "b"), rows(listOf("a", "b"), deferred = listOf("a", "b")))
        // The one currently in the dialog has no row.
        assertEquals(listOf("b"), rows(listOf("a", "b"), deferred = listOf("a", "b"), shown = "a"))
        // A deferred id that is no longer pending has no row (withdrawn / accepted / declined).
        assertEquals(listOf("b"), rows(listOf("b"), deferred = listOf("a", "b")))
    }

    @Test fun rows_firstSightHasNoRow_andBusyHasNone() {
        assertEquals(emptyList(), rows(listOf("a")))
        assertEquals(emptyList(), rows(listOf("a"), deferred = listOf("a"), busy = true))
    }

    @Test fun rows_andPresentation_neverBothClaimTheSameInvite() {
        val pending = listOf("a", "b", "c")
        for (deferred in listOf(emptyList(), listOf("a"), listOf("b", "c"), pending)) {
            for (shown in listOf(null, "a", "c")) {
                val auto = present(pending, deferred, shown)
                val r = rows(pending, deferred, auto)
                assertEquals(false, auto != null && auto in r)
            }
        }
    }

    @Test fun pruneDeferred_dropsInvitesNoLongerPending() {
        assertEquals(setOf("b"), GroupInvitePresentation.pruneDeferred(listOf("b", "c"), setOf("a", "b")))
        assertEquals(emptySet(), GroupInvitePresentation.pruneDeferred(emptyList(), setOf("a")))
    }

    // The referral offer reuses the rule with introIds (base64url) as the ids.
    @Test fun referralOfferIds_followTheSameRule() {
        val offers = listOf("Ab-_1", "Cd-_2")
        assertEquals("Ab-_1", present(offers))
        // Later on the first: the second presents; both deferred: nothing, rows for both.
        assertEquals("Cd-_2", present(offers, deferred = listOf("Ab-_1")))
        assertNull(present(offers, deferred = offers))
        assertEquals(offers, rows(offers, deferred = offers))
        // Reopened from its row: stays up, loses its row.
        assertEquals("Ab-_1", present(offers, deferred = offers, shown = "Ab-_1"))
        assertEquals(listOf("Cd-_2"), rows(offers, deferred = offers, shown = "Ab-_1"))
        // Offers pass busy=false to toAutoPresent: an accept in flight re-adopts the pending (undeferred) offer.
        assertEquals("Ab-_1", present(offers, shown = null, busy = false))
    }
}

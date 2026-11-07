package com.vg.run

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for the contact-list FIRST-REVEAL gate ([contactListRevealed] +
 * [contactListSurface]) — the pure part of the 2026-09-11 directive that the
 * list (rows, unread badges, repair banner AND the empty-contacts copy) must
 * not be on screen at all until the relay has actually answered once.
 *
 * Two properties are load-bearing and are exactly what these pin:
 *
 *  1. The latch is MONOTONE within a session. Only the FIRST reveal is gated;
 *     losing reachability afterwards (stall / grey-out phases) must NOT hide a
 *     list the user is already looking at — "not visible until connected", not
 *     "hidden whenever disconnected".
 *  2. The reveal gate OUTRANKS emptiness, so a fresh vault shows the
 *     pre-connect placeholder rather than flashing "no contacts yet" before
 *     the relay answers — and, symmetrically, a vault WITH contacts never
 *     reports the `empty_contacts_state` surface just because the relay is
 *     still connecting (the e2e empty-vault/freshness probes key on that id).
 *
 * iOS sibling: `ContactListView.swift`'s `listRevealed` @State makes the same
 * three-way choice in `body` (verified by build + e2e — a SwiftUI branch has
 * no JVM-testable seam).
 */
class ContactListRevealTest {

    // --- the latch ----------------------------------------------------------

    @Test
    fun notRevealedUntilTheRelayIsReachable() {
        assertFalse(contactListRevealed(alreadyRevealed = false, relayReachable = false))
    }

    @Test
    fun firstReachableObservationReveals() {
        assertTrue(contactListRevealed(alreadyRevealed = false, relayReachable = true))
    }

    @Test
    fun staysRevealedWhenReachabilityIsLostAgain() {
        // THE point of the latch: a stall / grey-out after the first reveal
        // dims and disables the rows (rowsEnabled) but must never take the
        // list off screen.
        assertTrue(contactListRevealed(alreadyRevealed = true, relayReachable = false))
    }

    @Test
    fun latchSurvivesAWholeFlappingSession() {
        // Fold the real sequence a flapping circuit produces: never → up →
        // down → up → down. Once true, always true.
        var revealed = false
        val flaps = listOf(false, false, true, false, true, false, false)
        val seen = flaps.map { reachable ->
            revealed = contactListRevealed(revealed, reachable)
            revealed
        }
        assertEquals(listOf(false, false, true, true, true, true, true), seen)
    }

    // --- the surface --------------------------------------------------------

    @Test
    fun hiddenSurfaceWinsOverEmptiness_freshVaultNeverFlashesNoContacts() {
        assertEquals(
            ContactListSurface.HiddenUntilConnected,
            contactListSurface(revealed = false, hasContent = false),
        )
    }

    @Test
    fun hiddenSurfaceWinsOverContent_populatedVaultIsNotReportedEmpty() {
        assertEquals(
            ContactListSurface.HiddenUntilConnected,
            contactListSurface(revealed = false, hasContent = true),
        )
    }

    @Test
    fun revealedEmptyVaultShowsTheEmptyState() {
        assertEquals(
            ContactListSurface.EmptyState,
            contactListSurface(revealed = true, hasContent = false),
        )
    }

    @Test
    fun revealedPopulatedVaultShowsTheRows() {
        assertEquals(
            ContactListSurface.Rows,
            contactListSurface(revealed = true, hasContent = true),
        )
    }

    @Test
    fun revealedButNotYetLoaded_staysHidden_neverFlashesNoContacts() {
        // hasContent == null: the ViewModel's first contact-list load has not
        // landed yet. A revealed list must not report EmptyState in that gap.
        assertEquals(
            ContactListSurface.HiddenUntilConnected,
            contactListSurface(revealed = true, hasContent = null),
        )
        assertEquals(
            ContactListSurface.HiddenUntilConnected,
            contactListSurface(revealed = false, hasContent = null),
        )
    }

    @Test
    fun rowsAreTheOnlySurfaceThatCanFollowAReveal_withContent() {
        // Composed end-to-end: a populated vault goes placeholder → rows on
        // the first reachable tick and never returns to the placeholder.
        var revealed = false
        val surfaces = listOf(false, true, false).map { reachable ->
            revealed = contactListRevealed(revealed, reachable)
            contactListSurface(revealed, hasContent = true)
        }
        assertEquals(
            listOf(
                ContactListSurface.HiddenUntilConnected,
                ContactListSurface.Rows,
                ContactListSurface.Rows,
            ),
            surfaces,
        )
    }
}

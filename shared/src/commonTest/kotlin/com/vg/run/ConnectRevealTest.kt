package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// CONTACT-LIST REVEAL GATE — the shared pure rules.
//
// Android (`RunViewModel.settleUnreadPrime` / `contactsReady`) and iOS
// (`AppState.settleUnreadPrime` / `recomputeContactsReady`) both drive
// [ConnectReveal], so these are the platform-independent statements about what
// the user waits for:
//
//   • the prime settles on its FIRST per-contact result — not on the whole pass
//     (C4b rule 1: 39/48 Android and 44/45 iOS timelines had an unfinished
//     prime at the first relay answer);
//   • a pass that emits nothing still settles when it ENDS, so zero contacts /
//     no session / move-frozen reveal immediately;
//   • the cap is a BACKSTOP (3 s) and is the only event that narrates
//     PRIME_CAP — and only when it is what actually released the reveal;
//   • the gate is idempotent: the first event wins, later ones are no-ops, so
//     one connect narrates exactly one reveal.
// ---------------------------------------------------------------------------

class ConnectRevealTest {

    // --- rule 1: the first dot settles the prime ------------------------------

    @Test
    fun firstPerContactResultSettlesThePrime() {
        val outcome = ConnectReveal.primeSettle(
            alreadySettled = false,
            event = ConnectReveal.PrimeEvent.FIRST_DOT,
        )
        assertTrue(outcome.settles, "the prime's first answered peek must release the reveal")
        assertFalse(outcome.logCapLine, "a first dot is not a cap — it must not narrate PRIME_CAP")
    }

    @Test
    fun theRestOfThePassIsNotWaitedFor() {
        // The whole point of C4b: FIRST_DOT settles, and the PASS_ENDED that
        // arrives seconds later changes nothing (the remaining dots update
        // their own rows in place).
        var settled = false
        for (event in listOf(ConnectReveal.PrimeEvent.FIRST_DOT, ConnectReveal.PrimeEvent.PASS_ENDED)) {
            val outcome = ConnectReveal.primeSettle(settled, event)
            if (outcome.settles) settled = true
        }
        assertTrue(settled)
        assertFalse(
            ConnectReveal.primeSettle(settled, ConnectReveal.PrimeEvent.PASS_ENDED).settles,
            "the pass ending after the first dot must not re-fire the reveal",
        )
    }

    // --- passes that never emit -----------------------------------------------

    @Test
    fun aPassThatEmitsNothingStillSettlesWhenItEnds() {
        // Zero contacts, every peek failed, or the sweep was cancelled: the
        // reveal must never wait on a dead sweep.
        assertTrue(
            ConnectReveal.primeSettle(false, ConnectReveal.PrimeEvent.PASS_ENDED).settles,
            "a user with no contacts must reveal the instant the relay answers",
        )
    }

    @Test
    fun aSkippedPassSettlesImmediately() {
        // No session / move-frozen: no sweep is coming at all.
        val outcome = ConnectReveal.primeSettle(false, ConnectReveal.PrimeEvent.SKIPPED)
        assertTrue(outcome.settles)
        assertFalse(outcome.logCapLine)
    }

    // --- the cap is a backstop -------------------------------------------------

    @Test
    fun onlyTheCapNarratesPrimeCap() {
        assertTrue(ConnectReveal.primeSettle(false, ConnectReveal.PrimeEvent.CAP).logCapLine)
        for (event in listOf(
            ConnectReveal.PrimeEvent.FIRST_DOT,
            ConnectReveal.PrimeEvent.PASS_ENDED,
            ConnectReveal.PrimeEvent.SKIPPED,
        )) {
            assertFalse(
                ConnectReveal.primeSettle(false, event).logCapLine,
                "$event must not claim the reveal was capped",
            )
        }
    }

    @Test
    fun aCapThatExpiresAfterTheRevealIsSilent() {
        // The cap coroutine can still be scheduled when the first dot lands.
        // It must neither re-settle nor narrate a PRIME_CAP the timeline would
        // then read as "the reveal was held by a wedged peek".
        val outcome = ConnectReveal.primeSettle(
            alreadySettled = true,
            event = ConnectReveal.PrimeEvent.CAP,
        )
        assertFalse(outcome.settles)
        assertFalse(outcome.logCapLine)
    }

    @Test
    fun theCapIsThreeSecondsAndItsSecondsRenderingMatches() {
        // Pinned: the number is in ONE place because it is printed into a panel
        // line both platforms must emit word for word.
        assertEquals(3_000L, ConnectReveal.UNREAD_PRIME_REVEAL_CAP_MS)
        assertEquals(3, ConnectReveal.UNREAD_PRIME_REVEAL_CAP_SEC)
        assertEquals(
            ConnectReveal.UNREAD_PRIME_REVEAL_CAP_MS / 1000,
            ConnectReveal.UNREAD_PRIME_REVEAL_CAP_SEC.toLong(),
        )
    }

    // --- idempotence ------------------------------------------------------------

    @Test
    fun everyEventAfterTheFirstIsANoOp() {
        for (first in ConnectReveal.PrimeEvent.entries) {
            val settled = ConnectReveal.primeSettle(false, first).settles
            assertTrue(settled, "$first must settle a fresh gate")
            for (later in ConnectReveal.PrimeEvent.entries) {
                val outcome = ConnectReveal.primeSettle(settled, later)
                assertFalse(outcome.settles, "$later after $first must be a no-op")
                assertFalse(outcome.logCapLine, "$later after $first must narrate nothing")
            }
        }
    }

    // --- the gate itself ---------------------------------------------------------

    @Test
    fun bothHalvesAreRequiredToReveal() {
        assertFalse(ConnectReveal.contactsReady(relayAnswered = false, primeSettled = false))
        assertFalse(
            ConnectReveal.contactsReady(relayAnswered = false, primeSettled = true),
            "a settled prime alone is NOT a connect — the session's own first answer is the gate",
        )
        assertFalse(
            ConnectReveal.contactsReady(relayAnswered = true, primeSettled = false),
            "the relay answering alone still waits for the (now much shorter) prime grace",
        )
        assertTrue(ConnectReveal.contactsReady(relayAnswered = true, primeSettled = true))
    }
}

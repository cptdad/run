package com.vg.run

// ---------------------------------------------------------------------------
// ConnectReveal — the pure rules behind THE CONTACT-LIST REVEAL GATE.
//
// The gate is "the relay has answered AND the connect-time unread prime has
// settled", so every "message waiting" dot is already in place in the frame
// the runestone lights and the contacts appear — never a list first and dots
// trickling in a beat later.
//
// C4a's measurement showed the SECOND half had become the longer one: in 39 of
// 48 Android and 44 of 45 iOS timelines the prime had NOT finished when the
// relay answered, so the user waited 0–10 s of PRIME on top of a 5 s p50 of
// NETWORK, and `secs` (which closes at the first round trip) could not see it.
//
// C4b settles the prime earlier, by two rules:
//
//  1. THE FIRST PER-CONTACT RESULT SETTLES IT. [GroupManager.primeUnreadCounts]
//     reports every peek through its `onContactUnread` callback the moment that
//     peek lands (merge-only, strictly serial). The first one is enough to draw
//     the visible list correctly; the ones behind it update their own rows in
//     place, exactly as the steady-state sweep does seconds later. A pass that
//     ends without emitting anything — no contacts, no session, every peek
//     failed, move-frozen, cancelled — still settles on its END, so a user with
//     zero contacts and a user whose prime finishes instantly both reveal
//     immediately.
//  2. THE BACKSTOP IS [UNREAD_PRIME_REVEAL_CAP_MS] = 3 s, not 10. One parallel
//     /peek round over Tor is ~1–3 s, so the cap now only ever covers a
//     genuinely wedged peek: a backstop, never the common path.
//
// Both platforms drive these rules from here — Android
// `RunViewModel.settleUnreadPrime`, iOS `AppState.settleUnreadPrime` — so the
// semantics cannot drift and the panel lines stay word-for-word identical.
//
// This file sees BOOLEANS ONLY: no contact id, no count, no text. Nothing here
// can reach a log line or the wire.
// ---------------------------------------------------------------------------

object ConnectReveal {

    /**
     * Backstop for the reveal gate: how long after the FIRST relay answer the
     * contact list waits for the unread prime before revealing anyway.
     *
     * 3 s. The prime is one bounded-parallel /peek round
     * over an already-warm rendezvous circuit (~1–3 s end to end), and since
     * rule 1 above the gate no longer waits for the WHOLE round — only for its
     * first answer. Anything past this is a wedged peek, and a wedged peek must
     * not hold the contacts hostage.
     *
     * Counted from the first relay answer, not from the prime's start: the
     * prime is fired the instant the transport is wired (Tor `Connected`),
     * often long before the relay has answered anything.
     *
     * Consumed by `RunViewModel.UNREAD_PRIME_REVEAL_CAP_MS` and by
     * `AppState.unreadPrimeRevealCapSec`, which both also render it into the
     * [ConnectionLog.Code.PRIME_CAP] panel line — one constant, one number, one
     * phrase on both platforms.
     */
    const val UNREAD_PRIME_REVEAL_CAP_MS: Long = 3_000L

    /** [UNREAD_PRIME_REVEAL_CAP_MS] as whole seconds — what the PRIME_CAP panel
     *  line prints on both platforms. */
    const val UNREAD_PRIME_REVEAL_CAP_SEC: Int = (UNREAD_PRIME_REVEAL_CAP_MS / 1000).toInt()

    /**
     * What just happened to the connect-time unread prime. Every one of these
     * settles the gate; they differ only in what gets narrated.
     *
     *  - [FIRST_DOT] — the prime's first per-contact result landed (C4b rule 1).
     *  - [PASS_ENDED] — the pass returned: done, every peek failed, or cancelled.
     *  - [SKIPPED] — no pass is coming at all (no session, move-frozen).
     *  - [CAP] — [UNREAD_PRIME_REVEAL_CAP_MS] ran out after the first relay
     *    answer; the ONLY event that emits [ConnectionLog.Code.PRIME_CAP].
     */
    enum class PrimeEvent { FIRST_DOT, PASS_ENDED, SKIPPED, CAP }

    /**
     * @property settles flip the gate's prime half to true NOW (false ⇒ the
     *   caller does nothing at all: it has already settled, and a second
     *   narration of the same reveal would be a lie about the timeline).
     * @property logCapLine emit the [ConnectionLog.Code.PRIME_CAP] line — true
     *   only when the CAP is what actually released the reveal. A cap that
     *   expires after the prime already settled emits nothing.
     */
    data class PrimeSettle(val settles: Boolean, val logCapLine: Boolean)

    /**
     * THE settle predicate. Pure and idempotent: the first event wins and every
     * later one is a no-op, whichever thread delivers it (Android's prime
     * emission runs on an I/O worker while the cap coroutine runs on Main, so
     * the platform pairs this with an atomic flip).
     */
    fun primeSettle(alreadySettled: Boolean, event: PrimeEvent): PrimeSettle =
        if (alreadySettled) PrimeSettle(settles = false, logCapLine = false)
        else PrimeSettle(settles = true, logCapLine = event == PrimeEvent.CAP)

    /**
     * THE reveal gate itself. Both halves are per-transport: a Tor restart /
     * lock / wipe resets them together, so a new transport proves itself again
     * from scratch. Deliberately depends on nothing but the session's own first
     * answer plus the bounded prime grace above.
     *
     * `relayAnswered` (2026-10-26) is "the health probe flipped reachability OR
     * this transport's MessageManager has completed a round trip" — the prime's
     * first /peek 2xx counts, so the list no longer waits the extra 130–500 ms
     * for the parallel probe. Platforms: `AppState.recomputeContactsReady`,
     * `RunViewModel.contactsReady` (`_relayFirstAnswer`). The `REVEAL` panel line
     * may therefore precede `FIRST_ROUNDTRIP` (still emitted by the probe);
     * ConnectTelemetry floors `reveal` at `secs` for exactly that case.
     */
    fun contactsReady(relayAnswered: Boolean, primeSettled: Boolean): Boolean =
        relayAnswered && primeSettled
}
